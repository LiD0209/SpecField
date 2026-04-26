#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib import error, request


SYSTEM_SUMMARY_PROMPT = """
You summarize a single protocol change record into one concise search description for code retrieval.

Output strict JSON only:
{
  "summary": "..."
}

Rules:
- 1-2 sentences.
- Must mention the variable name and the core condition/action.
- Prefer concrete terms from evidence text.
- No markdown.
""".strip()


def normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


def resolve_cli_path(raw_path: str) -> Path:
    return Path(raw_path).expanduser().resolve(strict=False)


def call_chat_completions(
    api_key: str,
    base_url: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    timeout_sec: int,
) -> str:
    endpoint = f"{normalize_base_url(base_url)}/chat/completions"
    payload = {
        "model": model,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }

    req = request.Request(
        endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=timeout_sec) as resp:
            body = resp.read().decode("utf-8")
    except error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTPError {e.code}: {body}") from e
    except error.URLError as e:
        raise RuntimeError(f"URLError: {e}") from e

    data = json.loads(body)
    choices = data.get("choices", [])
    if not choices:
        raise RuntimeError(f"model response has no choices: {body}")

    content = choices[0].get("message", {}).get("content", "")
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(str(item))
        content = "\n".join(parts)

    return str(content).strip()


def extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("cannot extract JSON object from model output")

    obj = json.loads(text[start : end + 1])
    if not isinstance(obj, dict):
        raise ValueError("model output is not a JSON object")
    return obj


def summarize_change(
    change: dict[str, Any],
    *,
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    timeout_sec: int,
) -> str:
    user_prompt = (
        "Summarize this change for code retrieval. Keep it concise and specific.\n\n"
        f"{json.dumps(change, ensure_ascii=False, indent=2)}"
    )

    raw = call_chat_completions(
        api_key=api_key,
        base_url=base_url,
        model=model,
        system_prompt=SYSTEM_SUMMARY_PROMPT,
        user_prompt=user_prompt,
        temperature=temperature,
        timeout_sec=timeout_sec,
    )
    parsed = extract_json_object(raw)
    summary = str(parsed.get("summary", "")).strip()
    if not summary:
        raise ValueError("empty summary from model")
    return summary


def fallback_summary(change: dict[str, Any]) -> str:
    var_name = str(change.get("variable_name", "")).strip()
    cond = str(change.get("change_condition", "")).strip()
    action = str(change.get("change_action", "")).strip()
    evidence = str(change.get("evidence", "")).strip()

    parts = []
    if var_name:
        parts.append(f"Variable: {var_name}.")
    if cond:
        parts.append(f"Condition: {cond}.")
    if action:
        parts.append(f"Action: {action}.")
    if evidence:
        parts.append(f"Evidence: {evidence}")

    text = " ".join(parts).strip()
    return text or json.dumps(change, ensure_ascii=False)


def run_cmd(cmd: list[str], cwd: Path, *, desc: str, echo_stdout: bool = True) -> str:
    print(f"[RUN] {desc}")
    env = os.environ.copy()
    # Force UTF-8 for child Python processes to avoid mojibake on Windows consoles.
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    cp = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"{desc} failed (code={cp.returncode})\n"
            f"STDOUT:\n{cp.stdout}\n"
            f"STDERR:\n{cp.stderr}"
        )
    if cp.stderr.strip():
        print(cp.stderr.strip())
    if echo_stdout and cp.stdout.strip():
        print(cp.stdout.strip())
    return cp.stdout


def save_results_checkpoint(path: Path, results: list[Any]) -> None:
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(
        json.dumps(results, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tmp_path.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Workflow: summarize each change -> variable context -> collect snippets -> judge snippets"
    )
    parser.add_argument(
        "--changes-file",
        default="output/02_variable_changes.json",
        help="Path to JSON containing changes[]",
    )
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--base-url", default="https://api.bltcy.ai/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--max-changes", type=int, default=0, help="0 means all")
    parser.add_argument(
        "--pipeline-script",
        default="utils/variable_context_pipeline.py",
        help="Path to variable_context_pipeline.py",
    )
    parser.add_argument(
        "--collect-script",
        default="utils/collect_snippets_to_txt.py",
        help="Path to collect_snippets_to_txt.py",
    )
    parser.add_argument(
        "--judge-script",
        default="utils/judge_snippets_against_desc.py",
        help="Path to judge_snippets_against_desc.py",
    )
    parser.add_argument(
        "--test-txt",
        default="test.txt",
        help="Shared snippets txt file path (overwritten per change)",
    )
    parser.add_argument(
        "--pipeline-output-pattern",
        default="output/workflow/variable_context_result_change_{idx}.json",
        help="Output path pattern for pipeline result, supports {idx} as 1-based index",
    )
    parser.add_argument(
        "--result-json",
        default="result.json",
        help="Path to merged JSON result file for all processed changes",
    )
    args = parser.parse_args()

    if not args.api_key:
        raise ValueError("missing --api-key (or OPENAI_API_KEY)")

    repo_root = Path(args.repo_root).resolve(strict=False)
    if not repo_root.exists():
        raise ValueError(f"repo root not found: {repo_root}")

    changes_path = resolve_cli_path(args.changes_file)
    if not changes_path.exists():
        raise ValueError(f"changes file not found: {changes_path}")

    pipeline_script = resolve_cli_path(args.pipeline_script)
    collect_script = resolve_cli_path(args.collect_script)
    judge_script = resolve_cli_path(args.judge_script)

    for p in (pipeline_script, collect_script, judge_script):
        if not p.exists():
            raise ValueError(f"script not found: {p}")

    result_json_path = resolve_cli_path(args.result_json)
    result_json_path.parent.mkdir(parents=True, exist_ok=True)

    raw = json.loads(changes_path.read_text(encoding="utf-8"))
    changes = raw.get("changes", [])
    if not isinstance(changes, list) or not changes:
        raise ValueError("changes[] is empty or invalid")

    total = len(changes)
    limit = total if args.max_changes <= 0 else min(total, args.max_changes)
    merged_results: list[Any] = []
    save_results_checkpoint(result_json_path, merged_results)

    print(f"batch mode start: total={total}, processing={limit}")

    for i, change in enumerate(changes[:limit], start=1):
        print("=" * 90)
        print(f"[CHANGE {i}/{limit}] source_chunk_id={change.get('source_chunk_id', '')}")

        var_name = str(change.get("variable_name", "")).strip()
        if not var_name:
            print("[WARN] skip: empty variable_name")
            continue

        try:
            summary = summarize_change(
                change,
                api_key=args.api_key,
                base_url=args.base_url,
                model=args.model,
                temperature=args.temperature,
                timeout_sec=args.timeout_sec,
            )
            summary_source = "llm"
        except Exception as e:  # noqa: BLE001
            summary = fallback_summary(change)
            summary_source = f"fallback ({e})"

        print(f"[SUMMARY/{summary_source}] {summary}")

        pipeline_output = args.pipeline_output_pattern.format(idx=i)
        pipeline_output_path = resolve_cli_path(pipeline_output)
        pipeline_output_path.parent.mkdir(parents=True, exist_ok=True)

        test_txt_path = resolve_cli_path(args.test_txt)
        test_txt_path.parent.mkdir(parents=True, exist_ok=True)

        run_cmd(
            [
                sys.executable,
                "-X",
                "utf8",
                str(pipeline_script),
                "--repo-root",
                str(repo_root),
                "--var-name",
                var_name,
                "--desc",
                summary,
                "--use-llm",
                "--api-key",
                args.api_key,
                "--base-url",
                args.base_url,
                "--model",
                args.model,
                "--output",
                str(pipeline_output_path),
            ],
            cwd=repo_root,
            desc="variable_context_pipeline",
        )

        run_cmd(
            [
                sys.executable,
                "-X",
                "utf8",
                str(collect_script),
                "--input",
                str(pipeline_output_path),
                "--output",
                str(test_txt_path),
            ],
            cwd=repo_root,
            desc="collect_snippets_to_txt",
        )

        judge_stdout = run_cmd(
            [
                sys.executable,
                "-X",
                "utf8",
                str(judge_script),
                "--input",
                str(test_txt_path),
                "--desc",
                summary,
                "--repo-root",
                str(repo_root),
                "--variable-context-script",
                str(pipeline_script),
                "--api-key",
                args.api_key,
                "--base-url",
                args.base_url,
                "--model",
                args.model,
            ],
            cwd=repo_root,
            desc="judge_snippets_against_desc",
            echo_stdout=False,
        )

        judge_result: Any
        judge_text = judge_stdout.strip()
        try:
            judge_result = json.loads(judge_text) if judge_text else {}
        except json.JSONDecodeError:
            try:
                judge_result = extract_json_object(judge_text)
            except Exception:  # noqa: BLE001
                judge_result = {"_raw_text": judge_text}

        print("[JUDGE_RESULT_JSON]")
        print(judge_text)

        merged_results.append(judge_result)
        save_results_checkpoint(result_json_path, merged_results)
        print(f"[RESULT_JSON/CHECKPOINT] saved: {result_json_path} (items={len(merged_results)})")

    print(f"[RESULT_JSON] saved: {result_json_path}")

    print("batch mode done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
