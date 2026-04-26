#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any
import re
import sys
import threading
import time
from collections import deque


STAGE2_PROMPT_TEMPLATE = """
You are a practical code-to-description verifier and tester.

Goal:
Compare the description under test against the repository implementation.
The primary task is to determine whether the implementation is consistent with the description.
The requirement text is only supplementary context: use it only when the description is ambiguous, incomplete, or lacks enough context to determine the intended behavior.

Repository root:
{codebase_path}

Requirement source:
{standard_source}

Requirement text:
{standard_text}

Description under test:
{desc}

Related object context:
{context_json}

Instructions:
1) The primary comparison target is: determine whether the implementation is consistent with the description.

2) Requirement text is supplementary context only.
- Use it only if the description under test does not provide enough context,
- or if you need it to clarify behavior boundaries, intent, or terminology.

3) Configuration policy:
- First locate the repository default configuration file(s) in the codebase, and explicitly report the file path(s) you used.
- Use that discovered repository default configuration as the baseline.
- For macro definitions in code, their activation and values should be confirmed based on the default build configuration of the repository, rather than relying solely on conditional compilation branches in the source code for inference.
- If the description under test explicitly targets a non-default feature/mode (for example, post_hand_shake_only behavior), enable only the minimum required feature flags/options to realize that scenario.
- Explicitly report any non-default switches used and why they are required by the description.
- Do not introduce unrelated alternative configurations.

4) Actual code running tests must be conducted for verification

5) Testing should target the claimed behavior boundary.
- Prefer counterexample tests, rejection-path tests, or tests that directly exercise the claimed behavior.
- Do not treat an ordinary successful run as sufficient evidence unless it directly exercises the relevant behavior described.

6) If practical runtime testing is not feasible, explain the concrete blocker and then use a static trace as fallback.

7) Report expected vs observed behavior clearly for the performed test.

8) When possible, choose a test that can falsify the description.
- If the description claims a rejection or validation rule, try to trigger the violating input and observe whether the implementation rejects it.

9) Return exactly one final result:
- "not_satisfied": the implementation does not match the description under test.
- "satisfied": the implementation matches the description under test.

10) Do not return "uncertain", "insufficient", or any third state.

Output strict JSON only:
{{
"result": "satisfied|not_satisfied",
"test": {{
"name": "single test name",
"execution_mode": "runtime|static_trace",
"runtime_command": "required when execution_mode=runtime",
"runtime_output_excerpt": "required when execution_mode=runtime",
"steps": ["step1", "step2"],
"expected": "expected behavior according to the description under test",
"observed": "actual behavior observed from implementation",
"result": "pass|fail"
}},
"analysis": "2-6 sentences",
"confidence": 0.0,
"next_actions": ["action1", "action2"]
}}
""".strip()


def load_result_array(path: Path) -> list[Any]:
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and isinstance(raw.get("results"), list):
        return raw["results"]
    raise ValueError("input JSON must be an array or an object with results[]")


def _normalize_token(text: str) -> str:
    return re.sub(r"[\s_\-]+", "", str(text).strip().lower())


def is_not_satisfied(result_value: str, *, target_value: str, aliases: list[str]) -> bool:
    raw = str(result_value).strip()
    if not raw:
        return False
    if raw == target_value:
        return True
    if "不满足" in raw:
        return True
    if "not satisfied" in raw.lower():
        return True

    norm = _normalize_token(raw)
    candidates = [target_value, *aliases, "not_satisfied", "notsatisfied", "unsatisfied"]
    for c in candidates:
        if norm == _normalize_token(c):
            return True
    return False


def is_insufficient(result_value: str, *, target_value: str, aliases: list[str]) -> bool:
    raw = str(result_value).strip()
    if not raw:
        return False
    if raw == target_value:
        return True
    low_raw = raw.lower()
    if "insufficient" in low_raw:
        return True
    if "证据不足" in raw:
        return True

    norm = _normalize_token(raw)
    candidates = [target_value, *aliases, "insufficient", "evidence_insufficient", "not_enough_evidence"]
    for c in candidates:
        if norm == _normalize_token(c):
            return True
    return False


def extract_desc(obj: dict[str, Any]) -> str:
    return str(obj.get("desc", "")).strip()


def _score_stage2_json_candidate(obj: dict[str, Any]) -> int:
    score = 0
    result_raw = str(obj.get("result", "")).strip().lower()
    if "result" in obj:
        score += 3
    if result_raw in {"satisfied", "not_satisfied", "not satisfied", "notsatisfied", "pass", "fail"}:
        score += 3
    if isinstance(obj.get("test"), dict):
        score += 3
    if isinstance(obj.get("analysis"), str):
        score += 2
    if "confidence" in obj:
        score += 1
    if isinstance(obj.get("next_actions"), list):
        score += 1
    # De-prioritize stream-json event payloads.
    if str(obj.get("type", "")).strip().lower() in {"assistant", "user", "result"}:
        score -= 4
    return score


def _iter_json_object_candidates(text: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    # 1) Try fenced blocks first (```json ... ``` or plain ``` ... ```).
    for m in re.finditer(r"```(?:json)?\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL):
        block = m.group(1).strip()
        if not block:
            continue
        try:
            obj = json.loads(block)
            if isinstance(obj, dict):
                candidates.append(obj)
        except json.JSONDecodeError:
            continue

    # 2) Scan all balanced {...} regions and try parse each as JSON.
    in_string = False
    escape = False
    depth = 0
    start = -1

    for idx, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = idx
            depth += 1
            continue
        if ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start >= 0:
                snippet = text[start : idx + 1]
                try:
                    obj = json.loads(snippet)
                    if isinstance(obj, dict):
                        candidates.append(obj)
                except json.JSONDecodeError:
                    pass
                start = -1

    return candidates


def extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    candidates = _iter_json_object_candidates(text)
    if candidates:
        candidates.sort(key=_score_stage2_json_candidate, reverse=True)
        return candidates[0]

    raise ValueError("cannot extract JSON object from claude output")


def _clamp_confidence(v: Any) -> float:
    try:
        out = float(v)
    except (TypeError, ValueError):
        out = 0.0
    return max(0.0, min(1.0, out))


def sanitize_stage2(raw_obj: dict[str, Any]) -> dict[str, Any]:
    result_raw = str(raw_obj.get("result", "")).strip().lower()
    if result_raw in {"not_satisfied", "notsatisfied", "not satisfied", "fail", "不满足"}:
        result = "not_satisfied"
    elif result_raw in {"satisfied", "pass", "满足"}:
        result = "satisfied"
    else:
        raise ValueError(f"stage2 result must be satisfied/not_satisfied, got: {result_raw!r}")

    static_raw = raw_obj.get("static_analysis", {})
    if not isinstance(static_raw, dict):
        static_raw = {}
    static_key_evidence: list[str] = []
    raw_static_evidence = static_raw.get("key_evidence", [])
    if isinstance(raw_static_evidence, list):
        for item in raw_static_evidence:
            s = str(item).strip()
            if s:
                static_key_evidence.append(s)
    preliminary_raw = str(static_raw.get("preliminary_result", "")).strip().lower()
    if preliminary_raw in {"not_satisfied", "notsatisfied", "not satisfied", "fail"}:
        preliminary_result = "not_satisfied"
    elif preliminary_raw in {"satisfied", "pass"}:
        preliminary_result = "satisfied"
    else:
        preliminary_result = ""
    static_analysis = {
        "comparison": str(static_raw.get("comparison", "")).strip(),
        "preliminary_result": preliminary_result,
        "reason": str(static_raw.get("reason", "")).strip(),
        "key_evidence": static_key_evidence,
    }

    test_raw = raw_obj.get("test", {})
    if not isinstance(test_raw, dict):
        test_raw = {}
    test_steps: list[str] = []
    raw_steps = test_raw.get("steps", [])
    if isinstance(raw_steps, list):
        for s in raw_steps:
            st = str(s).strip()
            if st:
                test_steps.append(st)

    test_result_raw = str(test_raw.get("result", "")).strip().lower()
    if test_result_raw in {"fail", "failed", "not_satisfied", "不满足"}:
        test_result = "fail"
    elif test_result_raw in {"pass", "passed", "satisfied", "满足"}:
        test_result = "pass"
    else:
        test_result = test_result_raw

    test = {
        "name": str(test_raw.get("name", "")).strip(),
        "execution_mode": str(test_raw.get("execution_mode", "")).strip().lower(),
        "runtime_command": str(test_raw.get("runtime_command", "")).strip(),
        "runtime_output_excerpt": str(test_raw.get("runtime_output_excerpt", "")).strip(),
        "steps": test_steps,
        "expected": str(test_raw.get("expected", "")).strip(),
        "observed": str(test_raw.get("observed", "")).strip(),
        "result": test_result,
    }

    analysis = str(raw_obj.get("analysis", "")).strip()
    confidence = _clamp_confidence(raw_obj.get("confidence", 0.0))
    next_actions: list[str] = []
    raw_actions = raw_obj.get("next_actions", [])
    if isinstance(raw_actions, list):
        for x in raw_actions:
            s = str(x).strip()
            if s:
                next_actions.append(s)

    return {
        "result": result,
        "static_analysis": static_analysis,
        "test": test,
        "analysis": analysis,
        "confidence": confidence,
        "next_actions": next_actions,
    }


def _truncate_json_for_prompt(obj: Any, max_chars: int) -> str:
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated]"


def _find_claude_cmd() -> str:
    import shutil

    cmd_path = shutil.which("claude.cmd") or shutil.which("claude")
    if cmd_path:
        return cmd_path
    npm_global = Path.home() / "AppData" / "Roaming" / "npm" / "claude.cmd"
    if npm_global.exists():
        return str(npm_global)
    raise FileNotFoundError("cannot find claude or claude.cmd in PATH")


def _find_git_bash() -> str:
    import shutil

    existing = os.environ.get("CLAUDE_CODE_GIT_BASH_PATH", "")
    if existing and Path(existing).exists():
        return existing

    bash = shutil.which("bash")
    if bash:
        return bash

    # Fallback: probe common Program Files roots without hardcoding absolute paths.
    for env_name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_name, "")
        if not base:
            continue
        candidate = Path(base) / "Git" / "bin" / "bash.exe"
        if candidate.exists():
            return str(candidate)

    raise FileNotFoundError("cannot find git-bash; set CLAUDE_CODE_GIT_BASH_PATH")


def run_claude_exec_json(
    *,
    prompt: str,
    model: str,
    codebase_path: Path,
    timeout_sec: int,
    show_claude_stream: bool,
    heartbeat_sec: int,
) -> dict[str, Any]:
    claude_cmd = _find_claude_cmd()
    git_bash = _find_git_bash()

    env = os.environ.copy()
    env["CLAUDE_CODE_GIT_BASH_PATH"] = git_bash

    cmd = [
        claude_cmd,
        "-p",
        "--model", model,
        "--dangerously-skip-permissions",
        "--output-format", "stream-json",
        "--verbose",
        "--max-turns", "50",
    ]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(codebase_path),
    )

    if proc.stdin is None or proc.stdout is None or proc.stderr is None:
        raise RuntimeError("failed to create subprocess pipes for claude")

    proc.stdin.write(prompt)
    proc.stdin.close()

    stdout_lines: deque[str] = deque(maxlen=2000)
    stderr_lines: deque[str] = deque(maxlen=400)

    def _consume_stderr() -> None:
        try:
            assert proc.stderr is not None
            while True:
                line = proc.stderr.readline()
                if line == "":
                    break
                text = line.rstrip("\r\n")
                stderr_lines.append(text)
                if show_claude_stream and text:
                    print(f"[CLAUDE/ERR] {text}", file=sys.stderr, flush=True)
        finally:
            try:
                proc.stderr.close()  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                pass

    def _consume_stdout() -> None:
        try:
            assert proc.stdout is not None
            while True:
                line = proc.stdout.readline()
                if line == "":
                    break
                text = line.rstrip("\r\n")
                stdout_lines.append(text)
                if not text:
                    continue
                if not show_claude_stream:
                    continue
                try:
                    evt = json.loads(text)
                except json.JSONDecodeError:
                    print(f"[CLAUDE] {text}", file=sys.stderr, flush=True)
                    continue
                etype = evt.get("type", "")
                if etype == "assistant":
                    msg = evt.get("message", {})
                    for block in msg.get("content", []):
                        if block.get("type") == "text":
                            print(f"[CLAUDE/TEXT] {block['text'][:200]}", file=sys.stderr, flush=True)
                        elif block.get("type") == "tool_use":
                            name = block.get("name", "?")
                            inp = json.dumps(block.get("input", {}), ensure_ascii=False)
                            if len(inp) > 200:
                                inp = inp[:200] + "..."
                            print(f"[CLAUDE/TOOL] {name}: {inp}", file=sys.stderr, flush=True)
                        elif block.get("type") == "thinking":
                            thinking = block.get("thinking", "")
                            if thinking:
                                preview = thinking[:150].replace("\n", " ")
                                print(f"[CLAUDE/THINK] {preview}...", file=sys.stderr, flush=True)
                elif etype == "user":
                    msg = evt.get("message", {})
                    for block in msg.get("content", []):
                        if block.get("type") == "tool_result":
                            content = str(block.get("content", ""))
                            if len(content) > 200:
                                content = content[:200] + "..."
                            print(f"[CLAUDE/RESULT] {content}", file=sys.stderr, flush=True)
                elif etype == "result":
                    result_text = evt.get("result", "")
                    if result_text:
                        preview = str(result_text)[:200]
                        print(f"[CLAUDE/FINAL] {preview}", file=sys.stderr, flush=True)
        finally:
            try:
                proc.stdout.close()  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                pass

    t_out = threading.Thread(target=_consume_stdout, daemon=True)
    t_err = threading.Thread(target=_consume_stderr, daemon=True)
    t_out.start()
    t_err.start()

    timeout_limit: float | None = None
    if timeout_sec > 0:
        timeout_limit = max(30, timeout_sec)
    start = time.monotonic()
    last_heartbeat = start
    while True:
        ret = proc.poll()
        now = time.monotonic()
        if ret is not None:
            break

        if timeout_limit is not None and now - start > timeout_limit:
            proc.kill()
            t_out.join(timeout=1.0)
            t_err.join(timeout=1.0)
            raise TimeoutError(f"claude timed out after {timeout_limit}s")

        if show_claude_stream and heartbeat_sec > 0 and now - last_heartbeat >= heartbeat_sec:
            elapsed = int(now - start)
            print(
                f"[CLAUDE] running... elapsed={elapsed}s",
                file=sys.stderr,
                flush=True,
            )
            last_heartbeat = now

        time.sleep(0.2)

    t_out.join(timeout=3.0)
    t_err.join(timeout=3.0)

    if proc.returncode != 0:
        stderr_tail = list(stderr_lines)[-20:]
        stdout_tail = list(stdout_lines)[-20:]
        raise RuntimeError(
            "claude failed (model={}, code={}):\nSTDOUT tail:\n{}\nSTDERR tail:\n{}".format(
                model,
                proc.returncode,
                "\n".join(stdout_tail),
                "\n".join(stderr_tail),
            )
        )

    result_text = ""
    for line in reversed(stdout_lines):
        if not line.strip():
            continue
        try:
            evt = json.loads(line)
            if evt.get("type") == "result":
                result_text = evt.get("result", "")
                break
        except json.JSONDecodeError:
            continue

    if not result_text:
        raw_all = "\n".join(stdout_lines).strip()
        if not raw_all:
            raise RuntimeError("claude finished but produced no output")
        result_text = raw_all

    raw_text = str(result_text)
    try:
        parsed = extract_json_object(raw_text)
    except Exception as e:  # noqa: BLE001
        preview = raw_text[:800].replace("\n", "\\n")
        raise ValueError(f"failed to parse stage2 JSON: {e}; raw_preview={preview}") from e
    return {
        "raw_text": raw_text,
        "json": parsed,
        "stdout_tail": list(stdout_lines)[-20:],
        "stderr_tail": list(stderr_lines)[-20:],
    }


def read_standard_text(args: argparse.Namespace, *, codebase_path: Path) -> tuple[str, str]:
    if args.standard_text and args.standard_text.strip():
        return args.standard_text.strip(), "inline(--standard-text)"

    if args.standard_file:
        sf = Path(args.standard_file)
        if not sf.is_absolute():
            sf = (codebase_path / sf).resolve(strict=False)
        if not sf.exists():
            raise ValueError(f"standard file not found: {sf}")
        return sf.read_text(encoding="utf-8", errors="replace"), str(sf)

    return (
        "NOT_PROVIDED. Use the requirement claim implied in description only; if too weak, return not_satisfied only when test evidence is concrete.",
        "missing",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Find all top-level not-satisfied/insufficient items in result.json, then run stage-2 practical test for each (Claude version)."
        )
    )
    parser.add_argument("--input", default="result.json", help="path to result.json")
    parser.add_argument(
        "--output",
        default="output/recheck_not_satisfied_stage2_only_claude.json",
        help="path to final output json",
    )
    parser.add_argument(
        "--codebase-path",
        default=".",
        help="repository path to be inspected by claude via --cwd",
    )
    parser.add_argument(
        "--standard-file",
        default="",
        help="optional requirement/standard text file",
    )
    parser.add_argument(
        "--standard-text",
        default="",
        help="optional requirement/standard text inline",
    )
    parser.add_argument("--test-model", default="claude-opus-4-7")
    parser.add_argument(
        "--timeout-sec",
        type=int,
        default=0,
        help="timeout seconds for each Claude run; 0 disables timeout",
    )
    parser.add_argument(
        "--hide-claude-stream",
        action="store_true",
        help="hide live Claude stdout/stderr stream (default: show)",
    )
    parser.add_argument(
        "--claude-heartbeat-sec",
        type=int,
        default=8,
        help="heartbeat interval seconds while Claude runs; 0 disables heartbeat",
    )
    parser.add_argument("--not-satisfied-value", default="不满足")
    parser.add_argument(
        "--not-satisfied-alias",
        action="append",
        default=[],
        help="extra alias for not-satisfied result, repeatable",
    )
    parser.add_argument("--insufficient-value", default="证据不足")
    parser.add_argument(
        "--insufficient-alias",
        action="append",
        default=[],
        help="extra alias for insufficient result, repeatable",
    )
    parser.add_argument(
        "--context-max-chars",
        type=int,
        default=12000,
        help="max chars for source object context inside stage-2 prompt",
    )
    args = parser.parse_args()

    try:
        codebase_path = Path(args.codebase_path)
        if not codebase_path.is_absolute():
            codebase_path = (Path.cwd() / codebase_path).resolve(strict=False)
        if not codebase_path.exists():
            raise ValueError(f"codebase path not found: {codebase_path}")

        input_path = Path(args.input)
        if not input_path.is_absolute():
            input_path = (Path.cwd() / input_path).resolve(strict=False)
        if not input_path.exists():
            raise ValueError(f"input file not found: {input_path}")

        output_path = Path(args.output)
        if not output_path.is_absolute():
            output_path = (Path.cwd() / output_path).resolve(strict=False)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        standard_text, standard_source = read_standard_text(args, codebase_path=codebase_path)
        data = load_result_array(input_path)
        print(
            f"[FLOW] loaded input items={len(data)}, codebase={codebase_path}",
            file=sys.stderr,
            flush=True,
        )

        target_items: list[dict[str, Any]] = []
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                continue
            result_value = str(item.get("result", "")).strip()
            if is_not_satisfied(
                result_value,
                target_value=args.not_satisfied_value,
                aliases=args.not_satisfied_alias,
            ):
                target_items.append(
                    {
                        "index": idx,
                        "item": item,
                        "matched_result": result_value,
                        "matched_result_kind": "not_satisfied",
                    }
                )
                continue
            if is_insufficient(
                result_value,
                target_value=args.insufficient_value,
                aliases=args.insufficient_alias,
            ):
                target_items.append(
                    {
                        "index": idx,
                        "item": item,
                        "matched_result": result_value,
                        "matched_result_kind": "insufficient",
                    }
                )
                continue

        if not target_items:
            out = {
                "status": "no_target_result",
                "input": str(input_path),
                "codebase_path": str(codebase_path),
                "total_items": len(data),
                "claude_calls": 0,
                "message": "No item with result not_satisfied/insufficient found. Stop without calling Claude.",
            }
            output_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 0

        print(
            f"[FLOW] matched top-level items={len(target_items)}, running stage2 with model={args.test_model}",
            file=sys.stderr,
            flush=True,
        )
        processed_results: list[dict[str, Any]] = []
        missing_desc_items: list[dict[str, Any]] = []
        failed_items: list[dict[str, Any]] = []
        claude_calls = 0

        for target in target_items:
            matched_idx = int(target["index"])
            matched_obj = target["item"]
            matched_result = str(target["matched_result"])
            matched_result_kind = str(target["matched_result_kind"])
            first_desc = extract_desc(matched_obj)
            if not first_desc:
                missing_desc_items.append(
                    {
                        "matched_index": matched_idx,
                        "matched_result": matched_result,
                        "matched_result_kind": matched_result_kind,
                        "message": "Target item desc is missing. Skipped.",
                    }
                )
                continue

            context_json = _truncate_json_for_prompt(matched_obj, max_chars=args.context_max_chars)
            print(
                f"[FLOW] matched index={matched_idx}, kind={matched_result_kind}, running stage2 with model={args.test_model}",
                file=sys.stderr,
                flush=True,
            )
            stage2_prompt = STAGE2_PROMPT_TEMPLATE.format(
                codebase_path=str(codebase_path),
                standard_source=standard_source,
                standard_text=standard_text,
                desc=first_desc,
                context_json=context_json,
            )
            try:
                stage2_exec = run_claude_exec_json(
                    prompt=stage2_prompt,
                    model=args.test_model,
                    codebase_path=codebase_path,
                    timeout_sec=args.timeout_sec,
                    show_claude_stream=not args.hide_claude_stream,
                    heartbeat_sec=max(0, args.claude_heartbeat_sec),
                )
                stage2 = sanitize_stage2(stage2_exec["json"])
                claude_calls += 1
                print(
                    f"[FLOW] stage2 finished and sanitized for index={matched_idx}",
                    file=sys.stderr,
                    flush=True,
                )
            except Exception as item_err:  # noqa: BLE001
                failed_items.append(
                    {
                        "matched_index": matched_idx,
                        "matched_result": matched_result,
                        "matched_result_kind": matched_result_kind,
                        "desc": first_desc,
                        "error": str(item_err),
                    }
                )
                continue

            if stage2.get("result") == "not_satisfied":
                final_decision = "Not satisfied by practical test."
            else:
                final_decision = "Satisfied by practical test."

            processed_results.append(
                {
                    "matched_index": matched_idx,
                    "matched_result": matched_result,
                    "matched_result_kind": matched_result_kind,
                    "desc": first_desc,
                    "test_stage": {
                        "model": args.test_model,
                        "result": stage2,
                        "claude_last_message": stage2_exec["json"],
                        "claude_last_message_raw": stage2_exec["raw_text"],
                    },
                    "final_decision": final_decision,
                }
            )

        if failed_items or missing_desc_items:
            status = "partial_done"
        else:
            status = "done"

        satisfied_by_test = sum(
            1 for x in processed_results if x.get("test_stage", {}).get("result", {}).get("result") == "satisfied"
        )
        not_satisfied_by_test = sum(
            1 for x in processed_results if x.get("test_stage", {}).get("result", {}).get("result") == "not_satisfied"
        )

        out = {
            "status": status,
            "input": str(input_path),
            "output": str(output_path),
            "codebase_path": str(codebase_path),
            "total_items": len(data),
            "matched_top_level_items": len(target_items),
            "skipped_non_target_items": len(data) - len(target_items),
            "standard_source": standard_source,
            "results": processed_results,
            "missing_desc_items": missing_desc_items,
            "failed_items": failed_items,
            "summary": {
                "processed_items": len(processed_results),
                "missing_desc_items": len(missing_desc_items),
                "failed_items": len(failed_items),
                "satisfied_by_test": satisfied_by_test,
                "not_satisfied_by_test": not_satisfied_by_test,
            },
            "claude_calls": claude_calls,
        }
        output_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    except Exception as e:  # noqa: BLE001
        err = {
            "status": "error",
            "error": str(e),
        }
        print(json.dumps(err, ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
