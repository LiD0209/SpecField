#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
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

3) First perform static analysis.
- The first judgment must be whether the implementation appears consistent with the description under test.
- Output this preliminary judgment as either "satisfied" or "not_satisfied".

4) Judge against the repository's default configuration behavior.

5) Determine default compile-time feature flags from build configuration files first
(e.g., configure.ac, CMakeLists.txt, build scripts, default config headers).

6) Treat code paths guarded by default-disabled feature flags as inactive for this judgment.

7) Focus on whether the implementation behavior matches the description.
- Do not drift into unrelated code quality review.
- Do not judge based on hypothetical alternate configurations unless they are default-enabled.

8) If the description under test is clearly enough on its own, rely on it directly.
- Do not let requirement text override the description unless the description is truly underspecified.

9) After static analysis:
- If static analysis shows a likely mismatch, run a real runtime test or targeted build/test command when feasible.
- If static analysis shows it is satisfied, still prefer a boundary or negative test when feasible to confirm the implementation actually behaves as described.

10) Testing should target the claimed behavior boundary.
- Prefer counterexample tests or rejection-path tests over ordinary success-path tests.
- Do not treat an ordinary successful run as sufficient evidence unless it directly exercises the relevant behavior described.

11) If a runtime test is not feasible, explain the concrete blocker and use a static trace instead.

12) Report expected vs observed behavior clearly for the performed test.

13) Return exactly one final result:
- "not_satisfied": the implementation does not match the description under test.
- "satisfied": the implementation matches the description under test.

14) Do not return "uncertain", "insufficient", or any third state.

Output strict JSON only:
{{
"result": "satisfied|not_satisfied",
"static_analysis": {{
"comparison": "description under test vs repository implementation, with requirement text used only as supplementary context when needed",
"preliminary_result": "satisfied|not_satisfied",
"reason": "2-4 sentences",
"key_evidence": ["evidence1", "evidence2"]
}},
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
    if "[non-English text removed]satisfied" in raw:
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
    if "[non-English text removed]" in raw:
        return True

    norm = _normalize_token(raw)
    candidates = [target_value, *aliases, "insufficient", "evidence_insufficient", "not_enough_evidence"]
    for c in candidates:
        if norm == _normalize_token(c):
            return True
    return False


def extract_desc(obj: dict[str, Any]) -> str:
    return str(obj.get("desc", "")).strip()


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
        raise ValueError("cannot extract JSON object from codex output")

    obj = json.loads(text[start : end + 1])
    if not isinstance(obj, dict):
        raise ValueError("codex output is not a JSON object")
    return obj


def _clamp_confidence(v: Any) -> float:
    try:
        out = float(v)
    except (TypeError, ValueError):
        out = 0.0
    return max(0.0, min(1.0, out))


def sanitize_stage2(raw_obj: dict[str, Any]) -> dict[str, Any]:
    result_raw = str(raw_obj.get("result", "")).strip().lower()
    if result_raw in {"not_satisfied", "notsatisfied", "not satisfied", "fail", "[non-English text removed]satisfied"}:
        result = "not_satisfied"
    elif result_raw in {"satisfied", "pass", "satisfied"}:
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
    if test_result_raw in {"fail", "failed", "not_satisfied", "[non-English text removed]satisfied"}:
        test_result = "fail"
    elif test_result_raw in {"pass", "passed", "satisfied", "satisfied"}:
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


def run_codex_exec_json(
    *,
    prompt: str,
    model: str,
    codebase_path: Path,
    timeout_sec: int,
    show_codex_stream: bool,
    heartbeat_sec: int,
) -> dict[str, Any]:
    def _consume_stream(
        stream: Any,
        *,
        tag: str,
        sink: deque[str],
        show: bool,
    ) -> None:
        try:
            while True:
                line = stream.readline()
                if line == "":
                    break
                text = line.rstrip("\r\n")
                sink.append(text)
                if show and text:
                    print(f"[{tag}] {text}", file=sys.stderr, flush=True)
        finally:
            try:
                stream.close()
            except Exception:  # noqa: BLE001
                pass

    with tempfile.TemporaryDirectory(prefix="codex_exec_") as td:
        out_file = Path(td) / "last_message.txt"
        cmd = [
            "cmd",
            "/c",
            "codex",
            "exec",
            "-m",
            model,
            "-C",
            str(codebase_path),
            "--skip-git-repo-check",
            "-o",
            str(out_file),
            "-",
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        if proc.stdin is None or proc.stdout is None or proc.stderr is None:
            raise RuntimeError("failed to create subprocess pipes for codex exec")

        proc.stdin.write(prompt)
        proc.stdin.close()

        stdout_lines: deque[str] = deque(maxlen=400)
        stderr_lines: deque[str] = deque(maxlen=400)
        t_out = threading.Thread(
            target=_consume_stream,
            kwargs={
                "stream": proc.stdout,
                "tag": "CODEX/STDOUT",
                "sink": stdout_lines,
                "show": show_codex_stream,
            },
            daemon=True,
        )
        t_err = threading.Thread(
            target=_consume_stream,
            kwargs={
                "stream": proc.stderr,
                "tag": "CODEX/STDERR",
                "sink": stderr_lines,
                "show": show_codex_stream,
            },
            daemon=True,
        )
        t_out.start()
        t_err.start()

        timeout_limit = max(30, timeout_sec)
        start = time.monotonic()
        last_heartbeat = start
        while True:
            ret = proc.poll()
            now = time.monotonic()
            if ret is not None:
                break

            if now - start > timeout_limit:
                proc.kill()
                t_out.join(timeout=1.0)
                t_err.join(timeout=1.0)
                raise TimeoutError(f"codex exec timed out after {timeout_limit}s")

            if show_codex_stream and heartbeat_sec > 0 and now - last_heartbeat >= heartbeat_sec:
                elapsed = int(now - start)
                msg_file_size = out_file.stat().st_size if out_file.exists() else 0
                print(
                    f"[CODEX] running... elapsed={elapsed}s, last_message_bytes={msg_file_size}",
                    file=sys.stderr,
                    flush=True,
                )
                last_heartbeat = now

            time.sleep(0.2)

        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)

        if proc.returncode != 0:
            stderr_tail = list(stderr_lines)[-20:]
            stdout_tail = list(stdout_lines)[-20:]
            raise RuntimeError(
                "codex exec failed (model={}, code={}):\nSTDOUT tail:\n{}\nSTDERR tail:\n{}".format(
                    model,
                    proc.returncode,
                    "\n".join(stdout_tail),
                    "\n".join(stderr_tail),
                )
            )
        if not out_file.exists():
            raise RuntimeError("codex exec finished but last message file not found")

        raw_text = out_file.read_text(encoding="utf-8", errors="replace").strip()
        parsed = extract_json_object(raw_text)
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
            "Find first not-satisfied/insufficient item in result.json, then run stage-2 practical test only."
        )
    )
    parser.add_argument("--input", default="result.json", help="path to result.json")
    parser.add_argument(
        "--output",
        default="output/recheck_not_satisfied_stage2_only.json",
        help="path to final output json",
    )
    parser.add_argument(
        "--codebase-path",
        default=".",
        help="repository path to be inspected by codex exec via -C",
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
    parser.add_argument("--test-model", default="gpt-5.3-codex")
    parser.add_argument("--timeout-sec", type=int, default=900)
    parser.add_argument(
        "--hide-codex-stream",
        action="store_true",
        help="hide live Codex stdout/stderr stream (default: show)",
    )
    parser.add_argument(
        "--codex-heartbeat-sec",
        type=int,
        default=8,
        help="heartbeat interval seconds while Codex runs; 0 disables heartbeat",
    )
    parser.add_argument("--not-satisfied-value", default="[non-English text removed]satisfied")
    parser.add_argument(
        "--not-satisfied-alias",
        action="append",
        default=[],
        help="extra alias for not-satisfied result, repeatable",
    )
    parser.add_argument("--insufficient-value", default="[non-English text removed]")
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

        matched_idx: int | None = None
        matched_obj: dict[str, Any] | None = None
        matched_result = ""
        matched_result_kind = ""
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                continue
            result_value = str(item.get("result", "")).strip()
            if is_not_satisfied(
                result_value,
                target_value=args.not_satisfied_value,
                aliases=args.not_satisfied_alias,
            ):
                matched_idx = idx
                matched_obj = item
                matched_result = result_value
                matched_result_kind = "not_satisfied"
                break
            if is_insufficient(
                result_value,
                target_value=args.insufficient_value,
                aliases=args.insufficient_alias,
            ):
                matched_idx = idx
                matched_obj = item
                matched_result = result_value
                matched_result_kind = "insufficient"
                break

        if matched_obj is None:
            out = {
                "status": "no_target_result",
                "input": str(input_path),
                "codebase_path": str(codebase_path),
                "total_items": len(data),
                "codex_calls": 0,
                "message": "No item with result not_satisfied/insufficient found. Stop without calling Codex.",
            }
            output_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 0

        first_desc = extract_desc(matched_obj)
        if not first_desc:
            out = {
                "status": "missing_desc",
                "input": str(input_path),
                "codebase_path": str(codebase_path),
                "matched_index": matched_idx,
                "matched_result": matched_result,
                "matched_result_kind": matched_result_kind,
                "codex_calls": 0,
                "message": "Found target item but desc is missing.",
            }
            output_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 1

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
        stage2_exec = run_codex_exec_json(
            prompt=stage2_prompt,
            model=args.test_model,
            codebase_path=codebase_path,
            timeout_sec=args.timeout_sec,
            show_codex_stream=not args.hide_codex_stream,
            heartbeat_sec=max(0, args.codex_heartbeat_sec),
        )
        stage2 = sanitize_stage2(stage2_exec["json"])
        print("[FLOW] stage2 finished and sanitized", file=sys.stderr, flush=True)

        if stage2.get("result") == "not_satisfied":
            final_decision = "Not satisfied by practical test."
        else:
            final_decision = "Satisfied by practical test."

        out = {
            "status": "done",
            "input": str(input_path),
            "output": str(output_path),
            "codebase_path": str(codebase_path),
            "total_items": len(data),
            "matched_index": matched_idx,
            "matched_result": matched_result,
            "matched_result_kind": matched_result_kind,
            "desc": first_desc,
            "standard_source": standard_source,
            "test_stage": {
                "model": args.test_model,
                "result": stage2,
                "codex_last_message": stage2_exec["json"],
                "codex_last_message_raw": stage2_exec["raw_text"],
            },
            "codex_calls": 1,
            "final_decision": final_decision,
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
