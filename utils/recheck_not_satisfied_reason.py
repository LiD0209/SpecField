#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any


STAGE1_PROMPT_TEMPLATE = """
You are a strict verifier.

Goal:
Verify whether the given description is a TRUE mismatch between requirement and implementation.

Repository root:
{codebase_path}

Requirement source:
{standard_source}

Requirement text:
{standard_text}

Description to verify:
{desc}

Related object context:
{context_json}

Instructions:
1) Inspect repository code directly.
2) Judge against the repository's default configuration behavior.
3) Determine default compile-time feature flags from build configuration files first (e.g., configure.ac / CMakeLists.txt).
4) Treat code paths guarded by default-disabled feature flags as inactive for this judgment.
5) Decide: true_mismatch, not_mismatch, or insufficient.
6) If requirement text is missing/too weak, use insufficient.
7) Provide concrete evidence with file path and short detail.

Output strict JSON only:
{{
  "true_mismatch": true,
  "verdict": "true_mismatch|not_mismatch|insufficient",
  "analysis": "2-6 sentences",
  "evidence": [
    {{
      "file": "relative/or/absolute/path",
      "line_hint": "optional line or function",
      "detail": "what this evidence proves"
    }}
  ],
  "confidence": 0.0
}}
""".strip()


STAGE2_PROMPT_TEMPLATE = """
You are a second-pass practical tester.

Goal:
Run one practical test to validate whether the mismatch is real.

Repository root:
{codebase_path}

Requirement source:
{standard_source}

Requirement text:
{standard_text}

Description under test:
{desc}

Stage-1 result:
{stage1_json}

Instructions:
1) Define one concrete test scenario based on requirement + description.
2) Judge against the repository's default configuration behavior.
3) Determine default compile-time feature flags from build configuration files first (e.g., configure.ac / CMakeLists.txt).
4) Treat code paths guarded by default-disabled feature flags as inactive for this judgment.
5) Execute one practical test using repository evidence:
   - Prefer runnable test/command if feasible.
   - If not feasible, run one static trace test on concrete code path.
6) Report expected vs observed and pass/fail for this single test.
7) Return exactly one final result:
   - "not_satisfied": requirement is not met by implementation.
   - "satisfied": requirement is met by implementation.
   No uncertain/insufficient option in stage-2.

Output strict JSON only:
{{
  "result": "satisfied|not_satisfied",
  "test": {{
    "name": "single test name",
    "execution_mode": "runtime|static_trace",
    "steps": ["step1", "step2"],
    "expected": "expected behavior by requirement",
    "observed": "actual behavior from test",
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


def sanitize_stage1(raw_obj: dict[str, Any]) -> dict[str, Any]:
    verdict = str(raw_obj.get("verdict", "")).strip().lower()
    true_mismatch = raw_obj.get("true_mismatch", False)
    if isinstance(true_mismatch, str):
        true_mismatch = true_mismatch.strip().lower() == "true"
    true_mismatch = bool(true_mismatch)

    if not true_mismatch and verdict == "true_mismatch":
        true_mismatch = True

    if verdict not in {"true_mismatch", "not_mismatch", "insufficient"}:
        verdict = "true_mismatch" if true_mismatch else "insufficient"

    analysis = str(raw_obj.get("analysis", "")).strip()
    confidence = _clamp_confidence(raw_obj.get("confidence", 0.0))

    evidence: list[dict[str, str]] = []
    raw_ev = raw_obj.get("evidence", [])
    if isinstance(raw_ev, list):
        for item in raw_ev:
            if not isinstance(item, dict):
                continue
            evidence.append(
                {
                    "file": str(item.get("file", "")).strip(),
                    "line_hint": str(item.get("line_hint", "")).strip(),
                    "detail": str(item.get("detail", "")).strip(),
                }
            )
    return {
        "true_mismatch": true_mismatch,
        "verdict": verdict,
        "analysis": analysis,
        "evidence": evidence,
        "confidence": confidence,
    }


def sanitize_stage2(raw_obj: dict[str, Any]) -> dict[str, Any]:
    result_raw = str(raw_obj.get("result", "")).strip().lower()
    result = ""
    if result_raw in {"not_satisfied", "notsatisfied", "not satisfied", "fail", "不满足"}:
        result = "not_satisfied"
    elif result_raw in {"satisfied", "pass", "满足"}:
        result = "satisfied"
    else:
        # Backward compatibility with old stage-2 schema.
        confirmed = raw_obj.get("confirmed_mismatch", False)
        if isinstance(confirmed, str):
            confirmed = confirmed.strip().lower() == "true"
        confirmed = bool(confirmed)
        verdict = str(raw_obj.get("final_verdict", "")).strip().lower()
        if not confirmed and verdict == "confirmed_mismatch":
            confirmed = True
        result = "not_satisfied" if confirmed else "satisfied"

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
    test = {
        "name": str(test_raw.get("name", "")).strip(),
        "execution_mode": str(test_raw.get("execution_mode", "")).strip().lower(),
        "steps": test_steps,
        "expected": str(test_raw.get("expected", "")).strip(),
        "observed": str(test_raw.get("observed", "")).strip(),
        "result": (
            "fail"
            if str(test_raw.get("result", "")).strip().lower() in {"fail", "failed", "not_satisfied", "不满足"}
            else "pass"
            if str(test_raw.get("result", "")).strip().lower() in {"pass", "passed", "satisfied", "满足"}
            else str(test_raw.get("result", "")).strip().lower()
        ),
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
) -> dict[str, Any]:
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
        cp = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=max(30, timeout_sec),
        )
        if cp.returncode != 0:
            stderr_tail = (cp.stderr or "").strip().splitlines()[-20:]
            stdout_tail = (cp.stdout or "").strip().splitlines()[-20:]
            raise RuntimeError(
                "codex exec failed (model={}, code={}):\nSTDOUT tail:\n{}\nSTDERR tail:\n{}".format(
                    model,
                    cp.returncode,
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
            "stdout_tail": (cp.stdout or "").strip().splitlines()[-20:],
            "stderr_tail": (cp.stderr or "").strip().splitlines()[-20:],
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
        "NOT_PROVIDED. Use the requirement claim implied in description only; if too weak, return insufficient.",
        "missing",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Find first not-satisfied item in result.json, then run stage-1 review and optional stage-2 practical test."
        )
    )
    parser.add_argument("--input", default="result.json", help="path to result.json")
    parser.add_argument(
        "--output",
        default="output/recheck_not_satisfied_final.json",
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
    parser.add_argument("--review-model", default="gpt-5.4")
    parser.add_argument("--test-model", default="gpt-5.3-codex")
    parser.add_argument("--timeout-sec", type=int, default=900)
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
        help="max chars for source object context inside stage-1 prompt",
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
        stage1_prompt = STAGE1_PROMPT_TEMPLATE.format(
            codebase_path=str(codebase_path),
            standard_source=standard_source,
            standard_text=standard_text,
            desc=first_desc,
            context_json=context_json,
        )
        stage1_exec = run_codex_exec_json(
            prompt=stage1_prompt,
            model=args.review_model,
            codebase_path=codebase_path,
            timeout_sec=args.timeout_sec,
        )
        stage1 = sanitize_stage1(stage1_exec["json"])
        need_stage2 = bool(stage1["true_mismatch"] or stage1["verdict"] == "insufficient")

        stage2_exec: dict[str, Any] | None = None
        stage2: dict[str, Any] | None = None
        if need_stage2:
            stage2_prompt = STAGE2_PROMPT_TEMPLATE.format(
                codebase_path=str(codebase_path),
                standard_source=standard_source,
                standard_text=standard_text,
                desc=first_desc,
                stage1_json=json.dumps(stage1, ensure_ascii=False, indent=2),
            )
            stage2_exec = run_codex_exec_json(
                prompt=stage2_prompt,
                model=args.test_model,
                codebase_path=codebase_path,
                timeout_sec=args.timeout_sec,
            )
            stage2 = sanitize_stage2(stage2_exec["json"])

        if not need_stage2:
            final_decision = "Stage-1 verdict is not_mismatch; stop."
        elif stage2 and stage2.get("result") == "not_satisfied":
            final_decision = "Not satisfied by stage-2 practical test."
        else:
            final_decision = "Satisfied by stage-2 practical test."

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
            "review_stage": {
                "model": args.review_model,
                "result": stage1,
                "codex_last_message": stage1_exec["json"],
                "codex_last_message_raw": stage1_exec["raw_text"],
            },
            "need_stage2_test": need_stage2,
            "test_stage": (
                {
                    "model": args.test_model,
                    "result": stage2,
                    "codex_last_message": stage2_exec["json"] if stage2_exec else {},
                    "codex_last_message_raw": stage2_exec["raw_text"] if stage2_exec else "",
                }
                if need_stage2
                else None
            ),
            "codex_calls": 1 + (1 if need_stage2 else 0),
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
