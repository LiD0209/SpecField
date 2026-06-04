#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline_utils import (
    OpenAICompatClient,
    extract_json_array,
    normalize_text,
    now_ts,
    write_json,
)

METHOD_ZERO_SHOT = "0-shot"
METHOD_TWO_SHOT = "2-shot"
METHOD_SCHEMA_ONLY = "schema-only"
METHODS = (METHOD_ZERO_SHOT, METHOD_TWO_SHOT, METHOD_SCHEMA_ONLY)

MODALITIES = {"MUST", "MUST NOT", "SHOULD", "SHOULD NOT"}
ACTION_TYPES = {
    "assign",
    "derive",
    "select",
    "require-present",
    "require-absent",
    "compare",
    "range-check",
    "state-update",
    "reject",
}

ZERO_SHOT_PROMPT = """
You are a protocol-standards analysis assistant.
Extract field-level conformance rules directly from the CURRENT standard chunk.

A field-level rule means: under condition C, protocol field f must satisfy action or constraint A.
Only extract concrete rules for serialized/message fields, parameters, headers, flags, options, extensions, or structured payload fields.
Use only normative requirements in this chunk, especially MUST, MUST NOT, SHOULD, and SHOULD NOT. Ignore MAY.

Return only a JSON array. Each item must be:
{
  "f": "constrained protocol field",
  "C": "condition under which the rule applies",
  "A": "required action or constraint",
  "M": "MUST or MUST NOT or SHOULD or SHOULD NOT",
  "E": "short source evidence copied from this chunk"
}

Current chunk:
{chunk_text}
""".strip()

TWO_SHOT_PROMPT = """
You are a protocol-standards analysis assistant.
Extract field-level conformance rules directly from the CURRENT standard chunk.

A field-level rule means: under condition C, protocol field f must satisfy action or constraint A.
Only extract concrete rules for serialized/message fields, parameters, headers, flags, options, extensions, or structured payload fields.
Use only normative requirements in this chunk, especially MUST, MUST NOT, SHOULD, and SHOULD NOT. Ignore MAY.

Example 1:
Input text:
The Cookie extension contains a Cookie structure with opaque cookie<1..2^16-1>. A client receiving an invalid Cookie MUST abort the handshake.
Output:
[
  {
    "f": "Cookie.cookie",
    "C": "Client receives a TLS HelloRetryRequest Cookie extension.",
    "A": "Reject if the Cookie vector is empty or invalid.",
    "M": "MUST",
    "E": "opaque cookie<1..2^16-1>; client ... MUST abort"
  }
]

Example 2:
Input text:
The QoS bits in a PUBLISH packet MUST NOT both be set to 1. If a Server or Client receives a PUBLISH packet with QoS set to 3, it MUST close the Network Connection.
Output:
[
  {
    "f": "PUBLISH fixed header QoS bits",
    "C": "Endpoint receives a PUBLISH packet.",
    "A": "Reject or close the connection if QoS bits have value 3.",
    "M": "MUST NOT",
    "E": "QoS bits ... MUST NOT both be set to 1"
  }
]

Return only a JSON array in the same shape as the examples.

Current chunk:
{chunk_text}
""".strip()

SCHEMA_ONLY_PROMPT = """
You are a protocol-standards field-rule extractor.
Use only the CURRENT standard chunk. Do not assume a prebuilt field space or a global field catalog.

Task:
Extract normalized field-level rules from normative standard text.
A rule has the form <f, C, A, M, E>:
- f: concrete constrained protocol field, parameter, header field, flag, option, extension field, or structured payload member.
- C: condition under which the rule applies.
- A: required action or constraint.
- M: normative modality. Keep only MUST, MUST NOT, SHOULD, or SHOULD NOT. Ignore MAY.
- E: short source evidence copied from the current chunk.

Action families:
- assign: set, overwrite, clear, increment, decrement
- derive: compute from another field or value
- select: select from offered or negotiated values
- require-present: field must be present
- require-absent: field must be absent
- compare: equality, inequality, match, mismatch
- range-check: lower bound, upper bound, length bound, allowed range, membership
- state-update: update protocol state because of the field
- reject: abort, fail, close, ignore, send error, or reject invalid input

Normalization rules:
1. Split sentences with multiple independent constraints into multiple rules.
2. Rewrite negated requirements into explicit actions. For example, "MUST NOT accept x" becomes action_type "reject".
3. Do not emit broad security goals, implementation advice, performance guidance, or cryptographic assumptions with no concrete field.
4. Do not invent fields, conditions, or evidence outside this chunk.
5. If a cross-reference is mentioned but the relevant field/bound is not present in the current chunk, skip it.

Return only a JSON array. Each item must match this schema:
{
  "f": "",
  "C": "",
  "A": "",
  "M": "MUST",
  "E": "",
  "action_type": "assign|derive|select|require-present|require-absent|compare|range-check|state-update|reject",
  "source_location": "",
  "note": ""
}

Current chunk:
{chunk_text}
""".strip()

REPAIR_PROMPT = """
The previous output did not satisfy the required field-rule JSON schema.
Repair it using only the CURRENT standard chunk and the PREVIOUS OUTPUT.

Requirements:
- Return only a JSON array.
- Keep only concrete field-level normative rules.
- Keep only modalities: MUST, MUST NOT, SHOULD, SHOULD NOT.
- Every item must have non-empty f, C, A, M, and E.
- action_type, if present, must be one of: {action_types}.
- Drop any item whose source evidence is not supported by the current chunk.

CURRENT standard chunk:
{chunk_text}

PREVIOUS OUTPUT:
{raw_response}
""".strip()


def method_to_slug(method: str) -> str:
    return method.lower().replace("-", "_")


def build_prompt(method: str, chunk_text: str) -> str:
    templates = {
        METHOD_ZERO_SHOT: ZERO_SHOT_PROMPT,
        METHOD_TWO_SHOT: TWO_SHOT_PROMPT,
        METHOD_SCHEMA_ONLY: SCHEMA_ONLY_PROMPT,
    }
    if method not in templates:
        raise ValueError(f"Unsupported method: {method}")
    return templates[method].replace("{chunk_text}", chunk_text)


def _first_present(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = normalize_text(row.get(key))
        if value:
            return value
    return ""


def _normalize_modality(value: Any) -> str:
    text = normalize_text(value).upper().replace("_", " ")
    text = " ".join(text.split())
    if text in MODALITIES:
        return text
    if text == "MUSTNT":
        return "MUST NOT"
    if text == "SHOULDNT":
        return "SHOULD NOT"
    return ""


def _infer_action_type(action: str) -> str:
    low = action.lower()
    if any(word in low for word in ["reject", "abort", "fail", "close", "error", "ignore", "discard"]):
        return "reject"
    if any(word in low for word in ["present", "include", "contain", "appear"]):
        return "require-present"
    if any(word in low for word in ["absent", "omit", "not include", "not be sent"]):
        return "require-absent"
    if any(word in low for word in ["range", "bound", "less than", "greater than", "at least", "at most", "length"]):
        return "range-check"
    if any(word in low for word in ["equal", "match", "same", "different", "compare"]):
        return "compare"
    if any(word in low for word in ["derive", "compute", "calculate"]):
        return "derive"
    if any(word in low for word in ["select", "choose", "negotiate"]):
        return "select"
    if any(word in low for word in ["state", "update", "remember", "store"]):
        return "state-update"
    if any(word in low for word in ["set", "assign", "clear", "increment", "decrement"]):
        return "assign"
    return "compare"


def _evidence_supported(evidence: str, chunk_text: str) -> bool:
    ev = " ".join(evidence.lower().split())
    chunk = " ".join(chunk_text.lower().split())
    if not ev:
        return False
    if ev in chunk:
        return True
    tokens = [tok.strip(".,;:()[]{}<>\"'`") for tok in ev.split()]
    tokens = [tok for tok in tokens if len(tok) >= 4]
    if not tokens:
        return False
    hits = sum(1 for tok in tokens if tok in chunk)
    return hits >= max(2, min(5, len(tokens) // 2))


def normalize_rule(row: dict[str, Any], chunk_text: str, method: str, chunk_id: str) -> dict[str, Any] | None:
    field = _first_present(row, "f", "field", "variable_name", "field_name", "canonical_name")
    condition = _first_present(row, "C", "condition", "change_condition")
    action = _first_present(row, "A", "action", "constraint", "change_action")
    modality = _normalize_modality(_first_present(row, "M", "modality", "normative_modality"))
    evidence = _first_present(row, "E", "evidence", "source_evidence", "source_span")
    action_type = _first_present(row, "action_type", "action_family")
    source_location = _first_present(row, "source_location", "source_locations", "section", "module_or_section")
    note = _first_present(row, "note", "notes")

    if not field or not condition or not action or not modality or not evidence:
        return None
    if modality not in MODALITIES:
        return None
    if not _evidence_supported(evidence, chunk_text):
        return None

    action_type = action_type.strip().lower()
    if action_type and action_type not in ACTION_TYPES:
        action_type = ""
    if not action_type:
        action_type = _infer_action_type(action)

    return {
        "f": field,
        "C": condition,
        "A": action,
        "M": modality,
        "E": evidence,
        "action_type": action_type,
        "source_location": source_location,
        "note": note,
        "source_chunk_id": chunk_id,
        "extraction_method": method,
        "variable_name": field,
        "change_condition": condition,
        "change_action": action,
        "old_value": "",
        "new_value": "",
        "related_state_or_step": "",
        "explicit_or_inferred": "explicit",
        "evidence": evidence,
    }


def normalize_rules(rows: list[dict[str, Any]], chunk_text: str, method: str, chunk_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for row in rows:
        rule = normalize_rule(row, chunk_text, method, chunk_id)
        if rule is None:
            continue
        key = (
            rule["f"].lower(),
            rule["C"].lower(),
            rule["A"].lower(),
            rule["M"],
            rule["E"].lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(rule)
    return out


def dedupe_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dedup: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for rule in rules:
        key = (
            normalize_text(rule.get("f")).lower(),
            normalize_text(rule.get("C")).lower(),
            normalize_text(rule.get("A")).lower(),
            normalize_text(rule.get("M")).upper(),
        )
        if not all(key):
            continue
        if key not in dedup:
            dedup[key] = dict(rule)
            continue
        existing = dedup[key]
        if not existing.get("E") and rule.get("E"):
            existing["E"] = rule["E"]
            existing["evidence"] = rule["E"]
        old_chunk = normalize_text(existing.get("source_chunk_id"))
        new_chunk = normalize_text(rule.get("source_chunk_id"))
        if new_chunk and new_chunk not in old_chunk.split("; "):
            existing["source_chunk_id"] = f"{old_chunk}; {new_chunk}" if old_chunk else new_chunk
    return sorted(dedup.values(), key=lambda x: (x["f"].lower(), x["C"].lower(), x["A"].lower()))


def resolve_chunk_selector(chunks: list[dict[str, Any]], chunk_selector: str) -> tuple[int, dict[str, Any]]:
    selector = str(chunk_selector).strip()
    if not selector:
        raise ValueError("--chunk cannot be empty")

    if selector.startswith("chunk_"):
        for index, chunk in enumerate(chunks, start=1):
            if chunk.get("chunk_id") == selector:
                return index, chunk
        raise ValueError(f"--chunk {selector!r} not found")

    try:
        chunk_index = int(selector)
    except ValueError as exc:
        raise ValueError("--chunk must be a 1-based index or a chunk id like chunk_0051") from exc
    if chunk_index < 1 or chunk_index > len(chunks):
        raise ValueError(f"--chunk {chunk_index} out of range, total chunks={len(chunks)}")
    return chunk_index, chunks[chunk_index - 1]


def load_resume_rules(chunk_dir: Path, chunks: list[dict[str, Any]], stop_before: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rules: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    for chunk in chunks[: stop_before - 1]:
        chunk_id = chunk["chunk_id"]
        chunk_out = chunk_dir / f"{chunk_id}.json"
        if not chunk_out.exists():
            continue
        try:
            old = json.loads(chunk_out.read_text(encoding="utf-8"))
        except Exception:
            continue
        parsed = old.get("rules", old.get("parsed", []))
        if not isinstance(parsed, list):
            continue
        rules.extend([item for item in parsed if isinstance(item, dict)])
        logs.append(
            {
                "chunk_id": chunk_id,
                "parsed_count": len(parsed),
                "resumed_preload": True,
            }
        )
    return rules, logs


def run_method(
    method: str,
    chunks_path: str,
    output_path: str,
    api_key: str,
    base_url: str,
    model: str,
    max_retries_per_chunk: int,
    retry_backoff_sec: float,
    resume: bool,
    start_chunk: int,
    clear_existing: bool,
    repair_invalid: bool,
    chunk: str | None = None,
    chunk_output_dir: str | None = None,
) -> list[dict[str, Any]]:
    if method not in METHODS:
        raise ValueError(f"Unsupported method: {method}")

    chunks = json.loads(Path(chunks_path).read_text(encoding="utf-8"))
    if start_chunk < 1 or start_chunk > len(chunks):
        raise ValueError(f"--start-chunk {start_chunk} out of range, total chunks={len(chunks)}")

    out_path = Path(output_path)
    slug = method_to_slug(method)
    chunk_dir = Path(chunk_output_dir) if chunk_output_dir else out_path.parent / f"{out_path.stem}_{slug}_chunks"
    if clear_existing and resume:
        raise ValueError("--clear-existing cannot be used together with --resume")
    if chunk_dir.exists() and clear_existing:
        shutil.rmtree(chunk_dir)
    chunk_dir.mkdir(parents=True, exist_ok=True)

    client = OpenAICompatClient(api_key=api_key, base_url=base_url, model=model)
    total = len(chunks)
    append_single_chunk = chunk is not None
    if append_single_chunk:
        selected_start, selected_chunk = resolve_chunk_selector(chunks, chunk)
        selected_chunks = [selected_chunk]
    else:
        selected_start = start_chunk
        selected_chunks = chunks[start_chunk - 1 :]

    parsed_all: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    if resume and start_chunk > 1 and not append_single_chunk:
        preload_rules, preload_logs = load_resume_rules(chunk_dir, chunks, start_chunk)
        parsed_all.extend(preload_rules)
        logs.extend(preload_logs)

    for index, chunk_item in enumerate(selected_chunks, start=selected_start):
        chunk_id = chunk_item["chunk_id"]
        chunk_text = chunk_item["chunk_text"]
        chunk_out = chunk_dir / f"{chunk_id}.json"

        if resume and chunk_out.exists():
            try:
                old = json.loads(chunk_out.read_text(encoding="utf-8"))
                old_rules = old.get("rules", old.get("parsed", []))
                if isinstance(old_rules, list) and old_rules:
                    parsed_all.extend([item for item in old_rules if isinstance(item, dict)])
                    logs.append(
                        {
                            "chunk_id": chunk_id,
                            "parsed_count": len(old_rules),
                            "resumed": True,
                        }
                    )
                    print(f"[{now_ts()}] {method} {chunk_id} ({index}/{total}) resume-hit")
                    continue
            except Exception:
                pass

        print(f"[{now_ts()}] {method} {chunk_id} ({index}/{total})")
        prompt = build_prompt(method, chunk_text)
        last_err: Exception | None = None
        success = False
        raw_response = ""
        parsed_rules: list[dict[str, Any]] = []
        attempts_used = 0
        repaired = False

        for attempt in range(1, max(1, max_retries_per_chunk) + 1):
            attempts_used = attempt
            try:
                raw_response = client.chat(prompt)
                parsed = extract_json_array(raw_response)
                parsed_rules = normalize_rules(parsed, chunk_text, method, chunk_id)
                if repair_invalid and parsed and not parsed_rules:
                    repair_prompt = (
                        REPAIR_PROMPT.replace("{action_types}", ", ".join(sorted(ACTION_TYPES)))
                        .replace("{chunk_text}", chunk_text)
                        .replace("{raw_response}", raw_response)
                    )
                    raw_repair = client.chat(repair_prompt)
                    repaired = True
                    parsed_rules = normalize_rules(
                        extract_json_array(raw_repair),
                        chunk_text,
                        method,
                        chunk_id,
                    )
                    raw_response = raw_repair
                parsed_all.extend(parsed_rules)
                write_json(
                    chunk_out,
                    {
                        "method": method,
                        "chunk_id": chunk_id,
                        "parsed_count": len(parsed_rules),
                        "rules": parsed_rules,
                        "raw_response": raw_response,
                        "attempts": attempt,
                        "repaired": repaired,
                    },
                )
                logs.append(
                    {
                        "method": method,
                        "chunk_id": chunk_id,
                        "parsed_count": len(parsed_rules),
                        "attempts": attempt,
                        "repaired": repaired,
                    }
                )
                success = True
                break
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                if attempt < max(1, max_retries_per_chunk):
                    sleep_s = max(0.1, retry_backoff_sec) * attempt
                    print(f"[{now_ts()}] {method} {chunk_id} retry {attempt}/{max_retries_per_chunk}: {exc}")
                    time.sleep(sleep_s)

        if not success:
            err_text = str(last_err) if last_err else "unknown error"
            write_json(
                chunk_out,
                {
                    "method": method,
                    "chunk_id": chunk_id,
                    "parsed_count": 0,
                    "rules": [],
                    "error": err_text,
                    "attempts": attempts_used,
                },
            )
            logs.append(
                {
                    "method": method,
                    "chunk_id": chunk_id,
                    "parsed_count": 0,
                    "error": err_text,
                    "attempts": attempts_used,
                }
            )

    if append_single_chunk and out_path.exists():
        try:
            existing = json.loads(out_path.read_text(encoding="utf-8"))
            existing_rules = existing.get("rules", existing.get("changes", []))
            existing_logs = existing.get("logs", [])
            if isinstance(existing_rules, list):
                parsed_all = existing_rules + parsed_all
            if isinstance(existing_logs, list):
                logs = existing_logs + logs
        except Exception:
            pass

    rules = dedupe_rules(parsed_all)
    changes = [
        {
            "variable_name": rule["f"],
            "change_condition": rule["C"],
            "change_action": rule["A"],
            "old_value": "",
            "new_value": "",
            "related_state_or_step": "",
            "explicit_or_inferred": "explicit",
            "evidence": rule["E"],
            "note": rule.get("note", ""),
            "source_chunk_id": rule.get("source_chunk_id", ""),
            "modality": rule["M"],
            "action_type": rule["action_type"],
        }
        for rule in rules
    ]
    write_json(
        out_path,
        {
            "meta": {
                "method": method,
                "chunk_count": len(chunks),
                "processed_chunk_count": len(selected_chunks),
                "start_chunk": selected_start,
                "model": model,
                "base_url": base_url,
                "record_count": len(rules),
                "generated_at": now_ts(),
                "chunk_output_dir": str(chunk_dir),
                "repair_invalid": repair_invalid,
                "append_mode": append_single_chunk,
            },
            "rules": rules,
            "changes": changes,
            "logs": logs,
        },
    )
    print(f"[{now_ts()}] {method} done: {len(rules)} field rules")
    return rules


def output_for_method(output: str, method: str, all_methods: bool) -> str:
    path = Path(output)
    if not all_methods:
        return str(path)
    if path.suffix.lower() == ".json":
        return str(path.with_name(f"{path.stem}_{method_to_slug(method)}{path.suffix}"))
    path.mkdir(parents=True, exist_ok=True)
    return str(path / f"{method_to_slug(method)}_field_rules.json")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run RQ1 field-rule discovery baselines: 0-shot, 2-shot, and schema-only."
    )
    parser.add_argument("--method", choices=[*METHODS, "all"], required=True)
    parser.add_argument("--chunks", default="output/preprocessed_chunks.json")
    parser.add_argument("--output", default="output/field_rule_discovery_baseline.json")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--base-url", default="https://api.bltcy.ai/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--max-retries-per-chunk", type=int, default=4)
    parser.add_argument("--retry-backoff-sec", type=float, default=2.0)
    parser.add_argument("--start-chunk", type=int, default=1)
    parser.add_argument(
        "--chunk",
        default="",
        help="Run exactly one chunk and merge its result into output; accepts 1-based index or id like chunk_0051.",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--clear-existing", action="store_true")
    parser.add_argument("--chunk-output-dir", default="")
    parser.add_argument(
        "--no-repair-invalid",
        action="store_true",
        help="Disable one repair call when a model response parses but fails validation.",
    )
    args = parser.parse_args()

    methods = list(METHODS) if args.method == "all" else [args.method]
    for method in methods:
        method_chunk_output_dir = args.chunk_output_dir or None
        if method_chunk_output_dir and args.method == "all":
            method_chunk_output_dir = str(Path(method_chunk_output_dir) / method_to_slug(method))
        run_method(
            method=method,
            chunks_path=args.chunks,
            output_path=output_for_method(args.output, method, args.method == "all"),
            api_key=args.api_key,
            base_url=args.base_url,
            model=args.model,
            max_retries_per_chunk=args.max_retries_per_chunk,
            retry_backoff_sec=args.retry_backoff_sec,
            resume=args.resume,
            start_chunk=args.start_chunk,
            clear_existing=args.clear_existing,
            repair_invalid=not args.no_repair_invalid,
            chunk=args.chunk or None,
            chunk_output_dir=method_chunk_output_dir,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
