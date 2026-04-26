#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path

from pipeline_utils import (
    OpenAICompatClient,
    build_variable_catalog,
    extract_json_array,
    filter_change_records_to_catalog,
    merge_change_records,
    now_ts,
    write_json,
)

PROMPT_TEMPLATE = """
You are a standards-document extraction assistant.
You can only use the CURRENT chunk and must not assume global context.

Target domain hint:
{domain_hint}

Known packet field catalog:
{variable_catalog}

Task:
From the current chunk, extract only value-change and value-judgment rules for the fields in the catalog above.
Focus on protocol-message-level behavior for packet fields.

What counts:
- value change: set/overwrite/select/derive/copy/clear/increment/decrement
- value judgment: equality/inequality checks, lower and upper bound checks, range bounds, membership checks, validity checks, MUST/MUST NOT constraints
- explicit invalid/abort conditions tied to field values

Examples of valid `change_action`:
- set to constant
- selected from offered list
- must be present / must be absent
- must equal / must not equal
- validated range check
- derived/computed from another field
- invalid if value check fails

Rules:
1. Do not introduce new field names outside the catalog.
2. Ignore abstract runtime state changes unrelated to packet fields.
3. If a catalog field is mentioned but no clear rule is given, skip.
4. If a rule is partial, keep it and set `note` to "incomplete information".
5. Use evidence text directly from the chunk.
6. If the chunk contains comparison logic (`==`, `!=`, `<`, `>`, `within`, `in range`, `MUST`, `MUST NOT`), capture it as value judgment.

Output format:
Return a JSON array. Each item:
{
  "variable_name": "",
  "change_condition": "",
  "change_action": "",
  "old_value": "",
  "new_value": "",
  "related_state_or_step": "",
  "explicit_or_inferred": "explicit",
  "evidence": "",
  "note": ""
}

Current chunk:
{chunk_text}
""".strip()


def resolve_chunk_selector(chunks: list[dict], chunk_selector: str) -> tuple[int, dict]:
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

    if chunk_index < 1:
        raise ValueError("--chunk index must be >= 1")
    if chunk_index > len(chunks):
        raise ValueError(f"--chunk {chunk_index} out of range, total chunks={len(chunks)}")
    return chunk_index, chunks[chunk_index - 1]


def load_existing_stage2_output(output_path: Path) -> tuple[dict, list[dict], list[dict]]:
    if not output_path.exists():
        return {}, [], []

    try:
        obj = json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Existing output is not valid JSON: {output_path}") from exc

    if not isinstance(obj, dict):
        raise ValueError(f"Existing output must be a JSON object: {output_path}")

    meta = obj.get("meta", {})
    changes = obj.get("changes", [])
    logs = obj.get("logs", [])
    return (
        meta if isinstance(meta, dict) else {},
        changes if isinstance(changes, list) else [],
        logs if isinstance(logs, list) else [],
    )


def run_stage2(
    chunks_path: str,
    definitions_path: str,
    output_path: str,
    api_key: str,
    base_url: str,
    model: str,
    domain_hint: str,
    max_retries_per_chunk: int,
    retry_backoff_sec: float,
    resume: bool,
    start_chunk: int,
    clear_existing: bool,
    chunk: str | None = None,
    chunk_output_dir: str | None = None,
) -> list[dict]:
    chunks = json.loads(Path(chunks_path).read_text(encoding="utf-8"))
    definitions_obj = json.loads(Path(definitions_path).read_text(encoding="utf-8"))
    definitions = definitions_obj.get("definitions", [])
    if start_chunk < 1:
        raise ValueError("--start-chunk must be >= 1")
    if start_chunk > len(chunks):
        raise ValueError(f"--start-chunk {start_chunk} out of range, total chunks={len(chunks)}")
    out_path = Path(output_path)
    chunk_dir = Path(chunk_output_dir) if chunk_output_dir else out_path.parent / "stage2_chunks"
    if clear_existing and resume:
        raise ValueError("--clear-existing cannot be used together with --resume")
    if chunk_dir.exists() and clear_existing:
        shutil.rmtree(chunk_dir)
    chunk_dir.mkdir(parents=True, exist_ok=True)

    variable_catalog = build_variable_catalog(definitions)
    client = OpenAICompatClient(api_key=api_key, base_url=base_url, model=model)
    append_single_chunk = chunk is not None

    parsed_all = []
    logs = []
    total = len(chunks)
    # When resuming from a later chunk, preload earlier successful chunk outputs
    # so final merged output still includes them.
    if resume and start_chunk > 1 and not append_single_chunk:
        for chunk in chunks[: start_chunk - 1]:
            chunk_id = chunk["chunk_id"]
            chunk_out = chunk_dir / f"{chunk_id}.json"
            if not chunk_out.exists():
                continue
            try:
                old = json.loads(chunk_out.read_text(encoding="utf-8"))
                parsed_old = old.get("parsed", [])
                parsed_count_old = int(old.get("parsed_count", 0) or 0)
                if parsed_count_old > 0 and isinstance(parsed_old, list):
                    for item in parsed_old:
                        if isinstance(item, dict):
                            item["source_chunk_id"] = chunk_id
                            parsed_all.append(item)
                    logs.append(
                        {
                            "chunk_id": chunk_id,
                            "parsed_count": parsed_count_old,
                            "raw_response": old.get("raw_response", ""),
                            "resumed_preload": True,
                        }
                    )
            except Exception:
                continue

    if append_single_chunk:
        selected_start, selected_chunk = resolve_chunk_selector(chunks, chunk)
        selected_chunks = [selected_chunk]
    else:
        selected_start = start_chunk
        selected_chunks = chunks[start_chunk - 1 :]

    for i, chunk_item in enumerate(selected_chunks, start=selected_start):
        chunk_id = chunk_item["chunk_id"]
        chunk_out = chunk_dir / f"{chunk_id}.json"
        prompt = (
            PROMPT_TEMPLATE.replace("{domain_hint}", domain_hint)
            .replace("{variable_catalog}", variable_catalog)
            .replace("{chunk_text}", chunk_item["chunk_text"])
        )
        if resume and chunk_out.exists():
            try:
                old = json.loads(chunk_out.read_text(encoding="utf-8"))
                parsed_old = old.get("parsed", [])
                parsed_count_old = int(old.get("parsed_count", 0) or 0)
                if parsed_count_old > 0 and isinstance(parsed_old, list):
                    for item in parsed_old:
                        if isinstance(item, dict):
                            item["source_chunk_id"] = chunk_id
                            parsed_all.append(item)
                    logs.append(
                        {
                            "chunk_id": chunk_id,
                            "parsed_count": parsed_count_old,
                            "raw_response": old.get("raw_response", ""),
                            "resumed": True,
                        }
                    )
                    print(f"[{now_ts()}] stage2 {chunk_id} ({i}/{total}) resume-hit")
                    continue
            except Exception:
                # Corrupted resume file: rerun this chunk.
                pass

        print(f"[{now_ts()}] stage2 {chunk_id} ({i}/{total})")
        last_err: Exception | None = None
        success = False
        for attempt in range(1, max(1, max_retries_per_chunk) + 1):
            try:
                resp = client.chat(prompt)
                parsed = extract_json_array(resp)
                for item in parsed:
                    item["source_chunk_id"] = chunk_id
                parsed_all.extend(parsed)
                write_json(
                    chunk_out,
                    {
                        "chunk_id": chunk_id,
                        "parsed_count": len(parsed),
                        "parsed": parsed,
                        "raw_response": resp,
                        "attempts": attempt,
                    },
                )
                logs.append(
                    {
                        "chunk_id": chunk_id,
                        "parsed_count": len(parsed),
                        "raw_response": resp,
                        "attempts": attempt,
                    }
                )
                success = True
                break
            except Exception as e:  # noqa: BLE001
                last_err = e
                if attempt < max(1, max_retries_per_chunk):
                    sleep_s = max(0.1, retry_backoff_sec) * attempt
                    print(
                        f"[{now_ts()}] stage2 {chunk_id} retry {attempt}/{max_retries_per_chunk}: {e}"
                    )
                    time.sleep(sleep_s)

        if not success:
            err_text = str(last_err) if last_err else "unknown error"
            write_json(
                chunk_out,
                {
                    "chunk_id": chunk_id,
                    "parsed_count": 0,
                    "parsed": [],
                    "error": err_text,
                    "attempts": max(1, max_retries_per_chunk),
                },
            )
            logs.append(
                {
                    "chunk_id": chunk_id,
                    "parsed_count": 0,
                    "error": err_text,
                    "attempts": max(1, max_retries_per_chunk),
                }
            )

    output_logs = logs
    if append_single_chunk:
        existing_meta, existing_changes, existing_logs = load_existing_stage2_output(out_path)
        parsed_all = existing_changes + parsed_all
        output_logs = existing_logs + logs

    merged = merge_change_records(parsed_all)
    merged = filter_change_records_to_catalog(merged, definitions)
    if append_single_chunk:
        meta = {
            **existing_meta,
            "chunk_count": len(chunks),
            "model": model,
            "base_url": base_url,
            "record_count": len(merged),
            "generated_at": now_ts(),
            "chunk_output_dir": str(chunk_dir),
            "domain_hint": domain_hint,
            "append_mode": True,
            "last_appended_chunk": selected_chunks[0]["chunk_id"],
            "last_appended_chunk_index": selected_start,
        }
    else:
        meta = {
            "chunk_count": len(chunks),
            "start_chunk": start_chunk,
            "processed_chunk_count": len(selected_chunks),
            "model": model,
            "base_url": base_url,
            "record_count": len(merged),
            "generated_at": now_ts(),
            "chunk_output_dir": str(chunk_dir),
            "domain_hint": domain_hint,
            "clear_existing": clear_existing,
        }
    write_json(
        out_path,
        {
            "meta": meta,
            "changes": merged,
            "logs": output_logs,
        },
    )
    print(f"[{now_ts()}] stage2 done: {len(merged)} field rules")
    return merged


def main() -> int:
    parser = argparse.ArgumentParser(description="Step2: extract packet field value rules")
    parser.add_argument("--chunks", default="output/preprocessed_chunks.json")
    parser.add_argument("--definitions", default="output/01_variable_definitions.json")
    parser.add_argument("--output", default="output/02_variable_changes.json")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--base-url", default="https://api.bltcy.ai/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument(
        "--domain-hint",
        default="Generic protocol change rules for structured messages/packets (protocol-agnostic)",
    )
    parser.add_argument("--max-retries-per-chunk", type=int, default=4)
    parser.add_argument("--retry-backoff-sec", type=float, default=2.0)
    parser.add_argument("--start-chunk", type=int, default=1, help="1-based chunk index")
    parser.add_argument(
        "--chunk",
        default="",
        help=(
            "Run exactly one chunk and merge its results into the existing output "
            "(accepts 1-based index like 51 or id like chunk_0051)"
        ),
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--clear-existing",
        action="store_true",
        help="Delete existing chunk output directory before running",
    )
    parser.add_argument("--chunk-output-dir", default="")
    args = parser.parse_args()

    run_stage2(
        args.chunks,
        args.definitions,
        args.output,
        args.api_key,
        args.base_url,
        args.model,
        args.domain_hint,
        args.max_retries_per_chunk,
        args.retry_backoff_sec,
        args.resume,
        args.start_chunk,
        args.clear_existing,
        args.chunk or None,
        args.chunk_output_dir or None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
