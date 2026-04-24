#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
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

Known packet field catalog:
{variable_catalog}

Task:
From the current chunk, extract only value-change and value-judgment rules for the fields in the catalog above.
Focus on protocol-message-level behavior for packet fields.

What counts:
- value change: set/overwrite/select/derive/copy/clear/increment/decrement
- value judgment: equality/inequality checks, range bounds, membership checks, validity checks, MUST/MUST NOT constraints
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


def run_stage2(
    chunks_path: str,
    definitions_path: str,
    output_path: str,
    api_key: str,
    base_url: str,
    model: str,
    chunk_output_dir: str | None = None,
) -> list[dict]:
    chunks = json.loads(Path(chunks_path).read_text(encoding="utf-8"))
    definitions_obj = json.loads(Path(definitions_path).read_text(encoding="utf-8"))
    definitions = definitions_obj.get("definitions", [])
    out_path = Path(output_path)
    chunk_dir = Path(chunk_output_dir) if chunk_output_dir else out_path.parent / "stage2_chunks"
    if chunk_dir.exists():
        shutil.rmtree(chunk_dir)
    chunk_dir.mkdir(parents=True, exist_ok=True)

    variable_catalog = build_variable_catalog(definitions)
    client = OpenAICompatClient(api_key=api_key, base_url=base_url, model=model)

    parsed_all = []
    logs = []
    total = len(chunks)
    for i, chunk in enumerate(chunks, start=1):
        chunk_id = chunk["chunk_id"]
        prompt = (
            PROMPT_TEMPLATE.replace("{variable_catalog}", variable_catalog).replace(
                "{chunk_text}", chunk["chunk_text"]
            )
        )
        print(f"[{now_ts()}] stage2 {chunk_id} ({i}/{total})")
        try:
            resp = client.chat(prompt)
            parsed = extract_json_array(resp)
            for item in parsed:
                item["source_chunk_id"] = chunk_id
            parsed_all.extend(parsed)
            write_json(
                chunk_dir / f"{chunk_id}.json",
                {
                    "chunk_id": chunk_id,
                    "parsed_count": len(parsed),
                    "parsed": parsed,
                    "raw_response": resp,
                },
            )
            logs.append(
                {
                    "chunk_id": chunk_id,
                    "parsed_count": len(parsed),
                    "raw_response": resp,
                }
            )
        except Exception as e:  # noqa: BLE001
            write_json(
                chunk_dir / f"{chunk_id}.json",
                {
                    "chunk_id": chunk_id,
                    "parsed_count": 0,
                    "parsed": [],
                    "error": str(e),
                },
            )
            logs.append({"chunk_id": chunk_id, "parsed_count": 0, "error": str(e)})

    merged = merge_change_records(parsed_all)
    merged = filter_change_records_to_catalog(merged, definitions)
    write_json(
        out_path,
        {
            "meta": {
                "chunk_count": len(chunks),
                "model": model,
                "base_url": base_url,
                "record_count": len(merged),
                "generated_at": now_ts(),
                "chunk_output_dir": str(chunk_dir),
            },
            "changes": merged,
            "logs": logs,
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
    parser.add_argument("--base-url", default="https://api.zhizengzeng.com/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--chunk-output-dir", default="")
    args = parser.parse_args()

    run_stage2(
        args.chunks,
        args.definitions,
        args.output,
        args.api_key,
        args.base_url,
        args.model,
        args.chunk_output_dir or None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
