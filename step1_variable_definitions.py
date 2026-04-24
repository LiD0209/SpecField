#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from pipeline_utils import (
    OpenAICompatClient,
    extract_json_array,
    merge_definition_records,
    now_ts,
    write_json,
)

PROMPT_TEMPLATE = """
You are a standards-document extraction assistant.
You can only use the CURRENT chunk and must not assume you have seen the full document.

Task:
Find all concrete protocol packet/message fields that are DEFINED in this chunk.
Focus on wire-format fields used by TLS records, handshake messages, and extensions.

Include:
- fields in `struct` / `enum` / field tables
- explicit field definitions like `field_name: ...`
- packet-carried length/type/value/identifier fields

Exclude:
- abstract security concepts or properties
- implementation advice, state-machine commentary, timers/counters not carried in packets
- anything merely mentioned but not defined in this chunk

Extraction rules:
1. Keep original field names exactly as in the standard.
2. If abbreviation and full name both appear, keep both (`variable_name` + `alias`).
3. Fill type/range when explicitly available.
4. If not explicitly defined in this chunk, skip.

Output format:
Return a JSON array. Each item:
{
  "variable_name": "",
  "alias": [],
  "type": "",
  "definition": "",
  "initial_value_or_range": "",
  "module_or_section": "",
  "evidence": ""
}

Current chunk:
{chunk_text}
""".strip()


def run_stage1(
    chunks_path: str,
    output_path: str,
    api_key: str,
    base_url: str,
    model: str,
    chunk_output_dir: str | None = None,
) -> list[dict]:
    chunks = json.loads(Path(chunks_path).read_text(encoding="utf-8"))
    client = OpenAICompatClient(api_key=api_key, base_url=base_url, model=model)
    out_path = Path(output_path)
    chunk_dir = Path(chunk_output_dir) if chunk_output_dir else out_path.parent / "stage1_chunks"
    if chunk_dir.exists():
        shutil.rmtree(chunk_dir)
    chunk_dir.mkdir(parents=True, exist_ok=True)

    parsed_all = []
    logs = []
    total = len(chunks)
    for i, chunk in enumerate(chunks, start=1):
        chunk_id = chunk["chunk_id"]
        prompt = PROMPT_TEMPLATE.replace("{chunk_text}", chunk["chunk_text"])
        print(f"[{now_ts()}] stage1 {chunk_id} ({i}/{total})")
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

    merged = merge_definition_records(parsed_all)
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
            "definitions": merged,
            "logs": logs,
        },
    )
    print(f"[{now_ts()}] stage1 done: {len(merged)} packet fields")
    return merged


def main() -> int:
    parser = argparse.ArgumentParser(description="Step1: extract packet field definitions")
    parser.add_argument("--chunks", default="output/preprocessed_chunks.json")
    parser.add_argument("--output", default="output/01_variable_definitions.json")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--base-url", default="https://api.zhizengzeng.com/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--chunk-output-dir", default="")
    args = parser.parse_args()

    run_stage1(
        args.chunks,
        args.output,
        args.api_key,
        args.base_url,
        args.model,
        args.chunk_output_dir or None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
