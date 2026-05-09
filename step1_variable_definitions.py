#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import time
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

Target domain hint:
{domain_hint}

Task:
Find all concrete serialized/message/variable/schema fields that are DEFINED in this chunk.
Focus on fields carried in packets/messages/frames/headers/options/extensions or equivalent structured payloads.

Include:
- fields in `struct` / `enum` / field tables
- explicit field definitions like `field_name: ...`
- serialized length/type/value/identifier fields

Exclude:
- abstract concepts or properties with no concrete field definition
- implementation advice, state-machine commentary, timers/counters not carried in serialized payloads
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
    domain_hint: str,
    max_retries_per_chunk: int,
    retry_backoff_sec: float,
    resume: bool,
    chunk_output_dir: str | None = None,
) -> list[dict]:
    chunks = json.loads(Path(chunks_path).read_text(encoding="utf-8"))
    client = OpenAICompatClient(api_key=api_key, base_url=base_url, model=model)
    out_path = Path(output_path)
    chunk_dir = Path(chunk_output_dir) if chunk_output_dir else out_path.parent / "stage1_chunks"
    if chunk_dir.exists() and not resume:
        shutil.rmtree(chunk_dir)
    chunk_dir.mkdir(parents=True, exist_ok=True)

    parsed_all = []
    logs = []
    total = len(chunks)
    for i, chunk in enumerate(chunks, start=1):
        chunk_id = chunk["chunk_id"]
        chunk_out = chunk_dir / f"{chunk_id}.json"
        prompt = (
            PROMPT_TEMPLATE.replace("{domain_hint}", domain_hint).replace(
                "{chunk_text}", chunk["chunk_text"]
            )
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
                    print(f"[{now_ts()}] stage1 {chunk_id} ({i}/{total}) resume-hit")
                    continue
            except Exception:
                # If resume file is corrupted, just rerun this chunk.
                pass

        print(f"[{now_ts()}] stage1 {chunk_id} ({i}/{total})")
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
                        f"[{now_ts()}] stage1 {chunk_id} retry {attempt}/{max_retries_per_chunk}: {e}"
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
                "domain_hint": domain_hint,
            },
            "definitions": merged,
            "logs": logs,
        },
    )
    print(f"[{now_ts()}] stage1 done: {len(merged)} fields")
    return merged


def main() -> int:
    parser = argparse.ArgumentParser(description="Step1: extract packet field definitions")
    parser.add_argument("--chunks", default="output/preprocessed_chunks.json")
    parser.add_argument("--output", default="output/01_variable_definitions.json")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--base-url", default="https://api.bltcy.ai/v1")
    parser.add_argument("--model", default="gpt-5.5")
    parser.add_argument(
        "--domain-hint",
        default="Generic specification for structured messages/packets (protocol-agnostic)",
    )
    parser.add_argument("--max-retries-per-chunk", type=int, default=4)
    parser.add_argument("--retry-backoff-sec", type=float, default=2.0)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--chunk-output-dir", default="")
    args = parser.parse_args()

    run_stage1(
        args.chunks,
        args.output,
        args.api_key,
        args.base_url,
        args.model,
        args.domain_hint,
        args.max_retries_per_chunk,
        args.retry_backoff_sec,
        args.resume,
        args.chunk_output_dir or None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
