#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from pipeline_utils import OpenAICompatClient, now_ts, write_text

PROMPT_TEMPLATE = """
You are a standards-document consolidation assistant.

You are given:
1) packet field definitions
2) field-level value/change rules extracted from chunks

Task:
Merge by field name and produce a final summary table.
Only use provided input data. Do not add external assumptions.

Requirements:
1. Merge duplicate rules for the same field across chunks.
2. Keep distinct conditions/actions as separate rows.
3. If evidence is weak or partial, mark it clearly in Note.
4. Preserve original field terms from the source.
5. Distinguish value-change rules from value-judgment rules in Action wording.

Output:
Return a Markdown table with columns:
| No. | Field Name | Alias | Type | Definition/Purpose | Condition | Action | Old Value | New Value | Related Message/Step | Source Chunk | Evidence | Note |

Input:
Definitions:
{variable_definitions}

Change records:
{change_records}
""".strip()


def run_stage3(
    definitions_path: str,
    changes_path: str,
    output_path: str,
    api_key: str,
    base_url: str,
    model: str,
) -> str:
    definitions_obj = json.loads(Path(definitions_path).read_text(encoding="utf-8"))
    changes_obj = json.loads(Path(changes_path).read_text(encoding="utf-8"))
    definitions = definitions_obj.get("definitions", [])
    changes = changes_obj.get("changes", [])

    prompt = (
        PROMPT_TEMPLATE.replace(
            "{variable_definitions}", json.dumps(definitions, ensure_ascii=False, indent=2)
        ).replace("{change_records}", json.dumps(changes, ensure_ascii=False, indent=2))
    )

    client = OpenAICompatClient(api_key=api_key, base_url=base_url, model=model)
    print(f"[{now_ts()}] stage3 start")
    resp = client.chat(prompt)
    write_text(Path(output_path), resp)
    print(f"[{now_ts()}] stage3 done")
    return resp


def main() -> int:
    parser = argparse.ArgumentParser(description="Step3: summarize packet field rules")
    parser.add_argument("--definitions", default="output/01_variable_definitions.json")
    parser.add_argument("--changes", default="output/02_variable_changes.json")
    parser.add_argument("--output", default="output/03_variable_summary.md")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--base-url", default="https://api.zhizengzeng.com/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    args = parser.parse_args()

    run_stage3(
        args.definitions,
        args.changes,
        args.output,
        args.api_key,
        args.base_url,
        args.model,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
