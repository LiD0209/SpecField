#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import extract_tls_change_contexts as core


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_changes(changes_file: str, changes_key: str) -> list[dict[str, Any]]:
    obj = json.loads(Path(changes_file).read_text(encoding="utf-8"))
    if isinstance(obj, dict):
        arr = obj.get(changes_key, [])
        if not isinstance(arr, list):
            raise ValueError(f"{changes_file} key `{changes_key}` is not a list")
    elif isinstance(obj, list):
        arr = obj
    else:
        raise ValueError(f"unsupported JSON type: {type(obj).__name__}")

    out: list[dict[str, Any]] = []
    for item in arr:
        if isinstance(item, dict):
            out.append(item)
        else:
            out.append({"_raw": item})
    return out


def pick_context_name(
    context_id: str,
    ctx_to_names: dict[str, list[str]],
) -> str:
    names = [n for n in ctx_to_names.get(context_id, []) if n]
    if not names:
        return "unknown"
    c = Counter(names)
    return sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def compact_output(
    extracted: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    items = extracted.get("results", [])
    raw_store = extracted.get("context_store", {})

    ctx_to_names: dict[str, list[str]] = defaultdict(list)
    compact_items: list[dict[str, Any]] = []

    for item in items:
        change = item.get("change", {}) if isinstance(item, dict) else {}
        context_id = str(item.get("context_id", "")).strip()
        variable_name = str(change.get("variable_name", "")).strip()
        if context_id and variable_name:
            ctx_to_names[context_id].append(variable_name)

        compact_items.append(
            {
                "index": item.get("index", 0),
                "variable_name": variable_name,
                "context_id": context_id,
            }
        )

    compact_store: dict[str, Any] = {}
    for context_id, raw in raw_store.items():
        windows = raw.get("windows", []) if isinstance(raw, dict) else []
        start_line: list[int] = []
        end_line: list[int] = []
        if isinstance(windows, list) and windows:
            valid_windows = [w for w in windows if isinstance(w, dict)]
            valid_windows.sort(key=lambda w: int(w.get("start_line", 10**9)))
            for w in valid_windows:
                s = w.get("start_line")
                e = w.get("end_line")
                if isinstance(s, int):
                    start_line.append(s)
                if isinstance(e, int):
                    end_line.append(e)

        compact_store[context_id] = {
            "context_name": pick_context_name(context_id, ctx_to_names),
            "text": str(raw.get("text", "")).strip() if isinstance(raw, dict) else "",
            "start_line": start_line,
            "end_line": end_line,
        }

    return compact_store, compact_items


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compact TLS context extraction output (context_store only keeps essential fields)."
    )
    parser.add_argument(
        "--changes-file",
        default="output/02_variable_changes.json",
    )
    parser.add_argument("--changes-key", default="changes")
    parser.add_argument(
        "--doc-file",
        default="document/TLS1.3.txt",
    )
    parser.add_argument(
        "--output",
        default="output/06_change_contexts2.json",
    )
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--max-items", type=int, default=0, help="0 means all")
    parser.add_argument("--radius", type=int, default=1)
    parser.add_argument("--max-windows", type=int, default=4)
    parser.add_argument("--max-paragraphs-per-window", type=int, default=8)
    parser.add_argument("--min-score", type=float, default=1.0)

    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--base-url", default="https://api.zhizengzeng.com/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--llm-max-items", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        print(f"[{now_ts()}] loading document")
        cleaned_lines, _removed = core.read_and_clean_document(args.doc_file)
        paragraphs = core.build_paragraphs(cleaned_lines)
        if not paragraphs:
            raise ValueError("no paragraphs parsed from document")

        print(f"[{now_ts()}] loading changes")
        all_changes = load_changes(args.changes_file, args.changes_key)
        start = max(0, args.start_index)
        end = len(all_changes) if args.max_items <= 0 else min(len(all_changes), start + args.max_items)
        if start >= len(all_changes):
            raise ValueError(f"start-index {start} out of range, total={len(all_changes)}")
        changes = all_changes[start:end]

        if args.use_llm and not args.api_key:
            raise ValueError("missing API key for --use-llm")

        if args.dry_run:
            print(f"paragraphs={len(paragraphs)}, changes_total={len(all_changes)}, run_range=[{start}, {end})")
            return 0

        print(f"[{now_ts()}] extracting contexts for {len(changes)} changes")
        extracted = core.extract_change_contexts(
            changes=changes,
            paragraphs=paragraphs,
            max_windows=max(1, args.max_windows),
            radius=max(0, args.radius),
            min_score=max(0.0, args.min_score),
            max_paragraphs_per_window=max(1, args.max_paragraphs_per_window),
            use_llm=args.use_llm,
            api_key=args.api_key,
            base_url=args.base_url,
            model=args.model,
            temperature=args.temperature,
            timeout_sec=args.timeout_sec,
            llm_max_items=max(0, args.llm_max_items),
        )

        compact_store, compact_items = compact_output(extracted)

        out = {
            "meta": {
                "generated_at": now_ts(),
                "doc_file": str(Path(args.doc_file).resolve(strict=False)),
                "changes_file": str(Path(args.changes_file).resolve(strict=False)),
                "changes_key": args.changes_key,
                "changes_total": len(all_changes),
                "start_index": start,
                "end_index_exclusive": end,
                "processed_count": len(changes),
                "paragraph_count": len(paragraphs),
                "radius": args.radius,
                "max_windows": args.max_windows,
                "max_paragraphs_per_window": args.max_paragraphs_per_window,
                "min_score": args.min_score,
                "use_llm": args.use_llm,
                "model": args.model if args.use_llm else "",
            },
            "context_store": compact_store,
            "items": compact_items,
        }

        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[{now_ts()}] done -> {out_path}")
        print(f"context_count={len(compact_store)}, item_count={len(compact_items)}")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
