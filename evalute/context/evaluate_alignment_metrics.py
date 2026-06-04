#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import re
from pathlib import Path
from typing import Any


def read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def norm_name(value: Any) -> str:
    text = normalize_text(value).lower()
    text = re.sub(r"[^a-z0-9_]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text


def norm_path(value: Any) -> str:
    text = normalize_text(value).replace("\\", "/").lower()
    text = re.sub(r"/+", "/", text).strip()
    return text


def path_matches(pred: str, gold: str) -> bool:
    p = norm_path(pred)
    g = norm_path(gold)
    if not p or not g:
        return False
    return p == g or p.endswith("/" + g) or g.endswith("/" + p) or Path(p).name == Path(g).name


def line_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    if a_start <= 0 or a_end <= 0 or b_start <= 0 or b_end <= 0:
        return True
    return max(a_start, b_start) <= min(a_end, b_end)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        parts = [p.strip() for p in re.split(r"[;,]", value) if p.strip()]
        return parts or [value]
    return [value]


def load_alignments(path: str) -> list[dict[str, Any]]:
    obj = read_json(path)
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if not isinstance(obj, dict):
        raise ValueError(f"alignment output must be JSON object/list: {path}")
    alignments = obj.get("alignments", [])
    if not isinstance(alignments, list):
        raise ValueError(f"`alignments` must be a list: {path}")
    return [x for x in alignments if isinstance(x, dict)]


def _gold_from_row(row: dict[str, Any], fallback_index: int) -> dict[str, Any]:
    variables = (
        row.get("gold_variables")
        or row.get("variables")
        or row.get("variable_names")
        or row.get("gold_variable")
        or row.get("variable")
    )
    contexts = row.get("gold_contexts") or row.get("contexts") or row.get("context")
    if contexts is None and (row.get("file") or row.get("gold_file")):
        contexts = [
            {
                "file": row.get("gold_file") or row.get("file"),
                "symbol": row.get("gold_symbol") or row.get("symbol", ""),
                "start_line": row.get("gold_start_line") or row.get("start_line", 0),
                "end_line": row.get("gold_end_line") or row.get("end_line", 0),
            }
        ]
    return {
        "input_index": int(row.get("input_index") or row.get("index") or fallback_index),
        "rule_id": normalize_text(row.get("rule_id") or row.get("id")),
        "gold_variables": [normalize_text(v) for v in as_list(variables) if normalize_text(v)],
        "gold_contexts": normalize_contexts(contexts),
    }


def normalize_contexts(value: Any) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    if value is None:
        return contexts
    if isinstance(value, str):
        value = [v.strip() for v in value.split(";") if v.strip()]
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return contexts
    for item in value:
        if isinstance(item, str):
            contexts.append({"file": item, "symbol": "", "start_line": 0, "end_line": 0})
            continue
        if not isinstance(item, dict):
            continue
        start = int(item.get("start_line") or item.get("line_start") or item.get("start") or item.get("line") or 0)
        end = int(item.get("end_line") or item.get("line_end") or item.get("end") or item.get("line") or 0)
        if start and not end:
            end = start
        if end and not start:
            start = end
        contexts.append(
            {
                "file": normalize_text(item.get("file") or item.get("path") or item.get("gold_file")),
                "symbol": normalize_text(item.get("symbol") or item.get("function") or item.get("gold_symbol")),
                "start_line": start,
                "end_line": end,
            }
        )
    return contexts


def load_gold(path: str) -> dict[int, dict[str, Any]]:
    p = Path(path)
    if p.suffix.lower() == ".csv":
        rows: list[dict[str, Any]] = []
        with p.open("r", encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                rows.append(dict(row))
    else:
        obj = read_json(path)
        if isinstance(obj, dict):
            rows = obj.get("items") or obj.get("gold") or obj.get("annotations") or obj.get("alignments") or []
        elif isinstance(obj, list):
            rows = obj
        else:
            rows = []
        if not isinstance(rows, list):
            raise ValueError(f"gold file must contain a list: {path}")
    gold: dict[int, dict[str, Any]] = {}
    for idx, row in enumerate(rows, start=1):
        if isinstance(row, dict):
            g = _gold_from_row(row, idx)
            gold[g["input_index"]] = g
    return gold


def predicted_variables(alignment: dict[str, Any]) -> list[str]:
    result = alignment.get("result", {})
    items = result.get("ranked_variables", []) if isinstance(result, dict) else []
    out: list[str] = []
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                name = normalize_text(item.get("name") or item.get("variable") or item.get("variable_name"))
            else:
                name = normalize_text(item)
            if name:
                out.append(name)
    return out


def predicted_contexts(alignment: dict[str, Any]) -> list[dict[str, Any]]:
    result = alignment.get("result", {})
    items = result.get("contexts", []) if isinstance(result, dict) else []
    return normalize_contexts(items)


def variable_hit_at(preds: list[str], gold_vars: list[str], k: int) -> bool:
    gold_norm = {norm_name(v) for v in gold_vars if norm_name(v)}
    if not gold_norm:
        return False
    for pred in preds[:k]:
        pn = norm_name(pred)
        if pn in gold_norm:
            return True
    return False


def reciprocal_rank(preds: list[str], gold_vars: list[str]) -> float:
    gold_norm = {norm_name(v) for v in gold_vars if norm_name(v)}
    if not gold_norm:
        return 0.0
    for rank, pred in enumerate(preds, start=1):
        if norm_name(pred) in gold_norm:
            return 1.0 / rank
    return 0.0


def context_matches(pred: dict[str, Any], gold: dict[str, Any]) -> bool:
    pred_file = normalize_text(pred.get("file"))
    gold_file = normalize_text(gold.get("file"))
    if gold_file and not path_matches(pred_file, gold_file):
        return False

    gold_symbol = norm_name(gold.get("symbol"))
    pred_symbol = norm_name(pred.get("symbol"))
    if gold_symbol and pred_symbol and gold_symbol != pred_symbol:
        return False

    return line_overlap(
        int(pred.get("start_line") or 0),
        int(pred.get("end_line") or 0),
        int(gold.get("start_line") or 0),
        int(gold.get("end_line") or 0),
    )


def context_hit_at(preds: list[dict[str, Any]], gold_contexts: list[dict[str, Any]], k: int) -> bool:
    if not gold_contexts:
        return False
    for pred in preds[:k]:
        for gold in gold_contexts:
            if context_matches(pred, gold):
                return True
    return False


def estimate_tokens_for_alignment(alignment: dict[str, Any]) -> int:
    total_chars = 0
    for cand in alignment.get("candidate_snippets", []) or []:
        if isinstance(cand, dict):
            total_chars += len(normalize_text(cand.get("snippet")))
            total_chars += len(normalize_text(cand.get("reason")))
    raw = normalize_text(alignment.get("raw_model_output"))
    total_chars += len(raw)
    return int(math.ceil(total_chars / 4.0))


def evaluate(alignments: list[dict[str, Any]], gold: dict[int, dict[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for idx, alignment in enumerate(alignments, start=1):
        input_index = int(alignment.get("input_index") or idx)
        g = gold.get(input_index)
        if not g:
            continue
        preds_v = predicted_variables(alignment)
        preds_c = predicted_contexts(alignment)
        gold_vars = g.get("gold_variables", [])
        gold_contexts = g.get("gold_contexts", [])
        row = {
            "input_index": input_index,
            "var_at_1": variable_hit_at(preds_v, gold_vars, 1),
            "var_at_3": variable_hit_at(preds_v, gold_vars, 3),
            "ctx_at_1": context_hit_at(preds_c, gold_contexts, 1),
            "ctx_at_3": context_hit_at(preds_c, gold_contexts, 3),
            "rr": reciprocal_rank(preds_v, gold_vars),
            "tok": estimate_tokens_for_alignment(alignment),
            "predicted_variables": preds_v[:5],
            "gold_variables": gold_vars,
            "predicted_contexts": preds_c[:3],
            "gold_contexts": gold_contexts,
        }
        rows.append(row)

    n = len(rows)
    if n == 0:
        summary = {
            "count": 0,
            "Var@1": 0.0,
            "Var@3": 0.0,
            "Ctx@1": 0.0,
            "Ctx@3": 0.0,
            "MRR": 0.0,
            "Tok.": 0.0,
        }
    else:
        summary = {
            "count": n,
            "Var@1": round(sum(1 for r in rows if r["var_at_1"]) / n, 4),
            "Var@3": round(sum(1 for r in rows if r["var_at_3"]) / n, 4),
            "Ctx@1": round(sum(1 for r in rows if r["ctx_at_1"]) / n, 4),
            "Ctx@3": round(sum(1 for r in rows if r["ctx_at_3"]) / n, 4),
            "MRR": round(sum(float(r["rr"]) for r in rows) / n, 4),
            "Tok.": round(sum(int(r["tok"]) for r in rows) / n / 1000.0, 3),
        }
    return {"summary": summary, "rows": rows}


def markdown_table(results: list[tuple[str, dict[str, Any]]]) -> str:
    lines = [
        "| Method | Var@1 | Var@3 | Ctx@1 | Ctx@3 | MRR | Tok. | Count |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for method, result in results:
        s = result["summary"]
        lines.append(
            "| {method} | {var1:.2f} | {var3:.2f} | {ctx1:.2f} | {ctx3:.2f} | {mrr:.2f} | {tok:.1f}K | {count} |".format(
                method=method,
                var1=float(s["Var@1"]),
                var3=float(s["Var@3"]),
                ctx1=float(s["Ctx@1"]),
                ctx3=float(s["Ctx@3"]),
                mrr=float(s["MRR"]),
                tok=float(s["Tok."]),
                count=int(s["count"]),
            )
        )
    return "\n".join(lines) + "\n"


def method_name_from_output(path: str, alignments: list[dict[str, Any]]) -> str:
    try:
        obj = read_json(path)
        if isinstance(obj, dict):
            method = normalize_text((obj.get("meta") or {}).get("method"))
            if method:
                return method
    except Exception:
        pass
    if alignments:
        method = normalize_text(alignments[0].get("method"))
        if method:
            return method
    return Path(path).stem


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate Var@1, Var@3, Ctx@1, Ctx@3, MRR, and Tok. for rule-to-code alignment outputs."
    )
    parser.add_argument("--alignment", action="append", required=True, help="Baseline output JSON. Repeat for multiple methods.")
    parser.add_argument("--gold", required=True, help="Gold annotation JSON/CSV.")
    parser.add_argument("--output-json", default="output/alignment_metrics.json")
    parser.add_argument("--output-md", default="output/alignment_metrics.md")
    args = parser.parse_args()

    gold = load_gold(args.gold)
    results: list[tuple[str, dict[str, Any]]] = []
    for path in args.alignment:
        alignments = load_alignments(path)
        method = method_name_from_output(path, alignments)
        results.append((method, evaluate(alignments, gold)))

    write_json(
        Path(args.output_json),
        {
            "meta": {
                "gold": args.gold,
                "alignment_files": args.alignment,
            },
            "results": [{"method": method, **result} for method, result in results],
        },
    )
    write_text(Path(args.output_md), markdown_table(results))
    print(markdown_table(results), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
