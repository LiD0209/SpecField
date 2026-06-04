#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline_utils import now_ts, write_json, write_text  # noqa: E402


DEFAULT_PRICING = {
    "input_per_1m": 1.25,
    "output_per_1m": 10.0,
}


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def load_judgments(path: str | Path) -> list[dict[str, Any]]:
    obj = read_json(path)
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if not isinstance(obj, dict):
        return []
    if isinstance(obj.get("judgments"), list):
        return [x for x in obj["judgments"] if isinstance(x, dict)]
    if isinstance(obj.get("results"), list):
        return [x for x in obj["results"] if isinstance(x, dict)]
    if isinstance(obj.get("alignments"), list):
        return [x for x in obj["alignments"] if isinstance(x, dict)]
    return []


def report_key(item: dict[str, Any]) -> str:
    rule = item.get("rule", {}) if isinstance(item.get("rule"), dict) else {}
    final = (item.get("reasoning") or [{}])[-1] if isinstance(item.get("reasoning"), list) else {}
    parts = [
        normalize_text(rule.get("rule_id") or item.get("rule_id") or item.get("id")),
        normalize_text(rule.get("f") or rule.get("field") or item.get("field")),
        normalize_text(rule.get("C") or rule.get("condition")),
        normalize_text(rule.get("A") or rule.get("action")),
        normalize_text(final.get("R") or item.get("reason")),
    ]
    key = "|".join(p.lower() for p in parts if p)
    return key or json.dumps(item, sort_keys=True, ensure_ascii=False)[:300]


def final_label(item: dict[str, Any]) -> str:
    if isinstance(item.get("reasoning"), list) and item["reasoning"]:
        return normalize_text(item["reasoning"][-1].get("y")).upper()
    return normalize_text(item.get("status") or item.get("result") or item.get("y")).upper()


def maintainer_status(item: dict[str, Any]) -> str:
    raw = normalize_text(
        item.get("maintainer_status")
        or item.get("adjudication")
        or item.get("status")
        or item.get("outcome")
        or item.get("label")
    ).lower()
    if raw in {"confirmed", "fixed", "confirm", "conf", "valid", "true_positive"}:
        return "confirmed"
    if raw in {"false_positive", "fp", "rejected", "not_a_bug", "invalid"}:
        return "false_positive"
    if raw in {"pending", "unknown", "open", ""}:
        return "pending"
    if final_label(item) == "INCONSISTENT":
        return "pending"
    return "not_submitted"


def infer_protocol_subject(path: str | Path, item: dict[str, Any]) -> tuple[str, str]:
    meta = item.get("meta", {}) if isinstance(item.get("meta"), dict) else {}
    protocol = normalize_text(item.get("protocol") or meta.get("protocol"))
    subject = normalize_text(item.get("subject") or meta.get("subject"))
    if protocol and subject:
        return protocol, subject
    text = str(path).replace("\\", "/").lower()
    if "mqtt" in text:
        protocol = protocol or "MQTT"
    elif "quic" in text:
        protocol = protocol or "QUIC"
    elif "dtls" in text:
        protocol = protocol or "DTLS"
    elif "tls" in text:
        protocol = protocol or "TLS"
    subject = subject or Path(path).parts[-2] if len(Path(path).parts) >= 2 else Path(path).stem
    return protocol or "unknown", subject or "unknown"


def rq3_bug_finding(files: list[str]) -> dict[str, Any]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    all_reports: dict[str, dict[str, Any]] = {}
    for file in files:
        for item in load_judgments(file):
            key = report_key(item)
            if key in all_reports:
                continue
            all_reports[key] = item
            protocol, subject = infer_protocol_subject(file, item)
            bucket = rows.setdefault(
                (subject, protocol),
                {"subject": subject, "protocol": protocol, "rules": 0, "submitted": 0, "confirmed": 0, "false_positive": 0, "pending": 0},
            )
            bucket["rules"] += 1
            if final_label(item) == "INCONSISTENT":
                bucket["submitted"] += 1
                status = maintainer_status(item)
                if status == "confirmed":
                    bucket["confirmed"] += 1
                elif status == "false_positive":
                    bucket["false_positive"] += 1
                else:
                    bucket["pending"] += 1
    out_rows = list(rows.values())
    totals = Counter()
    for row in out_rows:
        for key in ["rules", "submitted", "confirmed", "false_positive", "pending"]:
            totals[key] += row[key]
        denom = row["confirmed"] + row["false_positive"]
        row["adjusted_precision"] = round(row["confirmed"] / denom, 4) if denom else None
    return {"generated_at": now_ts(), "rows": out_rows, "total": dict(totals)}


def estimate_tokens(text: str) -> int:
    return int(math.ceil(len(text) / 4.0))


def stage_from_item(item: dict[str, Any]) -> str:
    stage = normalize_text(item.get("stage") or item.get("pipeline_stage"))
    if stage:
        return stage
    if "validation" in item:
        return "verification_test_agent"
    if "candidate_snippets" in item or "contexts" in item or "bundle" in item:
        return "code_context_extraction"
    if "rule" in item and "reasoning" in item:
        return "consistency_reasoning"
    return "unknown"


def normalize_usage(usage: Any) -> dict[str, int]:
    if isinstance(usage, dict):
        return {
            "input_tokens": int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0),
            "output_tokens": int(usage.get("output_tokens") or usage.get("completion_tokens") or 0),
        }
    return {"input_tokens": 0, "output_tokens": 0}


def add_usage(stage_usage: dict[str, Counter], stage: str, input_text: str = "", output_text: str = "", usage: Any = None) -> None:
    explicit = normalize_usage(usage)
    if explicit["input_tokens"] or explicit["output_tokens"]:
        stage_usage[stage]["input_tokens"] += explicit["input_tokens"]
        stage_usage[stage]["output_tokens"] += explicit["output_tokens"]
        return
    stage_usage[stage]["input_tokens"] += estimate_tokens(input_text)
    stage_usage[stage]["output_tokens"] += estimate_tokens(output_text)


def collect_stage_token_usage(item: dict[str, Any]) -> dict[str, Counter]:
    stage_usage: dict[str, Counter] = defaultdict(Counter)
    usage_by_stage = item.get("usage_by_stage")
    if isinstance(usage_by_stage, dict):
        for stage, usage in usage_by_stage.items():
            add_usage(stage_usage, normalize_text(stage) or "unknown", usage=usage)
        return stage_usage

    item_usage = normalize_usage(item.get("usage"))
    if item_usage["input_tokens"] or item_usage["output_tokens"]:
        add_usage(stage_usage, stage_from_item(item), usage=item_usage)
        return stage_usage

    rule = item.get("rule", {}) if isinstance(item.get("rule"), dict) else {}
    bundle = item.get("bundle", {}) if isinstance(item.get("bundle"), dict) else {}
    reasoning = item.get("reasoning", []) if isinstance(item.get("reasoning"), list) else []
    validation = item.get("validation", {}) if isinstance(item.get("validation"), dict) else {}

    if bundle:
        bundle_input = json.dumps({"rule": rule, "candidate_budget": len(bundle.get("candidate_snippets", []))}, ensure_ascii=False)
        bundle_output = json.dumps(
            {
                "ranked_variables": bundle.get("ranked_variables", []),
                "contexts": bundle.get("contexts", []),
                "missing_links": bundle.get("missing_links", []),
                "alignment_summary": bundle.get("alignment_summary", ""),
            },
            ensure_ascii=False,
        )
        add_usage(stage_usage, "code_context_extraction", bundle_input, bundle_output)

    if reasoning:
        raw_output = "".join(normalize_text(r.get("raw_response")) for r in reasoning if isinstance(r, dict))
        if not raw_output:
            raw_output = json.dumps(reasoning, ensure_ascii=False)
        reason_input = json.dumps({"rule": rule, "bundle": bundle}, ensure_ascii=False)
        add_usage(stage_usage, "consistency_reasoning", reason_input, raw_output)

    if validation:
        validation_input = json.dumps({"rule": rule, "reasoning": reasoning[-1] if reasoning else {}, "validation_input": validation.get("input", {})}, ensure_ascii=False)
        validation_output = normalize_text(validation.get("raw_response")) or json.dumps(validation, ensure_ascii=False)
        add_usage(stage_usage, "verification_test_agent", validation_input, validation_output)

    if not stage_usage:
        raw = json.dumps(item, ensure_ascii=False)
        add_usage(stage_usage, stage_from_item(item), raw, "")
    return stage_usage


def rq4_cost(files: list[str], pricing: dict[str, float]) -> dict[str, Any]:
    stage_usage: dict[str, Counter] = defaultdict(Counter)
    submitted = 0
    for file in files:
        for item in load_judgments(file):
            if final_label(item) == "INCONSISTENT":
                submitted += 1
            for stage, usage in collect_stage_token_usage(item).items():
                stage_usage[stage]["input_tokens"] += usage["input_tokens"]
                stage_usage[stage]["output_tokens"] += usage["output_tokens"]
    rows = []
    total_cost = 0.0
    denom = max(1, submitted)
    for stage, usage in sorted(stage_usage.items()):
        cost = usage["input_tokens"] / 1_000_000 * pricing["input_per_1m"] + usage["output_tokens"] / 1_000_000 * pricing["output_per_1m"]
        total_cost += cost
        rows.append(
            {
                "stage": stage,
                "input_tokens": usage["input_tokens"],
                "output_tokens": usage["output_tokens"],
                "cost_total": round(cost, 6),
                "cost_per_submitted_report": round(cost / denom, 6),
            }
        )
    for row in rows:
        row["share"] = round(row["cost_total"] / total_cost, 4) if total_cost else 0.0
    return {
        "generated_at": now_ts(),
        "submitted_reports": submitted,
        "pricing": pricing,
        "rows": rows,
        "total_cost": round(total_cost, 6),
        "cost_per_submitted_report": round(total_cost / denom, 6),
    }


def rq5_component_buildup(files_by_config: list[tuple[str, str]]) -> dict[str, Any]:
    all_keys: set[str] = set()
    config_items: list[tuple[str, list[dict[str, Any]]]] = []
    for config, file in files_by_config:
        items = load_judgments(file)
        config_items.append((config, items))
        for item in items:
            if final_label(item) == "INCONSISTENT":
                all_keys.add(report_key(item))
    denom = max(1, len(all_keys))
    rows = []
    for config, items in config_items:
        counts = Counter()
        discovered: set[str] = set()
        for item in items:
            label = final_label(item)
            if label == "INCONSISTENT":
                counts["submitted"] += 1
                discovered.add(report_key(item))
                status = maintainer_status(item)
                counts[status] += 1
            elif label == "INSUFFICIENT":
                counts["pending"] += 1
        confirmed = counts["confirmed"]
        fp = counts["false_positive"]
        rows.append(
            {
                "configuration": config,
                "submitted": counts["submitted"],
                "confirmed": confirmed,
                "false_positive": fp,
                "pending": counts["pending"],
                "adjusted_precision": round(confirmed / (confirmed + fp), 4) if (confirmed + fp) else None,
                "coverage": round(len(discovered) / denom, 4),
            }
        )
    return {"generated_at": now_ts(), "union_inconsistent_reports": len(all_keys), "rows": rows}


def markdown_table(title: str, rows: list[dict[str, Any]]) -> str:
    if not rows:
        return f"# {title}\n\nNo rows.\n"
    headers = list(rows[0].keys())
    lines = [f"# {title}", "", "| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
    return "\n".join(lines) + "\n"


def parse_config_files(values: list[str]) -> list[tuple[str, str]]:
    out = []
    for value in values:
        if "=" not in value:
            raise ValueError("--config-file must be NAME=PATH")
        name, path = value.split("=", 1)
        out.append((name.strip(), path.strip()))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate SpecField RQ3/RQ4/RQ5 artifacts.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p3 = sub.add_parser("rq3", help="Aggregate submitted/confirmed/FP/pending report outcomes.")
    p3.add_argument("--input", action="append", required=True)
    p3.add_argument("--output-json", default="output/specfield_rq3.json")
    p3.add_argument("--output-md", default="output/specfield_rq3.md")

    p4 = sub.add_parser("rq4", help="Estimate model cost by pipeline stage.")
    p4.add_argument("--input", action="append", required=True)
    p4.add_argument("--pricing-json", default="")
    p4.add_argument("--output-json", default="output/specfield_rq4.json")
    p4.add_argument("--output-md", default="output/specfield_rq4.md")

    p5 = sub.add_parser("rq5", help="Aggregate component-buildup configurations.")
    p5.add_argument("--config-file", action="append", required=True, help="NAME=PATH")
    p5.add_argument("--output-json", default="output/specfield_rq5.json")
    p5.add_argument("--output-md", default="output/specfield_rq5.md")

    args = parser.parse_args()
    if args.cmd == "rq3":
        result = rq3_bug_finding(args.input)
        write_json(Path(args.output_json), result)
        write_text(Path(args.output_md), markdown_table("RQ3 Bug Finding", result["rows"]))
        print(json.dumps(result["total"], ensure_ascii=False, indent=2))
    elif args.cmd == "rq4":
        pricing = DEFAULT_PRICING
        if args.pricing_json:
            pricing = {**pricing, **read_json(args.pricing_json)}
        result = rq4_cost(args.input, pricing)
        write_json(Path(args.output_json), result)
        write_text(Path(args.output_md), markdown_table("RQ4 Cost", result["rows"]))
        print(json.dumps({"total_cost": result["total_cost"], "cost_per_submitted_report": result["cost_per_submitted_report"]}, ensure_ascii=False, indent=2))
    elif args.cmd == "rq5":
        result = rq5_component_buildup(parse_config_files(args.config_file))
        write_json(Path(args.output_json), result)
        write_text(Path(args.output_md), markdown_table("RQ5 Component Buildup", result["rows"]))
        print(json.dumps({"union_inconsistent_reports": result["union_inconsistent_reports"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
