#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


PROTOCOL_SOURCES = {
    "mqtt3.1.1": {
        "protocol": "MQTT",
        "version": "3.1.1",
        "source_standard": "document/mqtt/mqtt-v3.1.1-os.doc",
        "source_changes": "output/mqtt_02_variable_changes.json",
        "output": "evalute/field/mqtt3_1_1_field_rules.json",
        "rule_prefix": "MQTT311",
    },
    "tls1.3": {
        "protocol": "TLS",
        "version": "1.3",
        "source_standard": "document/TLS1.3.txt",
        "source_changes": "output/TLS_02_variable_changes.json",
        "output": "evalute/field/tls1_3_field_rules.json",
        "rule_prefix": "TLS13",
    },
}

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


def text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def infer_modality(row: dict[str, Any]) -> tuple[str, str]:
    haystack = " ".join([text(row.get("evidence")), text(row.get("change_action"))])
    normalized = re.sub(r"\s+", " ", haystack).upper()
    for pattern, modality in [
        (r"\bMUST\s+NOT\b", "MUST NOT"),
        (r"\bSHOULD\s+NOT\b", "SHOULD NOT"),
        (r"\bMUST\b", "MUST"),
        (r"\bSHOULD\b", "SHOULD"),
    ]:
        if re.search(pattern, normalized):
            return modality, "explicit"
    return "MUST", "inferred_from_step2_record"


def infer_action_type(row: dict[str, Any]) -> str:
    value = " ".join(
        [
            text(row.get("change_action")),
            text(row.get("evidence")),
            text(row.get("related_state_or_step")),
            text(row.get("change_condition")),
            text(row.get("new_value")),
            text(row.get("old_value")),
        ]
    ).lower()

    if any(word in value for word in ["malformed", "reject", "abort", "fail", "close", "error", "ignore", "discard", "invalid if"]):
        return "reject"
    if any(word in value for word in ["must be present", "present", "include", "contain", "appear"]):
        return "require-present"
    if any(word in value for word in ["must not be present", "absent", "omit", "not include", "not be sent"]):
        return "require-absent"
    if any(word in value for word in ["range", "bound", "less than", "greater than", "at least", "at most", "length", "maximum", "minimum"]):
        return "range-check"
    if any(word in value for word in ["derive", "derived", "compute", "computed", "calculate", "recompute", "hash", "hkdf", "transcript"]):
        return "derive"
    if any(word in value for word in ["select", "choose", "chosen", "negotiate", "negotiated", "offered", "supported list"]):
        return "select"
    if any(word in value for word in ["session", "state", "update", "remember", "store", "maintain", "cache", "resume"]):
        return "state-update"
    if any(word in value for word in ["set to", "set ", "assign", "clear", "increment", "decrement", "constant", "write"]):
        return "assign"
    if any(word in value for word in ["equal", "match", "same", "different", "correspond", "validate", "compare", "verify"]):
        return "compare"
    return "compare"


def rule_action(row: dict[str, Any]) -> str:
    action = text(row.get("change_action"))
    details = []
    old_value = text(row.get("old_value"))
    new_value = text(row.get("new_value"))
    if old_value:
        details.append(f"old value: {old_value}")
    if new_value:
        details.append(f"new value: {new_value}")
    if details:
        return f"{action}; " + "; ".join(details)
    return action


def normalize_change(row: dict[str, Any], index: int, prefix: str) -> dict[str, Any] | None:
    field = text(row.get("variable_name") or row.get("f"))
    condition = text(row.get("change_condition") or row.get("C"))
    action = rule_action(row)
    evidence = text(row.get("evidence") or row.get("E"))
    if not field or not condition or not action or not evidence:
        return None

    modality, modality_source = infer_modality(row)
    note = text(row.get("note"))
    if modality_source != "explicit":
        extra = "modality defaulted to MUST because the source step2 record is normative but no explicit MUST/SHOULD token was found"
        note = f"{note}; {extra}" if note else extra

    action_type = infer_action_type(row)
    if action_type not in ACTION_TYPES:
        action_type = "compare"

    return {
        "rule_id": f"{prefix}_{index:04d}",
        "f": field,
        "C": condition,
        "A": action,
        "M": modality,
        "E": evidence,
        "action_type": action_type,
        "source_location": text(row.get("source_location")),
        "source_chunk_id": text(row.get("source_chunk_id")),
        "related_state_or_step": text(row.get("related_state_or_step")),
        "old_value": text(row.get("old_value")),
        "new_value": text(row.get("new_value")),
        "explicit_or_inferred": text(row.get("explicit_or_inferred")) or "explicit",
        "note": note,
        "modality_source": modality_source,
    }


def compatibility_change(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": rule["rule_id"],
        "variable_name": rule["f"],
        "change_condition": rule["C"],
        "change_action": rule["A"],
        "old_value": rule.get("old_value", ""),
        "new_value": rule.get("new_value", ""),
        "related_state_or_step": rule.get("related_state_or_step", ""),
        "explicit_or_inferred": rule.get("explicit_or_inferred", "explicit"),
        "evidence": rule["E"],
        "note": rule.get("note", ""),
        "source_chunk_id": rule.get("source_chunk_id", ""),
        "action_type": rule["action_type"],
        "M": rule["M"],
    }


def build_rule_set(name: str, repo_root: Path) -> dict[str, Any]:
    config = PROTOCOL_SOURCES[name]
    source_path = repo_root / config["source_changes"]
    obj = json.loads(source_path.read_text(encoding="utf-8"))
    rows = obj.get("changes", [])
    if not isinstance(rows, list):
        raise ValueError(f"{source_path} does not contain a changes list")

    rules: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rule = normalize_change(row, len(rules) + 1, config["rule_prefix"])
        if rule is not None:
            rules.append(rule)

    modality_counts = Counter(rule["M"] for rule in rules)
    modality_source_counts = Counter(rule["modality_source"] for rule in rules)
    action_type_counts = Counter(rule["action_type"] for rule in rules)
    return {
        "meta": {
            "protocol": config["protocol"],
            "version": config["version"],
            "source_standard": config["source_standard"],
            "source_changes": config["source_changes"],
            "source_record_count": len(rows),
            "rule_count": len(rules),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "schema": "paper-style field rules: f, C, A, M, E, action_type",
            "modality_inference": "M is inferred from evidence/action text; records without explicit MUST/SHOULD default to MUST and are marked modality_source=inferred_from_step2_record.",
            "modality_counts": dict(sorted(modality_counts.items())),
            "modality_source_counts": dict(sorted(modality_source_counts.items())),
            "action_type_counts": dict(sorted(action_type_counts.items())),
        },
        "rules": rules,
        "changes": [compatibility_change(rule) for rule in rules],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build MQTT 3.1.1 and TLS 1.3 field rule JSON files from existing step2 outputs.")
    parser.add_argument("--protocol", choices=[*PROTOCOL_SOURCES.keys(), "all"], default="all")
    parser.add_argument("--repo-root", default=".")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve(strict=False)
    names = list(PROTOCOL_SOURCES) if args.protocol == "all" else [args.protocol]
    manifest = {}
    for name in names:
        data = build_rule_set(name, repo_root)
        output_path = repo_root / PROTOCOL_SOURCES[name]["output"]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        manifest[name] = str(output_path)
        print(f"{name}: wrote {data['meta']['rule_count']} rules -> {output_path}")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
