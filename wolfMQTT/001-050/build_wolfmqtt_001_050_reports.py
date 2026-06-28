#!/usr/bin/env python3

from __future__ import annotations



import json

import re

from collections import Counter, defaultdict

from datetime import datetime

from pathlib import Path





WORKSPACE = Path(__file__).resolve().parents[2]

OUT_DIR = Path(__file__).resolve().parent



SOURCE_JSON = WORKSPACE / "output" / "02_variable_changes.json"

TARGET_DIR = WORKSPACE / "wolfMQTT-master"



OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_001_050.json"

OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_001_050.md"

OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_001_050_simple.txt"

OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_001_050_partial_unsat_classification.json"

OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_001_050_partial_unsat_classification.md"





def load_json(path: Path) -> dict:

    return json.loads(path.read_text(encoding="utf-8"))





def save_json(path: Path, data: dict) -> None:

    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")





def normalize_counts(counter: Counter) -> dict:

    return {

        "satisfied": counter.get("satisfied", 0),

        "partially satisfied": counter.get("partially satisfied", 0),

        "unsatisfied": counter.get("unsatisfied", 0),

        "not applicable": counter.get("not applicable", 0),

        "unknown": counter.get("unknown", 0),

    }





def validate_evidence_refs(refs: list[str]) -> dict:

    missing_files: list[str] = []

    out_of_range: list[str] = []

    bad_format: list[str] = []

    cache: dict[Path, list[str]] = {}



    for ref in refs:

        m = re.match(r"^([^:]+):(\d+)$", ref)

        if not m:

            bad_format.append(ref)

            continue

        rel_path = m.group(1)

        line_no = int(m.group(2))

        abs_path = WORKSPACE / rel_path

        if not abs_path.exists():

            missing_files.append(ref)

            continue

        if abs_path not in cache:

            cache[abs_path] = abs_path.read_text(encoding="utf-8", errors="replace").splitlines()

        line_count = len(cache[abs_path])

        if line_no < 1 or line_no > line_count:

            out_of_range.append(ref)



    return {

        "total_references": len(refs),

        "missing_files": sorted(set(missing_files)),

        "out_of_range": sorted(set(out_of_range)),

        "bad_format": sorted(set(bad_format)),

        "all_locatable": not (missing_files or out_of_range or bad_format),

    }





def md_escape(text: str) -> str:

    return text.replace("|", "\\|").replace("\n", " ")





def rule_mapping() -> dict[int, dict]:

    return {

        1: {

            "status": "partially satisfied",

            "comment": "clean_session=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:1397",

                "wolfMQTT-master/src/mqtt_broker.c:1405",

                "wolfMQTT-master/src/mqtt_broker.c:3291",

                "wolfMQTT-master/src/mqtt_broker.c:3497",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "unspecified",

        },

        2: {

            "status": "satisfied",

            "comment": "SUBSCRIBE unspecified 0010.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1753",

                "wolfMQTT-master/src/mqtt_packet.c:1754",

            ],

        },

        3: {

            "status": "satisfied",

            "comment": "UNSUBSCRIBE unspecified 0010.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:2047",

                "wolfMQTT-master/src/mqtt_packet.c:2048",

            ],

        },

        4: {

            "status": "unsatisfied",

            "comment": "SUBSCRIBE unspecifiedvalidation packet type,unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:198",

                "wolfMQTT-master/src/mqtt_packet.c:1814",

                "wolfMQTT-master/src/mqtt_broker.c:3570",

                "wolfMQTT-master/src/mqtt_broker.c:3571",

            ],

            "category": "unspecifiedvalidation",

            "risk_level": "high",

            "reason": "unspecified malformed+close.",

        },

        5: {

            "status": "unsatisfied",

            "comment": "UNSUBSCRIBE unspecifiedpath.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:198",

                "wolfMQTT-master/src/mqtt_packet.c:2103",

                "wolfMQTT-master/src/mqtt_broker.c:3573",

                "wolfMQTT-master/src/mqtt_broker.c:3574",

            ],

            "category": "unspecifiedvalidation",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        6: {

            "status": "satisfied",

            "comment": "PUBREL unspecified 0010.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1563",

                "wolfMQTT-master/src/mqtt_packet.c:1566",

                "wolfMQTT-master/src/mqtt_broker.c:3425",

            ],

        },

        7: {

            "status": "satisfied",

            "comment": "same as ID6,PUBREL unspecified 0010 semantic.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1563",

                "wolfMQTT-master/src/mqtt_packet.c:1566",

                "wolfMQTT-master/src/mqtt_broker.c:3428",

            ],

        },

        8: {

            "status": "unsatisfied",

            "comment": "PUBREL unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:198",

                "wolfMQTT-master/src/mqtt_packet.c:1625",

                "wolfMQTT-master/src/mqtt_broker.c:3375",

                "wolfMQTT-master/src/mqtt_broker.c:3561",

            ],

            "category": "unspecifiedvalidation",

            "risk_level": "high",

            "reason": "PUBREL unspecified malformed+close.",

        },

        9: {

            "status": "unsatisfied",

            "comment": "same as ID8,PUBREL unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:198",

                "wolfMQTT-master/src/mqtt_packet.c:1625",

                "wolfMQTT-master/src/mqtt_broker.c:3375",

                "wolfMQTT-master/src/mqtt_broker.c:3561",

            ],

            "category": "unspecifiedvalidation",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        10: {

            "status": "satisfied",

            "comment": "SUBSCRIBE unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1753",

                "wolfMQTT-master/src/mqtt_packet.c:1754",

            ],

        },

        11: {

            "status": "unsatisfied",

            "comment": "SUBSCRIBE unspecifiedconnection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:198",

                "wolfMQTT-master/src/mqtt_packet.c:1814",

                "wolfMQTT-master/src/mqtt_broker.c:3570",

                "wolfMQTT-master/src/mqtt_broker.c:3571",

            ],

            "category": "unspecifiedvalidation",

            "risk_level": "high",

            "reason": "missingunspecifiedvalidation.",

        },

        12: {

            "status": "satisfied",

            "comment": "UNSUBSCRIBE unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:2047",

                "wolfMQTT-master/src/mqtt_packet.c:2048",

            ],

        },

        13: {

            "status": "unsatisfied",

            "comment": "UNSUBSCRIBE unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:198",

                "wolfMQTT-master/src/mqtt_packet.c:2103",

                "wolfMQTT-master/src/mqtt_broker.c:3573",

                "wolfMQTT-master/src/mqtt_broker.c:3574",

            ],

            "category": "unspecifiedvalidation",

            "risk_level": "high",

            "reason": "missing UNSUBSCRIBE unspecifiedprocessing.",

        },

        14: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:1397",

                "wolfMQTT-master/src/mqtt_broker.c:1405",

                "wolfMQTT-master/src/mqtt_broker.c:3291",

                "wolfMQTT-master/src/mqtt_broker.c:3497",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "unspecified",

        },

        15: {

            "status": "partially satisfied",

            "comment": "clean_session=0 unspecifiedstatus.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2775",

                "wolfMQTT-master/src/mqtt_broker.c:2778",

                "wolfMQTT-master/src/mqtt_broker.c:1745",

                "wolfMQTT-master/src/mqtt_broker.c:1780",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        16: {

            "status": "satisfied",

            "comment": "clean_session=1 unspecifiedsemantic.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2780",

                "wolfMQTT-master/src/mqtt_broker.c:2782",

                "wolfMQTT-master/src/mqtt_broker.c:1677",

            ],

        },

        17: {

            "status": "unsatisfied",

            "comment": "unspecified clean_session=1;clientunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:804",

                "wolfMQTT-master/src/mqtt_packet.c:869",

                "wolfMQTT-master/src/mqtt_broker.c:2744",

                "wolfMQTT-master/src/mqtt_broker.c:2972",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "unspecifiedprocessing.",

        },

        18: {

            "status": "unsatisfied",

            "comment": "unspecified ClientId + clean_session=0 unspecifiedconnection,MQTT5 pathunspecified ID.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2918",

                "wolfMQTT-master/src/mqtt_broker.c:2972",

                "wolfMQTT-master/src/mqtt_broker.c:2980",

                "wolfMQTT-master/src/mqtt_broker.c:3043",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "unspecified ID.",

        },

        19: {

            "status": "unsatisfied",

            "comment": "same as ID17:unspecified clean_session=1.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:804",

                "wolfMQTT-master/src/mqtt_packet.c:869",

                "wolfMQTT-master/src/mqtt_broker.c:2972",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "clean_session unspecified.",

        },

        20: {

            "status": "unsatisfied",

            "comment": "unspecified ClientId + clean_session=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2918",

                "wolfMQTT-master/src/mqtt_broker.c:2972",

                "wolfMQTT-master/src/mqtt_broker.c:3043",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        21: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2917",

                "wolfMQTT-master/src/mqtt_broker.c:2918",

            ],

            "category": "unspecified",

            "risk_level": "low",

            "reason": "unspecified.",

        },

        22: {

            "status": "satisfied",

            "comment": "clean_session=1 pathunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2780",

                "wolfMQTT-master/src/mqtt_broker.c:2782",

            ],

        },

        23: {

            "status": "not applicable",

            "comment": "unspecified broker protocolmandatoryvalidationunspecified.",

            "evidence": [],

        },

        24: {

            "status": "not applicable",

            "comment": "unspecified.",

            "evidence": [],

        },

        25: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:1397",

                "wolfMQTT-master/src/mqtt_broker.c:3581",

                "wolfMQTT-master/src/mqtt_broker.c:3586",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "unspecified",

        },

        26: {

            "status": "not applicable",

            "comment": "unspecified.",

            "evidence": [],

        },

        27: {

            "status": "unsatisfied",

            "comment": "clean_session=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2777",

                "wolfMQTT-master/src/mqtt_broker.c:3291",

                "wolfMQTT-master/src/mqtt_broker.c:3333",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        28: {

            "status": "partially satisfied",

            "comment": "clean_session=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2775",

                "wolfMQTT-master/src/mqtt_broker.c:2778",

                "wolfMQTT-master/src/mqtt_broker.c:1745",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "unspecifiedstatus.",

        },

        29: {

            "status": "unsatisfied",

            "comment": "unspecified UTF-8 well-formed validation,unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:356",

                "wolfMQTT-master/src/mqtt_broker.c:2694",

            ],

            "category": "UTF-8protocolvalidationunspecified",

            "risk_level": "high",

            "reason": "stringunspecifiedvalidation Unicode validunspecified.",

        },

        30: {

            "status": "satisfied",

            "comment": "serverunspecifiedprocessing.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1038",

                "wolfMQTT-master/src/mqtt_broker.c:2972",

            ],

        },

        31: {

            "status": "partially satisfied",

            "comment": "unspecifiedvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:354",

                "wolfMQTT-master/src/mqtt_broker.c:175",

                "wolfMQTT-master/src/mqtt_broker.c:202",

            ],

            "category": "UTF-8semanticunspecified",

            "risk_level": "low",

            "reason": "unspecifiedsemanticvalidationpath.",

        },

        32: {

            "status": "unsatisfied",

            "comment": "not foundunspecifiedrejectionvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:356",

            ],

            "category": "UTF-8protocolvalidationunspecified",

            "risk_level": "high",

            "reason": "missing surrogate code point unspecified.",

        },

        33: {

            "status": "unsatisfied",

            "comment": "not found U+0000 unspecifiedrejectionvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:356",

                "wolfMQTT-master/src/mqtt_broker.c:175",

            ],

            "category": "UTF-8protocolvalidationunspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        34: {

            "status": "unsatisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:356",

                "wolfMQTT-master/src/mqtt_broker.c:2694",

            ],

            "category": "UTF-8protocolvalidationunspecified",

            "risk_level": "high",

            "reason": "missing U+0000 unspecifiedlogic.",

        },

        35: {

            "status": "satisfied",

            "comment": "CONNECT unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:912",

                "wolfMQTT-master/src/mqtt_packet.c:932",

                "wolfMQTT-master/src/mqtt_packet.c:937",

                "wolfMQTT-master/src/mqtt_packet.c:940",

            ],

        },

        36: {

            "status": "satisfied",

            "comment": "ClientId unspecifiedpath.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:770",

                "wolfMQTT-master/src/mqtt_packet.c:1038",

            ],

        },

        37: {

            "status": "satisfied",

            "comment": "unspecifiedmedium ClientId fieldunspecifiedfield.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:770",

                "wolfMQTT-master/src/mqtt_packet.c:1038",

            ],

        },

        38: {

            "status": "satisfied",

            "comment": "unspecifiedfieldprocessing.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:805",

                "wolfMQTT-master/src/mqtt_packet.c:843",

                "wolfMQTT-master/src/mqtt_packet.c:846",

            ],

        },

        39: {

            "status": "unsatisfied",

            "comment": "ClientId UTF-8 validunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:1038",

                "wolfMQTT-master/src/mqtt_broker.c:2694",

            ],

            "category": "UTF-8protocolvalidationunspecified",

            "risk_level": "high",

            "reason": "ClientId unspecified.",

        },

        40: {

            "status": "unsatisfied",

            "comment": "ClientId unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:1038",

                "wolfMQTT-master/src/mqtt_broker.c:175",

            ],

            "category": "UTF-8protocolvalidationunspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        41: {

            "status": "partially satisfied",

            "comment": "protocolunspecified).",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:366",

                "wolfMQTT-master/src/mqtt_broker.c:2713",

            ],

            "category": "ClientIdlengthunspecified",

            "risk_level": "medium",

            "reason": "protocollengthunspecified.",

        },

        42: {

            "status": "satisfied",

            "comment": "unspecifiedlength ClientId.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1038",

                "wolfMQTT-master/src/mqtt_broker.c:2972",

            ],

        },

        43: {

            "status": "unsatisfied",

            "comment": "unspecifiedlength ClientId + clean_session=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2744",

                "wolfMQTT-master/src/mqtt_broker.c:2918",

                "wolfMQTT-master/src/mqtt_broker.c:2972",

            ],

            "category": "unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        44: {

            "status": "partially satisfied",

            "comment": "MQTT5 pathunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2972",

                "wolfMQTT-master/src/mqtt_broker.c:2975",

                "wolfMQTT-master/src/mqtt_broker.c:2980",

            ],

            "category": "unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        45: {

            "status": "partially satisfied",

            "comment": "same as ID44:unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2972",

                "wolfMQTT-master/src/mqtt_broker.c:2975",

                "wolfMQTT-master/src/mqtt_broker.c:2980",

            ],

            "category": "unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        46: {

            "status": "partially satisfied",

            "comment": "ClientId unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2713",

                "wolfMQTT-master/src/mqtt_broker.c:2726",

                "wolfMQTT-master/src/mqtt_broker.c:3043",

                "wolfMQTT-master/src/mqtt_broker.c:3541",

            ],

            "category": "ClientIdrejectionunspecified",

            "risk_level": "medium",

            "reason": "unspecified 0x02.",

        },

        47: {

            "status": "satisfied",

            "comment": "0x02(Identifier rejected) semanticunspecified.",

            "evidence": [

                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:382",

                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:383",

                "wolfMQTT-master/src/mqtt_broker.c:2726",

            ],

        },

        48: {

            "status": "partially satisfied",

            "comment": "unspecifiedexplicitvalidationlogic.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2713",

                "wolfMQTT-master/src/mqtt_broker.c:2731",

            ],

            "category": "ClientIdunspecifiedexplicitvalidation",

            "risk_level": "medium",

            "reason": "missingunspecified.",

        },

        49: {

            "status": "partially satisfied",

            "comment": "unspecified ClientId+clean_session=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2726",

                "wolfMQTT-master/src/mqtt_broker.c:2972",

            ],

            "category": "ClientIdrejectionunspecified",

            "risk_level": "medium",

            "reason": "rejectionunspecified.",

        },

        50: {

            "status": "unsatisfied",

            "comment": "unspecified well-formed validation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:356",

                "wolfMQTT-master/src/mqtt_broker.c:2694",

            ],

            "category": "UTF-8protocolvalidationunspecified",

            "risk_level": "high",

            "reason": "unspecifiedvalidation.",

        },

    }





def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:

    results: list[dict] = []

    for i, change in enumerate(changes, start=1):

        m = mapping[i]

        results.append(

            {

                "id": i,

                "source_index": i - 1,

                "variable_name": change.get("variable_name", ""),

                "change_action": change.get("change_action", ""),

                "change_condition": change.get("change_condition", ""),

                "old_value": change.get("old_value", ""),

                "new_value": change.get("new_value", ""),

                "related_state_or_step": change.get("related_state_or_step", ""),

                "source_chunk_id": change.get("source_chunk_id", ""),

                "status": m["status"],

                "comment": "Unspecified comment.",

                "evidence_in_wolfmqtt": m.get("evidence", []),

            }

        )



    counts = normalize_counts(Counter([r["status"] for r in results]))

    all_refs: list[str] = []

    for r in results:

        all_refs.extend(r.get("evidence_in_wolfmqtt", []))

    evidence_check = validate_evidence_refs(all_refs)



    meta = {

        "source_file": str(SOURCE_JSON),

        "scope": "source_changes_index_0_to_49",

        "display_scope": "001-050",

        "method": "static_code_comparison",

        "target": "wolfMQTT-master",

        "generated_at": datetime.now().isoformat(timespec="seconds"),

        "counts": counts,

        "evidence_validation": evidence_check,

    }

    return {"meta": meta, "results": results}





def build_compare_md(compare: dict) -> str:

    meta = compare["meta"]

    rows = compare["results"]

    lines = [

        f"# {meta.get('implementation', 'wolfMQTT-master')} comparison results",

        "",

        "- Source: `output/02_variable_changes.json`",

        "- Target code: `wolfMQTT-master`",

        f"- Satisfied: {meta['counts']['satisfied']}",

        f"- Partially satisfied: {meta['counts']['partially satisfied']}",

        f"- Unsatisfied: {meta['counts']['unsatisfied']}",

        f"- Not applicable: {meta['counts']['not applicable']}",

        f"- Unknown: {meta['counts'].get('unknown', 0)}",

        (

            "- Evidence validation: "

            f"all_locatable={meta['evidence_validation']['all_locatable']}, "

            f"references={meta['evidence_validation']['total_references']}"

        ),

        "",

        "| ID | source_idx | variable | action | status | comment | evidence_refs |",

        "|---:|---:|---|---|---|---|---:|",

    ]

    for r in rows:

        lines.append(

            "| {id} | {idx} | {var} | {act} | {status} | {comment} | {ev_count} |".format(

                id=r["id"],

                idx=r["source_index"],

                var=md_escape(r["variable_name"]),

                act=md_escape(r["change_action"]),

                status=r["status"],

                comment=md_escape(r["comment"]),

                ev_count=len(r.get("evidence_in_wolfmqtt", [])),

            )

        )

    lines.append("")

    return "\n".join(lines)



def build_simple_txt(compare: dict) -> str:

    lines: list[str] = []

    for r in compare["results"]:

        lines.append(f"{r['id']:03d}\t{r['status']}\t{r['comment']}")

    return "\n".join(lines) + "\n"





def build_classification(compare: dict, mapping: dict[int, dict]) -> dict:

    results = compare["results"]

    filtered = [r for r in results if r["status"] in ("partially satisfied", "unsatisfied")]

    class_rows: list[dict] = []



    for r in filtered:

        m = mapping[r["id"]]

        class_rows.append(

            {

                "id": r["id"],

                "status": r["status"],

                "category": "Uncategorized",

                "risk_level": m.get("risk_level", "medium"),

                "reason": "Unspecified reason.",

                "variable_name": r["variable_name"],

                "change_action": r["change_action"],

                "change_condition": r["change_condition"],

                "source_index": r["source_index"],

                "source_chunk_id": r["source_chunk_id"],

                "original_comment": r["comment"],

                "evidence_in_wolfmqtt": r.get("evidence_in_wolfmqtt", []),

            }

        )



    status_counter = Counter([x["status"] for x in class_rows])

    risk_counter = Counter([x["risk_level"] for x in class_rows])



    category_summary: dict[str, dict] = defaultdict(lambda: {"count": 0, "partial": 0, "unsatisfied": 0})

    for row in class_rows:

        cat = row["category"]

        category_summary[cat]["count"] += 1

        if row["status"] == "partially satisfied":

            category_summary[cat]["partial"] += 1

        elif row["status"] == "unsatisfied":

            category_summary[cat]["unsatisfied"] += 1



    return {

        "scope": "wolfMQTT-master 001-050 partial+unsatisfied",

        "total_reviewed": len(class_rows),

        "status_summary": {

            "partially satisfied": status_counter.get("partially satisfied", 0),

            "unsatisfied": status_counter.get("unsatisfied", 0),

        },

        "risk_summary": {

            "low": risk_counter.get("low", 0),

            "medium": risk_counter.get("medium", 0),

            "high": risk_counter.get("high", 0),

        },

        "category_summary": dict(sorted(category_summary.items(), key=lambda x: x[0])),

        "results": class_rows,

    }





def build_classification_md(classification: dict) -> str:

    lines = [

        "# wolfMQTT-master 001-050 unsatisfied/partially satisfied category",

        "",

        f"- total_reviewed: {classification['total_reviewed']}",

        f"- partially satisfied: {classification['status_summary']['partially satisfied']}",

        f"- unsatisfied: {classification['status_summary']['unsatisfied']}",

        (

            "- risk distribution: "

            f"low={classification['risk_summary']['low']}, "

            f"medium={classification['risk_summary']['medium']}, "

            f"high={classification['risk_summary']['high']}"

        ),

        "",

        "## classification summary",

        "",

        "| category | count | partially satisfied | unsatisfied |",

        "|---|---:|---:|---:|",

    ]

    for cat, summary in classification["category_summary"].items():

        lines.append(

            f"| {md_escape(cat)} | {summary['count']} | {summary['partial']} | {summary['unsatisfied']} |"

        )



    lines.extend(

        [

            "",

            "## details",

            "",

            "| ID | source_idx | status | risk | category | reason |",

            "|---:|---:|---|---|---|---|",

        ]

    )

    for row in classification["results"]:

        lines.append(

            "| {id} | {idx} | {status} | {risk} | {cat} | {reason} |".format(

                id=row["id"],

                idx=row["source_index"],

                status=row["status"],

                risk=row["risk_level"],

                cat=md_escape(row["category"]),

                reason=md_escape(row["reason"]),

            )

        )

    lines.append("")

    return "\n".join(lines)





def main() -> None:

    source = load_json(SOURCE_JSON)

    changes = source.get("changes", [])[:50]

    if len(changes) != 50:

        raise RuntimeError(f"Expected 50 records for 001-050, got {len(changes)}")



    mapping = rule_mapping()

    if sorted(mapping.keys()) != list(range(1, 51)):

        raise RuntimeError("Rule mapping must cover IDs 1..50")



    compare = build_compare(changes, mapping)

    save_json(OUT_COMPARE_JSON, compare)

    OUT_COMPARE_MD.write_text(build_compare_md(compare), encoding="utf-8")

    OUT_SIMPLE_TXT.write_text(build_simple_txt(compare), encoding="utf-8")



    classification = build_classification(compare, mapping)

    save_json(OUT_CLASS_JSON, classification)

    OUT_CLASS_MD.write_text(build_classification_md(classification), encoding="utf-8")



    print("Generated:")

    print(f"- {OUT_COMPARE_JSON}")

    print(f"- {OUT_COMPARE_MD}")

    print(f"- {OUT_SIMPLE_TXT}")

    print(f"- {OUT_CLASS_JSON}")

    print(f"- {OUT_CLASS_MD}")





if __name__ == "__main__":

    main()



