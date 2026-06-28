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



OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_101_150.json"

OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_101_150.md"

OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_101_150_simple.txt"

OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_101_150_partial_unsat_classification.json"

OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_101_150_partial_unsat_classification.md"





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

            cache[abs_path] = abs_path.read_text(

                encoding="utf-8", errors="replace"

            ).splitlines()

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

        101: {

            "status": "partially satisfied",

            "comment": "PUBCOMP unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3207",

                "wolfMQTT-master/src/mqtt_broker.c:3335",

                "wolfMQTT-master/src/mqtt_broker.c:3375",

                "wolfMQTT-master/src/mqtt_broker.c:3562",

            ],

            "category": "QoS2 unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        102: {

            "status": "partially satisfied",

            "comment": "Broker unspecified id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:1628",

                "wolfMQTT-master/src/mqtt_broker.c:1633",

                "wolfMQTT-master/src/mqtt_broker.c:3302",

                "wolfMQTT-master/src/mqtt_client.c:2169",

            ],

            "category": "Packet Identifier unspecified",

            "risk_level": "high",

            "reason": "missing in-use unspecified",

        },

        103: {

            "status": "satisfied",

            "comment": "UNSUBACK unspecified UNSUBSCRIBE.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3161",

                "wolfMQTT-master/src/mqtt_packet.c:2319",

            ],

        },

        104: {

            "status": "satisfied",

            "comment": "receives PUBREL unspecified packet id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3375",

                "wolfMQTT-master/src/mqtt_broker.c:3389",

                "wolfMQTT-master/src/mqtt_broker.c:3392",

            ],

        },

        105: {

            "status": "satisfied",

            "comment": "receives PUBREC unspecified packet id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3411",

                "wolfMQTT-master/src/mqtt_broker.c:3425",

                "wolfMQTT-master/src/mqtt_broker.c:3428",

            ],

        },

        106: {

            "status": "satisfied",

            "comment": "SUBACK unspecified SUBSCRIBE.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3111",

                "wolfMQTT-master/src/mqtt_broker.c:2623",

            ],

        },

        107: {

            "status": "partially satisfied",

            "comment": "QoS1 unspecified use validation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3300",

                "wolfMQTT-master/src/mqtt_broker.c:3302",

                "wolfMQTT-master/src/mqtt_broker.c:1628",

                "wolfMQTT-master/src/mqtt_broker.c:1633",

            ],

            "category": "Packet Identifier unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        108: {

            "status": "satisfied",

            "comment": "QoS1 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3335",

                "wolfMQTT-master/src/mqtt_broker.c:3342",

                "wolfMQTT-master/src/mqtt_client.c:964",

            ],

        },

        109: {

            "status": "satisfied",

            "comment": "QoS1 unspecified 0).",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1308",

                "wolfMQTT-master/src/mqtt_packet.c:1309",

                "wolfMQTT-master/src/mqtt_packet.c:1363",

            ],

        },

        110: {

            "status": "satisfied",

            "comment": "QoS2 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3335",

                "wolfMQTT-master/src/mqtt_broker.c:3343",

                "wolfMQTT-master/src/mqtt_client.c:965",

            ],

        },

        111: {

            "status": "partially satisfied",

            "comment": "QoS2 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3300",

                "wolfMQTT-master/src/mqtt_broker.c:3302",

                "wolfMQTT-master/src/mqtt_broker.c:1628",

                "wolfMQTT-master/src/mqtt_broker.c:1633",

            ],

            "category": "Packet Identifier unspecified",

            "risk_level": "high",

            "reason": "QoS2 unspecified.",

        },

        112: {

            "status": "satisfied",

            "comment": "QoS2 unspecified 0).",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1308",

                "wolfMQTT-master/src/mqtt_packet.c:1309",

                "wolfMQTT-master/src/mqtt_packet.c:1363",

            ],

        },

        113: {

            "status": "satisfied",

            "comment": "unspecified packet id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3411",

                "wolfMQTT-master/src/mqtt_broker.c:3425",

            ],

        },

        114: {

            "status": "satisfied",

            "comment": "SUBACK unspecified SUBSCRIBE.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3111",

                "wolfMQTT-master/src/mqtt_broker.c:2623",

            ],

        },

        115: {

            "status": "satisfied",

            "comment": "UNSUBACK unspecified UNSUBSCRIBE.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3161",

                "wolfMQTT-master/src/mqtt_packet.c:2319",

            ],

        },

        116: {

            "status": "unsatisfied",

            "comment": "Unspecified comment.",

            "evidence": [

                "wolfMQTT-master/wolfmqtt/mqtt_broker.h:194",

                "wolfMQTT-master/wolfmqtt/mqtt_broker.h:321",

                "wolfMQTT-master/src/mqtt_broker.c:3556",

                "wolfMQTT-master/src/mqtt_broker.c:3568",

            ],

            "category": "QoS2 Method B unspecified",

            "risk_level": "high",

            "reason": "Broker clientstatusunspecified.",

        },

        117: {

            "status": "unsatisfied",

            "comment": "not found Method B unspecifiedlogic.",

            "evidence": [

                "wolfMQTT-master/wolfmqtt/mqtt_broker.h:194",

                "wolfMQTT-master/wolfmqtt/mqtt_broker.h:262",

                "wolfMQTT-master/src/mqtt_broker.c:3207",

                "wolfMQTT-master/src/mqtt_broker.c:3335",

            ],

            "category": "QoS2 Method B unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        118: {

            "status": "unsatisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3411",

                "wolfMQTT-master/src/mqtt_broker.c:3425",

                "wolfMQTT-master/src/mqtt_broker.c:3566",

                "wolfMQTT-master/wolfmqtt/mqtt_broker.h:194",

            ],

            "category": "QoS2 Method B unspecified",

            "risk_level": "high",

            "reason": "unspecified,missing Method B semanticunspecified.",

        },

        119: {

            "status": "satisfied",

            "comment": "QoS0 PUBLISH unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1308",

                "wolfMQTT-master/src/mqtt_packet.c:1362",

                "wolfMQTT-master/src/mqtt_packet.c:1443",

            ],

        },

        120: {

            "status": "satisfied",

            "comment": "SUBACK useunspecified packet id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3111",

                "wolfMQTT-master/src/mqtt_broker.c:2623",

            ],

        },

        121: {

            "status": "partially satisfied",

            "comment": "unspecified SUBSCRIBE/UNSUBSCRIBE/PUBLISH(QoS>0) unspecified non-zero validation;unspecifiedvalidation non-zero.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1309",

                "wolfMQTT-master/src/mqtt_packet.c:1715",

                "wolfMQTT-master/src/mqtt_packet.c:2010",

                "wolfMQTT-master/src/mqtt_packet.c:1449",

                "wolfMQTT-master/src/mqtt_packet.c:1828",

                "wolfMQTT-master/src/mqtt_packet.c:2117",

            ],

            "category": "Packet Identifier unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        122: {

            "status": "satisfied",

            "comment": "UNSUBACK unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3161",

                "wolfMQTT-master/src/mqtt_packet.c:2319",

            ],

        },

        123: {

            "status": "partially satisfied",

            "comment": "receivesunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3207",

                "wolfMQTT-master/src/mqtt_broker.c:3335",

                "wolfMQTT-master/src/mqtt_broker.c:3561",

                "wolfMQTT-master/src/mqtt_broker.c:3564",

            ],

            "category": "QoS2 unspecified",

            "risk_level": "high",

            "reason": "Unspecified reason.",

        },

        124: {

            "status": "unsatisfied",

            "comment": "clean_session=0 unspecified PUBLISH/PUBREL.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:1397",

                "wolfMQTT-master/src/mqtt_broker.c:2777",

                "wolfMQTT-master/src/mqtt_client.c:3031",

                "wolfMQTT-master/src/mqtt_client.c:3042",

            ],

            "category": "CleanSession=0 unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        125: {

            "status": "unsatisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3497",

                "wolfMQTT-master/src/mqtt_broker.c:3581",

                "wolfMQTT-master/src/mqtt_client.c:3031",

                "wolfMQTT-master/src/mqtt_client.c:3042",

            ],

            "category": "CleanSession=0 unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        126: {

            "status": "satisfied",

            "comment": "unspecified packet id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3375",

                "wolfMQTT-master/src/mqtt_broker.c:3390",

            ],

        },

        127: {

            "status": "satisfied",

            "comment": "unspecified packet id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3335",

                "wolfMQTT-master/src/mqtt_broker.c:3342",

            ],

        },

        128: {

            "status": "satisfied",

            "comment": "PUBCOMP unspecified packet id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3389",

                "wolfMQTT-master/src/mqtt_broker.c:3392",

            ],

        },

        129: {

            "status": "partially satisfied",

            "comment": "ACK processingunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_client.c:2287",

                "wolfMQTT-master/src/mqtt_client.c:2297",

                "wolfMQTT-master/src/mqtt_client.c:3042",

                "wolfMQTT-master/src/mqtt_broker.c:1628",

            ],

            "category": "Packet Identifier unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        130: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_client.c:2169",

                "wolfMQTT-master/src/mqtt_packet.c:1309",

                "wolfMQTT-master/src/mqtt_broker.c:1628",

                "wolfMQTT-master/src/mqtt_broker.c:1633",

            ],

            "category": "Packet Identifier unspecified",

            "risk_level": "high",

            "reason": "missingunspecifiedvalidation",

        },

        131: {

            "status": "satisfied",

            "comment": "PUBACK/PUBREC/PUBREL pathmedium packet id unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_client.c:964",

                "wolfMQTT-master/src/mqtt_client.c:1000",

                "wolfMQTT-master/src/mqtt_broker.c:3335",

                "wolfMQTT-master/src/mqtt_broker.c:3425",

            ],

        },

        132: {

            "status": "satisfied",

            "comment": "SUBACK/UNSUBACK unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3111",

                "wolfMQTT-master/src/mqtt_broker.c:3161",

                "wolfMQTT-master/src/mqtt_client.c:1305",

            ],

        },

        133: {

            "status": "partially satisfied",

            "comment": "fieldunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1309",

                "wolfMQTT-master/src/mqtt_packet.c:1715",

                "wolfMQTT-master/src/mqtt_packet.c:2010",

                "wolfMQTT-master/src/mqtt_packet.c:1828",

                "wolfMQTT-master/src/mqtt_packet.c:2117",

            ],

            "category": "Packet Identifier unspecified",

            "risk_level": "high",

            "reason": "encoding sideunspecified.",

        },

        134: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_client.c:2169",

                "wolfMQTT-master/src/mqtt_client.c:2287",

                "wolfMQTT-master/src/mqtt_client.c:2910",

                "wolfMQTT-master/src/mqtt_client.c:3042",

            ],

            "category": "Packet Identifier unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        135: {

            "status": "satisfied",

            "comment": "QoS1/2 PUBLISH unspecified packet id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1308",

                "wolfMQTT-master/src/mqtt_packet.c:1363",

                "wolfMQTT-master/src/mqtt_packet.c:1443",

            ],

        },

        136: {

            "status": "satisfied",

            "comment": "PUBACK unspecified PUBLISH.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3335",

                "wolfMQTT-master/src/mqtt_broker.c:3342",

            ],

        },

        137: {

            "status": "satisfied",

            "comment": "PUBREC unspecified PUBLISH.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3335",

                "wolfMQTT-master/src/mqtt_broker.c:3343",

            ],

        },

        138: {

            "status": "partially satisfied",

            "comment": "Server unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3302",

                "wolfMQTT-master/src/mqtt_broker.c:1628",

                "wolfMQTT-master/src/mqtt_broker.c:1633",

                "wolfMQTT-master/src/mqtt_broker.c:3650",

            ],

            "category": "Packet Identifier unspecified",

            "risk_level": "high",

            "reason": "serverunspecified.",

        },

        139: {

            "status": "partially satisfied",

            "comment": "unspecifiedexplicitrejection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:886",

                "wolfMQTT-master/src/mqtt_packet.c:940",

                "wolfMQTT-master/src/mqtt_packet.c:1130",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "Password Flag=0 unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        140: {

            "status": "partially satisfied",

            "comment": "same as ID139:Password Flag=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:886",

                "wolfMQTT-master/src/mqtt_packet.c:940",

                "wolfMQTT-master/src/mqtt_packet.c:1130",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "Password Flag=0 unspecified",

            "risk_level": "medium",

            "reason": "missingunspecifiedexplicitprotocolrejection.",

        },

        141: {

            "status": "satisfied",

            "comment": "Password Flag=1 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1130",

                "wolfMQTT-master/src/mqtt_packet.c:1134",

            ],

        },

        142: {

            "status": "satisfied",

            "comment": "same as ID141:Password Flag=1 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1130",

                "wolfMQTT-master/src/mqtt_packet.c:1136",

            ],

        },

        143: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:774",

                "wolfMQTT-master/src/mqtt_packet.c:777",

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1130",

            ],

            "category": "Password/Username Flag unspecified",

            "risk_level": "medium",

            "reason": "unspecifiedprotocolvalidation.",

        },

        144: {

            "status": "satisfied",

            "comment": "Password fieldlengthuse 16-bit unspecifiedboundaryvalidation(0..65535).",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

                "wolfMQTT-master/src/mqtt_packet.c:366",

                "wolfMQTT-master/src/mqtt_packet.c:370",

            ],

        },

        145: {

            "status": "satisfied",

            "comment": "unspecified).",

            "evidence": [

                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:390",

                "wolfMQTT-master/src/mqtt_broker.c:2877",

                "wolfMQTT-master/src/mqtt_broker.c:2905",

                "wolfMQTT-master/src/mqtt_broker.c:2960",

            ],

        },

        146: {

            "status": "partially satisfied",

            "comment": "Password Flag=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1130",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "Password Flag=0 unspecified",

            "risk_level": "medium",

            "reason": "unspecifiedvalidation",

        },

        147: {

            "status": "satisfied",

            "comment": "Password Flag=1 unspecifiederror.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1130",

                "wolfMQTT-master/src/mqtt_packet.c:1134",

            ],

        },

        148: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:774",

                "wolfMQTT-master/src/mqtt_packet.c:777",

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1130",

            ],

            "category": "CONNECT Flags unspecified",

            "risk_level": "high",

            "reason": "clientunspecifiedrejection.",

        },

        149: {

            "status": "partially satisfied",

            "comment": "Password Flag=1 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:938",

                "wolfMQTT-master/src/mqtt_packet.c:941",

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1130",

            ],

            "category": "Password/Username Flag unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        150: {

            "status": "unsatisfied",

            "comment": "SUBSCRIBE unspecified payload(topic_count=0),unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1865",

                "wolfMQTT-master/src/mqtt_packet.c:1898",

                "wolfMQTT-master/src/mqtt_broker.c:2603",

                "wolfMQTT-master/src/mqtt_broker.c:3111",

                "wolfMQTT-master/src/mqtt_broker.c:3571",

            ],

            "category": "SUBSCRIBE Payload unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

    }





def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:

    results: list[dict] = []

    for i, change in enumerate(changes, start=101):

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

        "scope": "source_changes_index_100_to_149",

        "display_scope": "101-150",

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

    rows = [r for r in compare["results"] if r["status"] in ("partially satisfied", "unsatisfied")]

    out: list[dict] = []

    for r in rows:

        m = mapping[r["id"]]

        out.append(

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



    status_counter = Counter([x["status"] for x in out])

    risk_counter = Counter([x["risk_level"] for x in out])

    category_summary: dict[str, dict] = defaultdict(

        lambda: {"count": 0, "partial": 0, "unsatisfied": 0}

    )



    for row in out:

        c = category_summary[row["category"]]

        c["count"] += 1

        if row["status"] == "partially satisfied":

            c["partial"] += 1

        else:

            c["unsatisfied"] += 1



    return {

        "scope": "wolfMQTT-master 101-150 partial+unsatisfied",

        "total_reviewed": len(out),

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

        "results": out,

    }





def build_classification_md(cls: dict) -> str:

    lines = [

        "# wolfMQTT-master 101-150 unsatisfied/partially satisfied category",

        "",

        f"- total_reviewed: {cls['total_reviewed']}",

        f"- partially satisfied: {cls['status_summary']['partially satisfied']}",

        f"- unsatisfied: {cls['status_summary']['unsatisfied']}",

        (

            "- risk distribution: "

            f"low={cls['risk_summary']['low']}, "

            f"medium={cls['risk_summary']['medium']}, "

            f"high={cls['risk_summary']['high']}"

        ),

        "",

        "## classification summary",

        "",

        "| category | count | partially satisfied | unsatisfied |",

        "|---|---:|---:|---:|",

    ]

    for cat, s in cls["category_summary"].items():

        lines.append(f"| {md_escape(cat)} | {s['count']} | {s['partial']} | {s['unsatisfied']} |")



    lines.extend(

        [

            "",

            "## details",

            "",

            "| ID | source_idx | status | risk | category | reason |",

            "|---:|---:|---|---|---|---|",

        ]

    )

    for r in cls["results"]:

        lines.append(

            "| {id} | {idx} | {status} | {risk} | {cat} | {reason} |".format(

                id=r["id"],

                idx=r["source_index"],

                status=r["status"],

                risk=r["risk_level"],

                cat=md_escape(r["category"]),

                reason=md_escape(r["reason"]),

            )

        )

    lines.append("")

    return "\n".join(lines)





def main() -> None:

    source = load_json(SOURCE_JSON)

    changes = source.get("changes", [])[100:150]

    if len(changes) != 50:

        raise RuntimeError(f"Expected 50 items for 101-150, got {len(changes)}")



    mapping = rule_mapping()

    if sorted(mapping.keys()) != list(range(101, 151)):

        raise RuntimeError("Rule mapping must cover IDs 101..150")



    compare = build_compare(changes, mapping)

    save_json(OUT_COMPARE_JSON, compare)

    OUT_COMPARE_MD.write_text(build_compare_md(compare), encoding="utf-8")

    OUT_SIMPLE_TXT.write_text(build_simple_txt(compare), encoding="utf-8")



    cls = build_classification(compare, mapping)

    save_json(OUT_CLASS_JSON, cls)

    OUT_CLASS_MD.write_text(build_classification_md(cls), encoding="utf-8")



    print("Generated:")

    print(f"- {OUT_COMPARE_JSON}")

    print(f"- {OUT_COMPARE_MD}")

    print(f"- {OUT_SIMPLE_TXT}")

    print(f"- {OUT_CLASS_JSON}")

    print(f"- {OUT_CLASS_MD}")





if __name__ == "__main__":

    main()

