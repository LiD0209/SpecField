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



OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_051_100.json"

OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_051_100.md"

OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_051_100_simple.txt"

OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_051_100_partial_unsat_classification.json"

OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_051_100_partial_unsat_classification.md"





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

        51: {

            "status": "unsatisfied",

            "comment": "unspecified ClientId + clean_session=0 unspecified 0x02(Identifier rejected).",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2918",

                "wolfMQTT-master/src/mqtt_broker.c:2972",

                "wolfMQTT-master/src/mqtt_broker.c:3025",

            ],

            "category": "ClientIdrejectionunspecified",

            "risk_level": "high",

            "reason": "unspecifiedpath.",

        },

        52: {

            "status": "partially satisfied",

            "comment": "partialvalidationunspecified CONNACK.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2726",

                "wolfMQTT-master/src/mqtt_broker.c:2799",

                "wolfMQTT-master/src/mqtt_broker.c:2960",

                "wolfMQTT-master/src/mqtt_broker.c:2694",

            ],

            "category": "CONNECTunspecified",

            "risk_level": "medium",

            "reason": "decode unspecified",

        },

        53: {

            "status": "satisfied",

            "comment": "CONNECT validationunspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2918",

                "wolfMQTT-master/src/mqtt_broker.c:3025",

            ],

        },

        54: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3043",

                "wolfMQTT-master/src/mqtt_broker.c:3044",

                "wolfMQTT-master/src/mqtt_broker.c:3541",

                "wolfMQTT-master/src/mqtt_broker.c:3544",

            ],

        },

        55: {

            "status": "unsatisfied",

            "comment": "same as ID51:unspecified ClientId + clean_session=0 unspecified 0x02.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2918",

                "wolfMQTT-master/src/mqtt_broker.c:2972",

                "wolfMQTT-master/src/mqtt_broker.c:3025",

            ],

            "category": "ClientIdrejectionunspecified",

            "risk_level": "high",

            "reason": "Identifier rejected unspecified.",

        },

        56: {

            "status": "satisfied",

            "comment": "unspecified clean_session=0 connectionunspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2744",

                "wolfMQTT-master/src/mqtt_broker.c:2918",

                "wolfMQTT-master/src/mqtt_broker.c:3025",

            ],

        },

        57: {

            "status": "satisfied",

            "comment": "unspecified clean_session=1 connectionunspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2780",

                "wolfMQTT-master/src/mqtt_broker.c:2918",

                "wolfMQTT-master/src/mqtt_broker.c:3025",

            ],

        },

        58: {

            "status": "satisfied",

            "comment": "unspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2775",

                "wolfMQTT-master/src/mqtt_broker.c:2918",

                "wolfMQTT-master/src/mqtt_broker.c:3025",

            ],

        },

        59: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2713",

                "wolfMQTT-master/src/mqtt_broker.c:2726",

                "wolfMQTT-master/src/mqtt_broker.c:3025",

            ],

            "category": "ClientIdrejectionunspecified",

            "risk_level": "medium",

            "reason": "unspecified 0x02.",

        },

        60: {

            "status": "partially satisfied",

            "comment": "same as ID59:0x02 unspecifiedpartial ClientId rejectionpathunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2713",

                "wolfMQTT-master/src/mqtt_broker.c:2726",

                "wolfMQTT-master/src/mqtt_broker.c:3025",

            ],

            "category": "ClientIdrejectionunspecified",

            "risk_level": "medium",

            "reason": "rejectionunspecified.",

        },

        61: {

            "status": "satisfied",

            "comment": "serverunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2918",

                "wolfMQTT-master/src/mqtt_broker.c:3025",

            ],

        },

        62: {

            "status": "unsatisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:997",

                "wolfMQTT-master/src/mqtt_broker.c:2736",

                "wolfMQTT-master/src/mqtt_broker.c:2918",

            ],

            "category": "Protocol Levelvalidationunspecified",

            "risk_level": "high",

            "reason": "Unspecified reason.",

        },

        63: {

            "status": "partially satisfied",

            "comment": "unspecifiedexplicitvalidation bits7..1 unspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2917",

                "wolfMQTT-master/src/mqtt_packet.c:1176",

                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:370",

            ],

            "category": "CONNACK Flagsunspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        64: {

            "status": "satisfied",

            "comment": "Connect Flags unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:869",

                "wolfMQTT-master/src/mqtt_packet.c:873",

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1130",

            ],

        },

        65: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2726",

                "wolfMQTT-master/src/mqtt_broker.c:2799",

                "wolfMQTT-master/src/mqtt_broker.c:2960",

                "wolfMQTT-master/src/mqtt_broker.c:3025",

            ],

        },

        66: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2694",

                "wolfMQTT-master/src/mqtt_broker.c:2701",

                "wolfMQTT-master/src/mqtt_broker.c:3541",

                "wolfMQTT-master/src/mqtt_broker.c:3544",

            ],

            "category": "CONNECTunspecified",

            "risk_level": "medium",

            "reason": "unspecifiedmissingexplicit rule-level unspecified.",

        },

        67: {

            "status": "satisfied",

            "comment": "Remaining Length unspecified continuation bit.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:269",

                "wolfMQTT-master/src/mqtt_packet.c:272",

                "wolfMQTT-master/src/mqtt_packet.c:273",

            ],

        },

        68: {

            "status": "satisfied",

            "comment": "Remaining Length unspecified `(encodedByte & 128) != 0`.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:240",

                "wolfMQTT-master/src/mqtt_packet.c:245",

            ],

        },

        69: {

            "status": "satisfied",

            "comment": "unspecifiedprocessing.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3207",

                "wolfMQTT-master/src/mqtt_broker.c:3333",

                "wolfMQTT-master/src/mqtt_packet.c:1426",

            ],

        },

        70: {

            "status": "partially satisfied",

            "comment": "broker unspecified QoS0+dup=1.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3305",

                "wolfMQTT-master/src/mqtt_packet.c:1343",

            ],

            "category": "DUPunspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        71: {

            "status": "partially satisfied",

            "comment": "QoS1 unspecified duplicate.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3300",

                "wolfMQTT-master/src/mqtt_broker.c:3305",

                "wolfMQTT-master/src/mqtt_packet.c:1343",

            ],

            "category": "DUPunspecified",

            "risk_level": "medium",

            "reason": "missingunspecified.",

        },

        72: {

            "status": "partially satisfied",

            "comment": "QoS2 unspecifiedmandatory.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3300",

                "wolfMQTT-master/src/mqtt_broker.c:3305",

                "wolfMQTT-master/src/mqtt_packet.c:1343",

            ],

            "category": "DUPunspecified",

            "risk_level": "medium",

            "reason": "unspecifiedvalue.",

        },

        73: {

            "status": "partially satisfied",

            "comment": "QoS0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3305",

                "wolfMQTT-master/src/mqtt_packet.c:1343",

            ],

            "category": "DUPunspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        74: {

            "status": "partially satisfied",

            "comment": "Unspecified mandatory validation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1308",

                "wolfMQTT-master/src/mqtt_packet.c:1343",

                "wolfMQTT-master/src/mqtt_broker.c:3305",

            ],

            "category": "DUPunspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        75: {

            "status": "partially satisfied",

            "comment": "broker unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3207",

                "wolfMQTT-master/src/mqtt_broker.c:3305",

                "wolfMQTT-master/src/mqtt_broker.c:3315",

            ],

            "category": "DUPunspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        76: {

            "status": "unsatisfied",

            "comment": "not foundunspecifiedpath.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1343",

                "wolfMQTT-master/src/mqtt_broker.c:3305",

                "wolfMQTT-master/src/mqtt_client.c:2169",

            ],

            "category": "DUPunspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        77: {

            "status": "partially satisfied",

            "comment": "same as ID74:QoS0 DUP=0 unspecifiedmandatory.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1308",

                "wolfMQTT-master/src/mqtt_packet.c:1343",

                "wolfMQTT-master/src/mqtt_broker.c:3305",

            ],

            "category": "DUPunspecified",

            "risk_level": "medium",

            "reason": "missingunspecified.",

        },

        78: {

            "status": "unsatisfied",

            "comment": "same as ID76:Client/Server unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1343",

                "wolfMQTT-master/src/mqtt_broker.c:3305",

                "wolfMQTT-master/src/mqtt_client.c:2169",

            ],

            "category": "DUPunspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        79: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3207",

                "wolfMQTT-master/src/mqtt_broker.c:3305",

            ],

            "category": "DUPunspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        80: {

            "status": "satisfied",

            "comment": "Variable Byte Integer unspecified `encodedByte = X MOD 128`.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:269",

            ],

        },

        81: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:240",

            ],

        },

        82: {

            "status": "satisfied",

            "comment": "unspecified `encodedByte |= 128`.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:272",

                "wolfMQTT-master/src/mqtt_packet.c:273",

            ],

        },

        83: {

            "status": "unsatisfied",

            "comment": "unspecifiedvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:197",

                "wolfMQTT-master/src/mqtt_packet.c:202",

                "wolfMQTT-master/src/mqtt_broker.c:3570",

            ],

            "category": "Fixed Header Flagsvalidationunspecified",

            "risk_level": "high",

            "reason": "unspecifiedvalidation packet type,missing flags validunspecified.",

        },

        84: {

            "status": "unsatisfied",

            "comment": "Unspecified comment.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:197",

                "wolfMQTT-master/src/mqtt_packet.c:202",

                "wolfMQTT-master/src/mqtt_broker.c:3438",

            ],

            "category": "Fixed Header Flagsvalidationunspecified",

            "risk_level": "high",

            "reason": "missingunspecified.",

        },

        85: {

            "status": "unsatisfied",

            "comment": "same as ID84:unspecifiedprocessing.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:197",

                "wolfMQTT-master/src/mqtt_packet.c:202",

                "wolfMQTT-master/src/mqtt_broker.c:3438",

            ],

            "category": "Fixed Header Flagsvalidationunspecified",

            "risk_level": "high",

            "reason": "unspecifiedvalidation.",

        },

        86: {

            "status": "partially satisfied",

            "comment": "clientunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:888",

                "wolfMQTT-master/src/mqtt_client.c:2572",

                "wolfMQTT-master/src/mqtt_client.c:2641",

            ],

            "category": "KeepAliveclientunspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        87: {

            "status": "partially satisfied",

            "comment": "same as ID86:unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:888",

                "wolfMQTT-master/src/mqtt_client.c:2572",

                "wolfMQTT-master/src/mqtt_client.c:2641",

            ],

            "category": "KeepAliveclientunspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        88: {

            "status": "satisfied",

            "comment": "serverunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3607",

                "wolfMQTT-master/src/mqtt_broker.c:3611",

                "wolfMQTT-master/src/mqtt_broker.c:3624",

            ],

        },

        89: {

            "status": "satisfied",

            "comment": "Keep Alive unspecified).",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3608",

            ],

        },

        90: {

            "status": "satisfied",

            "comment": "unspecifieddisconnect.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3610",

                "wolfMQTT-master/src/mqtt_broker.c:3611",

                "wolfMQTT-master/src/mqtt_broker.c:3624",

            ],

        },

        91: {

            "status": "satisfied",

            "comment": "Keep Alive use 16 unspecified).",

            "evidence": [

                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:363",

                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:420",

                "wolfMQTT-master/src/mqtt_packet.c:1005",

            ],

        },

        92: {

            "status": "satisfied",

            "comment": "UTF-8 stringunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:361",

                "wolfMQTT-master/src/mqtt_packet.c:363",

                "wolfMQTT-master/src/mqtt_packet.c:370",

            ],

        },

        93: {

            "status": "satisfied",

            "comment": "Password unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:846",

                "wolfMQTT-master/src/mqtt_packet.c:941",

                "wolfMQTT-master/src/mqtt_packet.c:361",

            ],

        },

        94: {

            "status": "satisfied",

            "comment": "UTF-8 stringlengthunspecifiedboundaryvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:366",

                "wolfMQTT-master/src/mqtt_packet.c:367",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

        },

        95: {

            "status": "satisfied",

            "comment": "Will Message lengthunspecifiedlength.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:818",

                "wolfMQTT-master/src/mqtt_packet.c:934",

                "wolfMQTT-master/src/mqtt_packet.c:383",

            ],

        },

        96: {

            "status": "partially satisfied",

            "comment": "packet_id unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1309",

                "wolfMQTT-master/src/mqtt_packet.c:1363",

                "wolfMQTT-master/src/mqtt_client.c:2169",

                "wolfMQTT-master/src/mqtt_client.c:2288",

            ],

            "category": "Packet Identifierunspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        97: {

            "status": "satisfied",

            "comment": "PUBACK/PUBREC/PUBREL unspecified packet_id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3335",

                "wolfMQTT-master/src/mqtt_broker.c:3341",

                "wolfMQTT-master/src/mqtt_broker.c:3411",

                "wolfMQTT-master/src/mqtt_client.c:964",

            ],

        },

        98: {

            "status": "satisfied",

            "comment": "QoS0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1308",

                "wolfMQTT-master/src/mqtt_packet.c:1362",

                "wolfMQTT-master/src/mqtt_packet.c:1444",

            ],

        },

        99: {

            "status": "satisfied",

            "comment": "SUBACK/UNSUBACK unspecified SUBSCRIBE/UNSUBSCRIBE unspecified packet_id.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3111",

                "wolfMQTT-master/src/mqtt_broker.c:3161",

                "wolfMQTT-master/src/mqtt_packet.c:2623",

                "wolfMQTT-master/src/mqtt_packet.c:2319",

            ],

        },

        100: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3207",

                "wolfMQTT-master/src/mqtt_broker.c:3333",

                "wolfMQTT-master/src/mqtt_packet.c:1426",

            ],

        },

    }





def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:

    results: list[dict] = []

    for i, change in enumerate(changes, start=51):

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

        "scope": "source_changes_index_50_to_99",

        "display_scope": "051-100",

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

        "scope": "wolfMQTT-master 051-100 partial+unsatisfied",

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

        "# wolfMQTT-master 051-100 unsatisfied/partially satisfied category",

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

    changes = source.get("changes", [])[50:100]

    if len(changes) != 50:

        raise RuntimeError(f"Expected 50 items for 051-100, got {len(changes)}")



    mapping = rule_mapping()

    if sorted(mapping.keys()) != list(range(51, 101)):

        raise RuntimeError("Rule mapping must cover IDs 51..100")



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

