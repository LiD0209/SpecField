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



OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_251_300.json"

OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_251_300.md"

OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_251_300_simple.txt"

OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_251_300_partial_unsat_classification.json"

OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_251_300_partial_unsat_classification.md"





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

        251: {

            "status": "unsatisfied",

            "comment": "not foundunspecified Topic Filter medium U+0000 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

                "wolfMQTT-master/src/mqtt_packet.c:1877",

                "wolfMQTT-master/src/mqtt_broker.c:1464",

            ],

            "category": "UTF-8 unspecified",

            "risk_level": "high",

            "reason": "Topic Filter unspecified.",

        },

        252: {

            "status": "satisfied",

            "comment": "stringunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:285",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:366",

            ],

        },

        253: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2533",

                "wolfMQTT-master/src/mqtt_broker.c:2544",

                "wolfMQTT-master/src/mqtt_broker.c:2547",

            ],

        },

        254: {

            "status": "partially satisfied",

            "comment": "unspecified Topic Filter.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2572",

                "wolfMQTT-master/src/mqtt_broker.c:3066",

                "wolfMQTT-master/src/mqtt_broker.c:3087",

            ],

            "category": "unspecified",

            "risk_level": "medium",

            "reason": "unspecifiedprocessing.",

        },

        255: {

            "status": "partially satisfied",

            "comment": "SUBSCRIBE unspecified UTF-8 semanticvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1877",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

            "category": "UTF-8 semanticvalidationunspecified)",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        256: {

            "status": "partially satisfied",

            "comment": "UNSUBSCRIBE unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:2165",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

            "category": "UTF-8 semanticvalidationunspecified)",

            "risk_level": "high",

            "reason": "unspecified Topic Filter.",

        },

        257: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:1470",

                "wolfMQTT-master/src/mqtt_broker.c:1476",

                "wolfMQTT-master/src/mqtt_broker.c:1490",

            ],

        },

        258: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2528",

                "wolfMQTT-master/src/mqtt_broker.c:2529",

                "wolfMQTT-master/src/mqtt_broker.c:2530",

            ],

        },

        259: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2533",

                "wolfMQTT-master/src/mqtt_broker.c:2544",

                "wolfMQTT-master/src/mqtt_broker.c:2569",

            ],

        },

        260: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2534",

                "wolfMQTT-master/src/mqtt_broker.c:2535",

                "wolfMQTT-master/src/mqtt_broker.c:3066",

            ],

            "category": "Topic Filter unspecified",

            "risk_level": "medium",

            "reason": "unspecifiedmedium.",

        },

        261: {

            "status": "unsatisfied",

            "comment": "unspecifiedprocessing.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2537",

                "wolfMQTT-master/src/mqtt_broker.c:2541",

                "wolfMQTT-master/src/mqtt_broker.c:2543",

            ],

            "category": "Topic Filter unspecified",

            "risk_level": "high",

            "reason": "mayunspecified.",

        },

        262: {

            "status": "unsatisfied",

            "comment": "not found Topic Name unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1434",

                "wolfMQTT-master/src/mqtt_broker.c:3214",

                "wolfMQTT-master/src/mqtt_broker.c:3227",

            ],

            "category": "Topic Name unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        263: {

            "status": "unsatisfied",

            "comment": "unspecifiedrejectionvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:1434",

                "wolfMQTT-master/src/mqtt_broker.c:3233",

            ],

            "category": "UTF-8 unspecified",

            "risk_level": "high",

            "reason": "NUL unspecified.",

        },

        264: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:1434",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

            "category": "UTF-8 semanticvalidationunspecified)",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        265: {

            "status": "partially satisfied",

            "comment": "Topic Name unspecified UTF-8 semanticvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1434",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

            "category": "UTF-8 semanticvalidationunspecified)",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        266: {

            "status": "unsatisfied",

            "comment": "Topic Name unspecifiedrejection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:1434",

                "wolfMQTT-master/src/mqtt_broker.c:3239",

            ],

            "category": "UTF-8 unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        267: {

            "status": "satisfied",

            "comment": "Topic Name use 2 unspecifiedlengthfield(0..65535)unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:285",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

        },

        268: {

            "status": "satisfied",

            "comment": "encoding sideunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:361",

                "wolfMQTT-master/src/mqtt_packet.c:366",

                "wolfMQTT-master/src/mqtt_packet.c:367",

            ],

        },

        269: {

            "status": "partially satisfied",

            "comment": "Broker unspecifiedrejection Topic Name mediumunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3213",

                "wolfMQTT-master/src/mqtt_broker.c:3217",

                "wolfMQTT-master/src/mqtt_packet.c:1307",

            ],

            "category": "Topic Name unspecified",

            "risk_level": "medium",

            "reason": "unspecified Topic Name.",

        },

        270: {

            "status": "partially satisfied",

            "comment": "unspecifiedpathexplicitrejectionunspecified Topic Name.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3213",

                "wolfMQTT-master/src/mqtt_broker.c:3217",

                "wolfMQTT-master/src/mqtt_packet.c:1361",

            ],

            "category": "Topic Name unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        271: {

            "status": "unsatisfied",

            "comment": "unspecifiedvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1307",

                "wolfMQTT-master/src/mqtt_packet.c:1434",

                "wolfMQTT-master/src/mqtt_broker.c:3227",

            ],

            "category": "Topic Name unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        272: {

            "status": "unsatisfied",

            "comment": "not found Topic Name unspecifiedrejection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:1434",

                "wolfMQTT-master/src/mqtt_broker.c:3233",

            ],

            "category": "UTF-8 unspecified",

            "risk_level": "high",

            "reason": "stringunspecified.",

        },

        273: {

            "status": "satisfied",

            "comment": "Topic Name lengthunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:366",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

        },

        274: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2533",

                "wolfMQTT-master/src/mqtt_broker.c:2544",

                "wolfMQTT-master/src/mqtt_broker.c:2569",

            ],

        },

        275: {

            "status": "satisfied",

            "comment": "Broker unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3293",

                "wolfMQTT-master/src/mqtt_broker.c:3294",

                "wolfMQTT-master/src/mqtt_broker.c:3315",

            ],

        },

        276: {

            "status": "partially satisfied",

            "comment": "PUBLISH unspecified UTF-8 semanticvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1361",

                "wolfMQTT-master/src/mqtt_packet.c:1434",

                "wolfMQTT-master/src/mqtt_packet.c:338",

            ],

            "category": "UTF-8 semanticvalidationunspecified)",

            "risk_level": "high",

            "reason": "unspecified UTF-8 Topic Name.",

        },

        277: {

            "status": "partially satisfied",

            "comment": "unspecified Broker rejection Topic Name medium +/#,unspecifiedvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3213",

                "wolfMQTT-master/src/mqtt_broker.c:3217",

                "wolfMQTT-master/src/mqtt_packet.c:1307",

            ],

            "category": "Topic Name unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        278: {

            "status": "partially satisfied",

            "comment": "PUBLISH Topic Name unspecifiedsemanticvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1434",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

            "category": "UTF-8 semanticvalidationunspecified)",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        279: {

            "status": "satisfied",

            "comment": "PUBLISH unspecifiedprocessing Packet Identifier/unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1360",

                "wolfMQTT-master/src/mqtt_packet.c:1361",

                "wolfMQTT-master/src/mqtt_packet.c:1434",

            ],

        },

        280: {

            "status": "satisfied",

            "comment": "Topic Name unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2528",

                "wolfMQTT-master/src/mqtt_broker.c:2529",

                "wolfMQTT-master/src/mqtt_broker.c:2530",

            ],

        },

        281: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2533",

                "wolfMQTT-master/src/mqtt_broker.c:2544",

                "wolfMQTT-master/src/mqtt_broker.c:2569",

            ],

        },

        282: {

            "status": "partially satisfied",

            "comment": "CONNECT unspecifiedfield",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1142",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "CONNECT User Name Flag unspecified",

            "risk_level": "high",

            "reason": "mayunspecified.",

        },

        283: {

            "status": "partially satisfied",

            "comment": "same as ID282:unspecifiedrejection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1130",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "CONNECT User Name Flag unspecified",

            "risk_level": "high",

            "reason": "protocolunspecified.",

        },

        284: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1121",

                "wolfMQTT-master/src/mqtt_packet.c:1125",

            ],

        },

        285: {

            "status": "satisfied",

            "comment": "same as ID284:Flag=1 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1119",

                "wolfMQTT-master/src/mqtt_packet.c:1127",

            ],

        },

        286: {

            "status": "partially satisfied",

            "comment": "unspecifiedsemantic.",

            "evidence": [

                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:389",

                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:390",

                "wolfMQTT-master/src/mqtt_broker.c:2959",

            ],

            "category": "CONNECT unspecified",

            "risk_level": "medium",

            "reason": "errorunspecified.",

        },

        287: {

            "status": "partially satisfied",

            "comment": "User Name fieldunspecifiedvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1119",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

            "category": "UTF-8 semanticvalidationunspecified)",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        288: {

            "status": "satisfied",

            "comment": "CONNECT payloadunspecifiedmedium,User Name Flag=1 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1127",

                "wolfMQTT-master/src/mqtt_packet.c:1130",

            ],

        },

        289: {

            "status": "partially satisfied",

            "comment": "User Name unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1119",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

            "category": "UTF-8 semanticvalidationunspecified)",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        290: {

            "status": "unsatisfied",

            "comment": "not foundunspecified User Name medium U+0000 unspecifiedexplicitrejection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1119",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_broker.c:2860",

            ],

            "category": "UTF-8 unspecified",

            "risk_level": "high",

            "reason": "NUL mayunspecified.",

        },

        291: {

            "status": "satisfied",

            "comment": "User Name unspecifiedrange.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:285",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:1124",

            ],

        },

        292: {

            "status": "partially satisfied",

            "comment": "CONNECT medium User Name uselengthunspecifiedvalidation UTF-8 semanticvalidunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1119",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

            "category": "UTF-8 semanticvalidationunspecified)",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        293: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:774",

                "wolfMQTT-master/src/mqtt_packet.c:776",

                "wolfMQTT-master/src/mqtt_packet.c:1130",

            ],

            "category": "CONNECT User Name Flag unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        294: {

            "status": "partially satisfied",

            "comment": "unspecifiedpayload.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1142",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "CONNECT User Name Flag unspecified",

            "risk_level": "high",

            "reason": "Unspecified length equals remaining length behavior.",

        },

        295: {

            "status": "satisfied",

            "comment": "encoding sideunspecified User Name Flag=1.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:882",

                "wolfMQTT-master/src/mqtt_packet.c:883",

                "wolfMQTT-master/src/mqtt_packet.c:937",

            ],

        },

        296: {

            "status": "satisfied",

            "comment": "unspecifiedfield.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1119",

                "wolfMQTT-master/src/mqtt_packet.c:1127",

            ],

        },

        297: {

            "status": "partially satisfied",

            "comment": "DISCONNECT unspecifiedexplicitvalidation remaining length=0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:2446",

                "wolfMQTT-master/src/mqtt_packet.c:2492",

                "wolfMQTT-master/src/mqtt_broker.c:3579",

            ],

            "category": "unspecified",

            "risk_level": "medium",

            "reason": "protocolunspecified.",

        },

        298: {

            "status": "partially satisfied",

            "comment": "PINGREQ unspecified remaining length=0;broker receives PINGREQ unspecified/payload.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:2355",

                "wolfMQTT-master/src/mqtt_packet.c:2365",

                "wolfMQTT-master/src/mqtt_broker.c:3576",

            ],

            "category": "unspecified",

            "risk_level": "medium",

            "reason": "unspecifiedmissing strict format check.",

        },

        299: {

            "status": "partially satisfied",

            "comment": "PINGRESP unspecifiedvalidation remaining length unspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2591",

                "wolfMQTT-master/src/mqtt_broker.c:2592",

                "wolfMQTT-master/src/mqtt_packet.c:2389",

            ],

            "category": "unspecified",

            "risk_level": "medium",

            "reason": "unspecified PINGRESP.",

        },

        300: {

            "status": "partially satisfied",

            "comment": "Unspecified comment.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1000",

                "wolfMQTT-master/src/mqtt_broker.c:2789",

                "wolfMQTT-master/src/mqtt_broker.c:2845",

            ],

            "category": "Will Flag unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

    }





def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:

    results: list[dict] = []

    for i, change in enumerate(changes, start=251):

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

        "scope": "source_changes_index_250_to_299",

        "display_scope": "251-300",

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

        "scope": "wolfMQTT-master 251-300 partial+unsatisfied",

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

        "# wolfMQTT-master 251-300 unsatisfied/partially satisfied category",

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

    changes = source.get("changes", [])[250:300]

    if len(changes) != 50:

        raise RuntimeError(f"Expected 50 items for 251-300, got {len(changes)}")



    mapping = rule_mapping()

    if sorted(mapping.keys()) != list(range(251, 301)):

        raise RuntimeError("Rule mapping must cover IDs 251..300")



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



