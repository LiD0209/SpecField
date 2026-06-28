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



OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_151_200.json"

OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_151_200.md"

OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_151_200_simple.txt"

OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_151_200_partial_unsat_classification.json"

OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_151_200_partial_unsat_classification.md"





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

        151: {

            "status": "unsatisfied",

            "comment": "UNSUBSCRIBE unspecified payload(topic_count=0),unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:2091",

                "wolfMQTT-master/src/mqtt_packet.c:2154",

                "wolfMQTT-master/src/mqtt_packet.c:2181",

                "wolfMQTT-master/src/mqtt_broker.c:3141",

            ],

            "category": "SUBSCRIBE/UNSUBSCRIBE unspecified",

            "risk_level": "high",

            "reason": "protocolunspecifiedpayload.",

        },

        152: {

            "status": "unsatisfied",

            "comment": "Broker unspecifiedvalidation Remaining Length/payload unspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3509",

                "wolfMQTT-master/src/mqtt_broker.c:3579",

                "wolfMQTT-master/src/mqtt_broker.c:3588",

            ],

            "category": "PINGREQ/DISCONNECT unspecified",

            "risk_level": "high",

            "reason": "unspecifiedvalidation.",

        },

        153: {

            "status": "unsatisfied",

            "comment": "Broker unspecifiedvalidation Remaining Length unspecified PINGRESP.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3509",

                "wolfMQTT-master/src/mqtt_broker.c:3576",

                "wolfMQTT-master/src/mqtt_broker.c:2591",

            ],

            "category": "PINGREQ/DISCONNECT unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        154: {

            "status": "partially satisfied",

            "comment": "unspecifiedmandatory remain_len=0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2591",

                "wolfMQTT-master/src/mqtt_broker.c:2592",

                "wolfMQTT-master/src/mqtt_packet.c:2389",

                "wolfMQTT-master/src/mqtt_packet.c:2400",

            ],

            "category": "unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        155: {

            "status": "partially satisfied",

            "comment": "PUBCOMP unspecified packet id(remain_len=2);unspecified 2.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1533",

                "wolfMQTT-master/src/mqtt_packet.c:1563",

                "wolfMQTT-master/src/mqtt_packet.c:1632",

                "wolfMQTT-master/src/mqtt_broker.c:3390",

            ],

            "category": "ACK unspecified",

            "risk_level": "medium",

            "reason": "unspecifiedvalidation.",

        },

        156: {

            "status": "partially satisfied",

            "comment": "PUBREL unspecified packet id(remain_len=2);unspecified 2.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1533",

                "wolfMQTT-master/src/mqtt_packet.c:1563",

                "wolfMQTT-master/src/mqtt_packet.c:1632",

                "wolfMQTT-master/src/mqtt_broker.c:3426",

            ],

            "category": "ACK unspecified",

            "risk_level": "medium",

            "reason": "unspecifiedvalidation.",

        },

        157: {

            "status": "satisfied",

            "comment": "UNSUBACK unspecified payload.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:2280",

                "wolfMQTT-master/src/mqtt_packet.c:2308",

                "wolfMQTT-master/src/mqtt_packet.c:2319",

            ],

        },

        158: {

            "status": "unsatisfied",

            "comment": "SUBSCRIBE unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1865",

                "wolfMQTT-master/src/mqtt_packet.c:1898",

                "wolfMQTT-master/src/mqtt_broker.c:3066",

                "wolfMQTT-master/src/mqtt_broker.c:3111",

            ],

            "category": "SUBSCRIBE/UNSUBSCRIBE unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        159: {

            "status": "satisfied",

            "comment": "PUBLISH payload lengthunspecified variable header lengthunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1497",

                "wolfMQTT-master/src/mqtt_packet.c:1500",

                "wolfMQTT-master/src/mqtt_packet.c:1505",

            ],

        },

        160: {

            "status": "satisfied",

            "comment": "RETAIN=1 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3251",

                "wolfMQTT-master/src/mqtt_broker.c:3252",

                "wolfMQTT-master/src/mqtt_broker.c:3267",

            ],

        },

        161: {

            "status": "satisfied",

            "comment": "retained + payload=0 => unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3252",

                "wolfMQTT-master/src/mqtt_broker.c:3253",

                "wolfMQTT-master/src/mqtt_broker.c:2456",

            ],

        },

        162: {

            "status": "partially satisfied",

            "comment": "PUBACK unspecified payload;decoding sideunspecifiedvalidation remain_len>=2,unspecifiedvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1533",

                "wolfMQTT-master/src/mqtt_packet.c:1632",

                "wolfMQTT-master/src/mqtt_broker.c:3342",

            ],

            "category": "ACK unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        163: {

            "status": "partially satisfied",

            "comment": "PUBREC unspecified payload;decoding sideunspecifiedvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1533",

                "wolfMQTT-master/src/mqtt_packet.c:1632",

                "wolfMQTT-master/src/mqtt_broker.c:3343",

            ],

            "category": "ACK unspecified",

            "risk_level": "medium",

            "reason": "Unspecified reason.",

        },

        164: {

            "status": "satisfied",

            "comment": "PUBLISH payload unspecifiedboundaryprocessing.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1500",

                "wolfMQTT-master/src/mqtt_packet.c:1505",

                "wolfMQTT-master/src/mqtt_broker.c:3278",

            ],

        },

        165: {

            "status": "partially satisfied",

            "comment": "encoding sidesatisfied QoS>0 unspecifiedvalidation packet id unspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1308",

                "wolfMQTT-master/src/mqtt_packet.c:1309",

                "wolfMQTT-master/src/mqtt_packet.c:1362",

                "wolfMQTT-master/src/mqtt_packet.c:1443",

                "wolfMQTT-master/src/mqtt_packet.c:1449",

            ],

            "category": "QoS unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        166: {

            "status": "satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3299",

                "wolfMQTT-master/src/mqtt_broker.c:3300",

                "wolfMQTT-master/src/mqtt_broker.c:2488",

            ],

        },

        167: {

            "status": "unsatisfied",

            "comment": "unspecifiedpath.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:1397",

                "wolfMQTT-master/src/mqtt_broker.c:3497",

                "wolfMQTT-master/src/mqtt_client.c:3031",

                "wolfMQTT-master/src/mqtt_client.c:3042",

            ],

            "category": "CleanSession=0 unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        168: {

            "status": "satisfied",

            "comment": "QoS0 unspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3299",

                "wolfMQTT-master/src/mqtt_broker.c:3300",

            ],

        },

        169: {

            "status": "partially satisfied",

            "comment": "QoS1 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1343",

                "wolfMQTT-master/src/mqtt_broker.c:3299",

                "wolfMQTT-master/src/mqtt_broker.c:3080",

            ],

            "category": "QoS unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        170: {

            "status": "partially satisfied",

            "comment": "QoS2 unspecifiedrejection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1343",

                "wolfMQTT-master/src/mqtt_broker.c:3299",

                "wolfMQTT-master/src/mqtt_broker.c:3080",

            ],

            "category": "QoS unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        171: {

            "status": "partially satisfied",

            "comment": "QoS unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1308",

                "wolfMQTT-master/src/mqtt_packet.c:1362",

                "wolfMQTT-master/src/mqtt_packet.c:1443",

                "wolfMQTT-master/src/mqtt_packet.c:1449",

            ],

            "category": "QoS unspecified",

            "risk_level": "high",

            "reason": "decoding sideunspecifiedrejection QoS>0 + packet_id=0.",

        },

        172: {

            "status": "partially satisfied",

            "comment": "QoS>0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1309",

                "wolfMQTT-master/src/mqtt_packet.c:1443",

                "wolfMQTT-master/src/mqtt_packet.c:1449",

            ],

            "category": "QoS unspecified",

            "risk_level": "high",

            "reason": "unspecifiedvalidation.",

        },

        173: {

            "status": "satisfied",

            "comment": "unspecified).",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3299",

                "wolfMQTT-master/src/mqtt_broker.c:2488",

            ],

        },

        174: {

            "status": "satisfied",

            "comment": "SUBACK unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3073",

                "wolfMQTT-master/src/mqtt_broker.c:3080",

                "wolfMQTT-master/src/mqtt_broker.c:3106",

                "wolfMQTT-master/src/mqtt_broker.c:3111",

            ],

        },

        175: {

            "status": "partially satisfied",

            "comment": "unspecifiedlogic.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:1470",

                "wolfMQTT-master/src/mqtt_broker.c:1478",

                "wolfMQTT-master/src/mqtt_broker.c:3291",

                "wolfMQTT-master/src/mqtt_broker.c:3299",

            ],

            "category": "unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        176: {

            "status": "unsatisfied",

            "comment": "clean_session=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3497",

                "wolfMQTT-master/src/mqtt_broker.c:3581",

                "wolfMQTT-master/src/mqtt_client.c:3031",

            ],

            "category": "CleanSession=0 unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        177: {

            "status": "partially satisfied",

            "comment": "QoS0 + DUP unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1343",

                "wolfMQTT-master/src/mqtt_broker.c:3305",

            ],

            "category": "QoS unspecified",

            "risk_level": "medium",

            "reason": "missingunspecifiedvalidation.",

        },

        178: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3299",

                "wolfMQTT-master/src/mqtt_packet.c:1343",

            ],

            "category": "QoS unspecified",

            "risk_level": "medium",

            "reason": "unspecifiedmandatory.",

        },

        179: {

            "status": "unsatisfied",

            "comment": "SUBSCRIBE unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1890",

                "wolfMQTT-master/src/mqtt_broker.c:3080",

                "wolfMQTT-master/src/mqtt_broker.c:3083",

            ],

            "category": "SUBSCRIBE Requested QoS/unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        180: {

            "status": "unsatisfied",

            "comment": "SUBSCRIBE mediumunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1890",

                "wolfMQTT-master/src/mqtt_broker.c:3080",

                "wolfMQTT-master/src/mqtt_broker.c:3570",

            ],

            "category": "SUBSCRIBE Requested QoS/unspecified",

            "risk_level": "high",

            "reason": "missing invalid->disconnect unspecified.",

        },

        181: {

            "status": "satisfied",

            "comment": "unspecified:QoS1->PUBACK,QoS2->PUBREC,QoS0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3333",

                "wolfMQTT-master/src/mqtt_broker.c:3342",

                "wolfMQTT-master/src/mqtt_broker.c:3343",

            ],

        },

        182: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:1478",

                "wolfMQTT-master/src/mqtt_broker.c:3291",

                "wolfMQTT-master/src/mqtt_broker.c:3299",

            ],

            "category": "unspecified",

            "risk_level": "medium",

            "reason": "unspecified.",

        },

        183: {

            "status": "unsatisfied",

            "comment": "unspecified PUBLISH QoS bits=11 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:204",

                "wolfMQTT-master/src/mqtt_broker.c:3207",

                "wolfMQTT-master/src/mqtt_broker.c:3333",

            ],

            "category": "PUBLISH QoS bits unspecified",

            "risk_level": "high",

            "reason": "QoS=3 unspecifiedprocessingpath.",

        },

        184: {

            "status": "unsatisfied",

            "comment": "PUBLISH unspecifiedrejection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:204",

                "wolfMQTT-master/src/mqtt_packet.c:1426",

            ],

            "category": "PUBLISH QoS bits unspecified",

            "risk_level": "high",

            "reason": "unspecifiedvalidation qos bits validunspecified.",

        },

        185: {

            "status": "unsatisfied",

            "comment": "same as ID183:receives QoS bits=11 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:204",

                "wolfMQTT-master/src/mqtt_broker.c:3537",

                "wolfMQTT-master/src/mqtt_broker.c:3550",

            ],

            "category": "PUBLISH QoS bits unspecified",

            "risk_level": "high",

            "reason": "missingprotocolunspecified.",

        },

        186: {

            "status": "unsatisfied",

            "comment": "same as ID184:forbidden QoS bits unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:204",

                "wolfMQTT-master/src/mqtt_packet.c:1426",

            ],

            "category": "PUBLISH QoS bits unspecified",

            "risk_level": "high",

            "reason": "missing QoS bits=3 unspecifiedrejectionlogic.",

        },

        187: {

            "status": "satisfied",

            "comment": "Remaining Length unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:264",

                "wolfMQTT-master/src/mqtt_packet.c:236",

                "wolfMQTT-master/src/mqtt_packet.c:2957",

            ],

        },

        188: {

            "status": "partially satisfied",

            "comment": "unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:2984",

                "wolfMQTT-master/src/mqtt_packet.c:2991",

                "wolfMQTT-master/src/mqtt_packet.c:2992",

                "wolfMQTT-master/src/mqtt_packet.c:3012",

            ],

            "category": "Remaining Length unspecified",

            "risk_level": "medium",

            "reason": "unspecified",

        },

        189: {

            "status": "satisfied",

            "comment": "CONNECT unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:782",

                "wolfMQTT-master/src/mqtt_packet.c:804",

                "wolfMQTT-master/src/mqtt_packet.c:846",

                "wolfMQTT-master/src/mqtt_packet.c:851",

            ],

        },

        190: {

            "status": "satisfied",

            "comment": "PUBLISH payload lengthunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1497",

                "wolfMQTT-master/src/mqtt_packet.c:1500",

            ],

        },

        191: {

            "status": "satisfied",

            "comment": "PUBACK unspecifiedpath Remaining Length unspecified 2.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1533",

                "wolfMQTT-master/src/mqtt_broker.c:3342",

            ],

        },

        192: {

            "status": "satisfied",

            "comment": "PUBREC unspecifiedpath Remaining Length unspecified 2.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1533",

                "wolfMQTT-master/src/mqtt_broker.c:3343",

            ],

        },

        193: {

            "status": "satisfied",

            "comment": "Remaining Length unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:231",

                "wolfMQTT-master/src/mqtt_packet.c:241",

                "wolfMQTT-master/src/mqtt_packet.c:245",

            ],

        },

        194: {

            "status": "unsatisfied",

            "comment": "Requested QoS unspecified).",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1890",

                "wolfMQTT-master/src/mqtt_broker.c:3080",

            ],

            "category": "SUBSCRIBE Requested QoS/unspecified",

            "risk_level": "high",

            "reason": "unspecifiedvalidation.",

        },

        195: {

            "status": "unsatisfied",

            "comment": "Requested QoS unspecifiedprotocolerrordisconnectconnection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1890",

                "wolfMQTT-master/src/mqtt_broker.c:3080",

                "wolfMQTT-master/src/mqtt_broker.c:3570",

            ],

            "category": "SUBSCRIBE Requested QoS/unspecified",

            "risk_level": "high",

            "reason": "invalid unspecifiedprocessing.",

        },

        196: {

            "status": "partially satisfied",

            "comment": "serverunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3080",

                "wolfMQTT-master/src/mqtt_broker.c:3083",

                "wolfMQTT-master/src/mqtt_broker.c:3089",

                "wolfMQTT-master/src/mqtt_broker.c:3106",

            ],

            "category": "unspecified",

            "risk_level": "medium",

            "reason": "missingunspecified.",

        },

        197: {

            "status": "unsatisfied",

            "comment": "unspecifiedvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:198",

                "wolfMQTT-master/src/mqtt_packet.c:202",

                "wolfMQTT-master/src/mqtt_packet.c:204",

            ],

            "category": "Fixed Header Reserved bits validationunspecified",

            "risk_level": "high",

            "reason": "unspecifiedvalidation packet type,unspecifiedvalidation flags validunspecified.",

        },

        198: {

            "status": "unsatisfied",

            "comment": "DISCONNECT reserved bits unspecifiedexplicit invalid->disconnect validationunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:202",

                "wolfMQTT-master/src/mqtt_broker.c:3579",

                "wolfMQTT-master/src/mqtt_broker.c:3588",

            ],

            "category": "Fixed Header Reserved bits validationunspecified",

            "risk_level": "high",

            "reason": "unspecifiedvalidation.",

        },

        199: {

            "status": "unsatisfied",

            "comment": "SUBSCRIBE unspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1889",

                "wolfMQTT-master/src/mqtt_packet.c:1890",

            ],

            "category": "SUBSCRIBE Requested QoS/unspecified",

            "risk_level": "high",

            "reason": "unspecified QoS.",

        },

        200: {

            "status": "unsatisfied",

            "comment": "reserved bits unspecified invalid->disconnect processing.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:198",

                "wolfMQTT-master/src/mqtt_packet.c:202",

                "wolfMQTT-master/src/mqtt_broker.c:3537",

            ],

            "category": "Fixed Header Reserved bits validationunspecified",

            "risk_level": "high",

            "reason": "protocolunspecified.",

        },

    }





def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:

    results: list[dict] = []

    for i, change in enumerate(changes, start=151):

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

        "scope": "source_changes_index_150_to_199",

        "display_scope": "151-200",

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

        "scope": "wolfMQTT-master 151-200 partial+unsatisfied",

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

        "# wolfMQTT-master 151-200 unsatisfied/partially satisfied category",

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

    changes = source.get("changes", [])[150:200]

    if len(changes) != 50:

        raise RuntimeError(f"Expected 50 items for 151-200, got {len(changes)}")



    mapping = rule_mapping()

    if sorted(mapping.keys()) != list(range(151, 201)):

        raise RuntimeError("Rule mapping must cover IDs 151..200")



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

