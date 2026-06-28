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



OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_301_350.json"

OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_301_350.md"

OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_301_350_simple.txt"

OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_301_350_partial_unsat_classification.json"

OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_301_350_partial_unsat_classification.md"





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

        301: {

            "status": "satisfied",

            "comment": "Will Flag=0 unspecifieddecoding side `enable_lwt` unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:872",

                "wolfMQTT-master/src/mqtt_packet.c:873",

                "wolfMQTT-master/src/mqtt_packet.c:1000",

            ],

        },

        302: {

            "status": "satisfied",

            "comment": "Will Flag=1 unspecified LWT.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:872",

                "wolfMQTT-master/src/mqtt_packet.c:873",

                "wolfMQTT-master/src/mqtt_packet.c:1001",

            ],

        },

        303: {

            "status": "satisfied",

            "comment": "Will Flag=1 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1048",

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:1098",

            ],

        },

        304: {

            "status": "satisfied",

            "comment": "server CONNECT processingunspecified Will logic.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1001",

                "wolfMQTT-master/src/mqtt_broker.c:2739",

                "wolfMQTT-master/src/mqtt_broker.c:2789",

            ],

        },

        305: {

            "status": "partially satisfied",

            "comment": "Will Flag=0 unspecifiedvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1048",

                "wolfMQTT-master/src/mqtt_packet.c:1118",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "Will Flag=0 unspecified",

            "risk_level": "high",

            "reason": "mayunspecified.",

        },

        306: {

            "status": "partially satisfied",

            "comment": "same as ID305:missingunspecifiedexplicitrejection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1048",

                "wolfMQTT-master/src/mqtt_packet.c:1142",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "Will Flag=0 unspecified",

            "risk_level": "high",

            "reason": "protocolunspecified.",

        },

        307: {

            "status": "satisfied",

            "comment": "Will Flag=1 unspecifiederror.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1048",

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:1090",

            ],

        },

        308: {

            "status": "satisfied",

            "comment": "CONNECT unspecified Will Topic/Payload/QoS/Retain unspecifiedclientconnection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2789",

                "wolfMQTT-master/src/mqtt_broker.c:2833",

                "wolfMQTT-master/src/mqtt_broker.c:2845",

            ],

        },

        309: {

            "status": "satisfied",

            "comment": "receives DISCONNECT unspecifiedpublish.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:3579",

                "wolfMQTT-master/src/mqtt_broker.c:3580",

                "wolfMQTT-master/src/mqtt_broker.c:3588",

            ],

        },

        310: {

            "status": "satisfied",

            "comment": "Will publishunspecifiedclears;normal DISCONNECT unspecifiedclears.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2438",

                "wolfMQTT-master/src/mqtt_broker.c:2441",

                "wolfMQTT-master/src/mqtt_broker.c:3580",

            ],

        },

        311: {

            "status": "satisfied",

            "comment": "same as ID310,Will unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2012",

                "wolfMQTT-master/src/mqtt_broker.c:2417",

                "wolfMQTT-master/src/mqtt_broker.c:3580",

            ],

        },

        312: {

            "status": "satisfied",

            "comment": "Will Flag=1 unspecified CONNECT payloadmediumunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:1098",

                "wolfMQTT-master/src/mqtt_packet.c:1118",

            ],

        },

        313: {

            "status": "satisfied",

            "comment": "connectionunspecified(`bc->has_will=1`).",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2789",

                "wolfMQTT-master/src/mqtt_broker.c:2845",

                "wolfMQTT-master/src/mqtt_broker.c:3043",

            ],

        },

        314: {

            "status": "satisfied",

            "comment": "Will Flag=1 unspecified Will fieldpath.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1048",

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:1115",

            ],

        },

        315: {

            "status": "partially satisfied",

            "comment": "encoding sideunspecifiedvalidation Will Flag=0 unspecified 0.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:872",

                "wolfMQTT-master/src/mqtt_packet.c:875",

                "wolfMQTT-master/src/mqtt_packet.c:1053",

            ],

            "category": "Will QoS/Retain unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        316: {

            "status": "partially satisfied",

            "comment": "same as ID315:missingunspecifiedprotocolrejection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1000",

                "wolfMQTT-master/src/mqtt_packet.c:1053",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "Will QoS/Retain unspecified",

            "risk_level": "high",

            "reason": "flag bitsunspecified.",

        },

        317: {

            "status": "partially satisfied",

            "comment": "same as ID315/316:unspecifiedmandatoryvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1001",

                "wolfMQTT-master/src/mqtt_packet.c:1054",

                "wolfMQTT-master/src/mqtt_packet.c:1142",

            ],

            "category": "Will QoS/Retain unspecified",

            "risk_level": "high",

            "reason": "protocolunspecified.",

        },

        318: {

            "status": "unsatisfied",

            "comment": "not foundunspecified Will QoS=3(reserved value)unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1053",

                "wolfMQTT-master/src/mqtt_packet.c:1054",

                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:323",

            ],

            "category": "Will QoS validvaluevalidationunspecified",

            "risk_level": "high",

            "reason": "Will QoS reserved valuemayunspecifiedprocessingpath.",

        },

        319: {

            "status": "unsatisfied",

            "comment": "same as ID318:unspecified {0,1,2}.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1054",

                "wolfMQTT-master/src/mqtt_broker.c:2833",

                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:335",

            ],

            "category": "Will QoS validvaluevalidationunspecified",

            "risk_level": "high",

            "reason": "protocolreserved valueunspecified.",

        },

        320: {

            "status": "unsatisfied",

            "comment": "same as ID318/319:Will QoS=3 unspecifiederror.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1054",

                "wolfMQTT-master/src/mqtt_broker.c:2833",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "Will QoS validvaluevalidationunspecified",

            "risk_level": "high",

            "reason": "mayunspecified.",

        },

        321: {

            "status": "satisfied",

            "comment": "Will Flag=1 unspecifieduse.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1053",

                "wolfMQTT-master/src/mqtt_packet.c:1054",

                "wolfMQTT-master/src/mqtt_broker.c:2833",

            ],

        },

        322: {

            "status": "partially satisfied",

            "comment": "encoding sideunspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:872",

                "wolfMQTT-master/src/mqtt_packet.c:879",

                "wolfMQTT-master/src/mqtt_packet.c:1056",

            ],

            "category": "Will QoS/Retain unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        323: {

            "status": "partially satisfied",

            "comment": "same as ID322:Will Flag=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1000",

                "wolfMQTT-master/src/mqtt_packet.c:1056",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "Will QoS/Retain unspecified",

            "risk_level": "high",

            "reason": "protocolunspecified.",

        },

        324: {

            "status": "satisfied",

            "comment": "Will Retain=0 unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2453",

                "wolfMQTT-master/src/mqtt_broker.c:2454",

                "wolfMQTT-master/src/mqtt_broker.c:2490",

            ],

        },

        325: {

            "status": "satisfied",

            "comment": "Will Retain=1 unspecified retained processingpath(unspecified retained).",

            "evidence": [

                "wolfMQTT-master/src/mqtt_broker.c:2454",

                "wolfMQTT-master/src/mqtt_broker.c:2459",

                "wolfMQTT-master/src/mqtt_broker.c:2466",

            ],

        },

        326: {

            "status": "satisfied",

            "comment": "Will Retain unspecifiedconnectionstatus.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1056",

                "wolfMQTT-master/src/mqtt_broker.c:2834",

                "wolfMQTT-master/src/mqtt_broker.c:2848",

            ],

        },

        327: {

            "status": "partially satisfied",

            "comment": "Will Flag=0 unspecified Will topic payload.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1048",

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:1145",

            ],

            "category": "Will Flag=0 unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        328: {

            "status": "partially satisfied",

            "comment": "same as ID327:unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1000",

                "wolfMQTT-master/src/mqtt_packet.c:1048",

                "wolfMQTT-master/src/mqtt_packet.c:1142",

            ],

            "category": "Will Flag=0 unspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        329: {

            "status": "satisfied",

            "comment": "Will Flag=1 unspecified Will topic.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1048",

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:1096",

            ],

        },

        330: {

            "status": "partially satisfied",

            "comment": "Will topic unspecifiedvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

            "category": "Will topic UTF-8 semanticvalidationunspecified",

            "risk_level": "high",

            "reason": "unspecified malformed UTF-8 Will topic.",

        },

        331: {

            "status": "satisfied",

            "comment": "Will Flag=1 unspecified CONNECT medium Will unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:1098",

                "wolfMQTT-master/src/mqtt_packet.c:1118",

            ],

        },

        332: {

            "status": "satisfied",

            "comment": "Will Flag=1 unspecified Will topic field.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1048",

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:1090",

            ],

        },

        333: {

            "status": "partially satisfied",

            "comment": "Will topic unspecified.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:366",

            ],

            "category": "Will topic UTF-8 semanticvalidationunspecified",

            "risk_level": "high",

            "reason": "unspecifiedvalidation.",

        },

        334: {

            "status": "partially satisfied",

            "comment": "same as ID330/333:Will topic unspecifiedsemanticvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

            "category": "Will topic UTF-8 semanticvalidationunspecified",

            "risk_level": "high",

            "reason": "unspecified.",

        },

        335: {

            "status": "unsatisfied",

            "comment": "not foundunspecified Will topic medium U+0000 unspecifiedexplicitrejection.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:1087",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_broker.c:2803",

            ],

            "category": "Will topic unspecified(U+0000)",

            "risk_level": "high",

            "reason": "NUL unspecified.",

        },

        336: {

            "status": "satisfied",

            "comment": "Will topic stringlengthunspecifiedboundaryvalidation.",

            "evidence": [

                "wolfMQTT-master/src/mqtt_packet.c:285",

                "wolfMQTT-master/src/mqtt_packet.c:338",

                "wolfMQTT-master/src/mqtt_packet.c:346",

            ],

        },

    }





def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:

    results: list[dict] = []

    for i, change in enumerate(changes, start=301):

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

        "scope": "source_changes_index_300_to_335",

        "display_scope": "301-336",

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

        "scope": "wolfMQTT-master 301-336 partial+unsatisfied",

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

        "# wolfMQTT-master 301-336 unsatisfied/partially satisfied category",

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

    changes = source.get("changes", [])[300:]



    mapping = rule_mapping()

    if len(changes) != len(mapping):

        raise RuntimeError(

            f"Expected {len(mapping)} items for 301..{300+len(mapping)}, got {len(changes)}"

        )

    if sorted(mapping.keys()) != list(range(301, 301 + len(mapping))):

        raise RuntimeError("Rule mapping keys are not continuous from 301")



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



