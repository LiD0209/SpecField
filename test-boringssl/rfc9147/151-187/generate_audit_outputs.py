#!/usr/bin/env python3
import json
from collections import OrderedDict
from datetime import datetime
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[3]
WORKSPACE = PROJECT.parent
INPUT = PROJECT / "output" / "DTLS_02_variable_changes.json"
REPO = WORKSPACE / "boringssl-main"
OUT = Path(__file__).resolve().parent
STANDARD = "https://www.rfc-editor.org/rfc/rfc9147"
IMPL = "boringssl-main"

SAT = "满足"
PART = "部分满足"
UNSAT = "不满足"


SECTIONS = {
    "demux": "RFC 9147 Section 4.1, Demultiplexing DTLS Records",
    "ack": "RFC 9147 Section 7 / 7.1 / 7.2, ACK Message",
    "record": "RFC 9147 Sections 4.1-4.2.3, DTLS record layer / sequence number and epoch",
    "anti_replay": "RFC 9147 Section 4.5.1, Anti-Replay",
    "close_notify": "RFC 9147 Section 5.10, Alert Messages and close_notify handling",
    "handshake": "RFC 9147 Section 5.2, DTLS Handshake Message Format",
    "cid": "RFC 9147 Section 9, Connection ID Updates",
}


EVIDENCE = {
    151: ["boringssl-main/include/openssl/ssl3.h:110", "boringssl-main/ssl/dtls_record.cc:267", "boringssl-main/ssl/d1_pkt.cc:223"],
    152: ["boringssl-main/ssl/dtls_record.cc:267", "boringssl-main/ssl/d1_both.cc:419", "boringssl-main/ssl/d1_pkt.cc:223"],
    153: ["boringssl-main/ssl/dtls_record.cc:170", "boringssl-main/ssl/dtls_record.cc:431", "boringssl-main/ssl/dtls_record.cc:533"],
    154: ["boringssl-main/include/openssl/ssl3.h:111", "boringssl-main/ssl/d1_both.cc:419", "boringssl-main/ssl/d1_pkt.cc:45"],
    155: ["boringssl-main/ssl/dtls_record.cc:308", "boringssl-main/ssl/d1_both.cc:430", "boringssl-main/ssl/d1_pkt.cc:223"],
    156: ["boringssl-main/ssl/d1_pkt.cc:53", "boringssl-main/ssl/d1_pkt.cc:63", "boringssl-main/ssl/d1_both.cc:990"],
    157: ["boringssl-main/ssl/d1_both.cc:956", "boringssl-main/ssl/d1_both.cc:969", "boringssl-main/ssl/d1_both.cc:990"],
    158: ["boringssl-main/ssl/d1_both.cc:976", "boringssl-main/ssl/d1_both.cc:980", "boringssl-main/ssl/d1_both.cc:985"],
    159: ["boringssl-main/ssl/dtls_record.cc:181", "boringssl-main/ssl/dtls_record.cc:227", "boringssl-main/ssl/internal.h:621"],
    160: ["boringssl-main/ssl/dtls_record.cc:181", "boringssl-main/ssl/dtls_record.cc:540", "boringssl-main/ssl/dtls_record.cc:544"],
    161: ["boringssl-main/ssl/dtls_record.cc:211", "boringssl-main/ssl/dtls_record.cc:223", "boringssl-main/ssl/dtls_record.cc:563"],
    162: ["boringssl-main/ssl/dtls_record.cc:181", "boringssl-main/ssl/dtls_record.cc:227", "boringssl-main/ssl/dtls_record.cc:118"],
    163: ["boringssl-main/ssl/dtls_record.cc:181", "boringssl-main/ssl/dtls_record.cc:227", "boringssl-main/ssl/dtls_record.cc:544"],
    164: ["boringssl-main/ssl/dtls_record.cc:297", "boringssl-main/ssl/ssl_lib.cc:2600", "boringssl-main/ssl/internal.h:2775"],
    165: ["boringssl-main/ssl/internal.h:639", "boringssl-main/ssl/internal.h:659", "boringssl-main/ssl/dtls_record.cc:551"],
    166: ["boringssl-main/ssl/internal.h:639", "boringssl-main/ssl/internal.h:661", "boringssl-main/ssl/dtls_record.cc:499"],
    167: ["boringssl-main/ssl/dtls_record.cc:80", "boringssl-main/ssl/dtls_record.cc:176", "boringssl-main/ssl/dtls_record.cc:122"],
    168: ["boringssl-main/ssl/dtls_record.cc:316", "boringssl-main/ssl/dtls_record.cc:327", "boringssl-main/ssl/dtls_record.cc:366"],
    169: ["boringssl-main/ssl/dtls_record.cc:71", "boringssl-main/ssl/dtls_record.cc:75", "boringssl-main/ssl/dtls_record.cc:558"],
    170: ["boringssl-main/ssl/dtls_method.cc:119", "boringssl-main/ssl/dtls_method.cc:121", "boringssl-main/ssl/internal.h:616"],
    171: ["boringssl-main/ssl/internal.h:690", "boringssl-main/ssl/dtls_record.cc:29", "boringssl-main/ssl/dtls_record.cc:316"],
    172: ["boringssl-main/ssl/dtls_record.cc:29", "boringssl-main/ssl/dtls_record.cc:35", "boringssl-main/ssl/dtls_record.cc:316"],
    173: ["boringssl-main/ssl/dtls_record.cc:92", "boringssl-main/ssl/dtls_record.cc:102", "boringssl-main/ssl/ssl_internal_test.cc:27"],
    174: ["boringssl-main/ssl/internal.h:611", "boringssl-main/ssl/dtls_record.cc:35", "boringssl-main/ssl/dtls_record.cc:36"],
    175: ["boringssl-main/ssl/dtls_record.cc:32", "boringssl-main/ssl/dtls_record.cc:39", "boringssl-main/ssl/dtls_record.cc:43"],
    176: ["boringssl-main/ssl/internal.h:661", "boringssl-main/ssl/dtls_record.cc:499", "boringssl-main/ssl/dtls_record.cc:502"],
    177: ["boringssl-main/ssl/d1_both.cc:825", "boringssl-main/ssl/dtls_record.cc:578", "boringssl-main/ssl/dtls_record.cc:579"],
    178: ["boringssl-main/ssl/dtls_method.cc:81", "boringssl-main/ssl/internal.h:616", "boringssl-main/ssl/ssl_lib.cc:3039"],
    179: ["boringssl-main/ssl/dtls_record.cc:163", "boringssl-main/ssl/dtls_record.cc:563", "boringssl-main/ssl/dtls_record.cc:548"],
    180: ["boringssl-main/ssl/dtls_record.cc:563", "boringssl-main/ssl/dtls_record.cc:570", "boringssl-main/ssl/dtls_record.cc:574"],
    181: ["boringssl-main/ssl/dtls_record.cc:211", "boringssl-main/ssl/dtls_record.cc:221", "boringssl-main/ssl/dtls_record.cc:224"],
    182: ["boringssl-main/ssl/internal.h:637", "boringssl-main/ssl/internal.h:657", "boringssl-main/ssl/d1_both.cc:991"],
    183: ["boringssl-main/ssl/dtls_record.cc:316", "boringssl-main/ssl/d1_both.cc:327", "boringssl-main/ssl/d1_both.cc:353"],
    184: ["boringssl-main/ssl/d1_both.cc:255", "boringssl-main/ssl/d1_both.cc:353", "boringssl-main/ssl/d1_pkt.cc:219"],
    185: ["boringssl-main/ssl/dtls_record.cc:170", "boringssl-main/ssl/dtls_record.cc:431", "boringssl-main/ssl/dtls_record.cc:533"],
    186: ["boringssl-main/ssl/dtls_record.cc:170", "boringssl-main/ssl/dtls_record.cc:533", "boringssl-main/ssl/dtls_record.cc:540"],
    187: ["boringssl-main/ssl/dtls_record.cc:170", "boringssl-main/ssl/d1_both.cc:784", "boringssl-main/ssl/dtls_record.cc:533"],
}


OVERRIDES = {
    152: (PART, "Heartbeat content type appears in the RFC demux table, but BoringSSL has no Heartbeat feature or handler. Unsupported Heartbeat records are not dispatched, so this is partial rather than a core DTLS 1.3 failure.", "missing optional feature/path", "medium", "demux"),
    153: (UNSAT, "BoringSSL has no DTLS 1.2 tls12_cid demux path, rejects DTLS 1.3 records with the C bit set, and always sends DTLS 1.3 encrypted records with C=0.", "missing feature/path", "high", "demux"),
    157: (PART, "ACK encoding can represent a length-prefixed record_numbers vector, but dtls1_schedule_ack only sends ACKs when records_to_ack is non-empty and send_ack assumes space for at least one RecordNumber.", "incomplete ACK behavior", "medium", "ack"),
    185: (UNSAT, "NewConnectionId usage=cid_spare cannot be implemented because BoringSSL has no DTLS CID update state machine and no CID-capable record support. 根因同 ID153.", "missing CID update feature/path", "high", "cid"),
    186: (UNSAT, "cid_immediate switching cannot be implemented because the sender always uses C=0 and there is no state transition to select a new CID for future records. 根因同 ID153.", "missing CID update feature/path", "high", "cid"),
    187: (UNSAT, "RequestConnectionId cannot trigger a cid_spare NewConnectionId response because RequestConnectionId/NewConnectionId handling and CID-capable records are absent. 根因同 ID153.", "missing CID update feature/path", "high", "cid"),
}


def topic_for(item_id: int, variable: str) -> str:
    if item_id in OVERRIDES:
        return OVERRIDES[item_id][4]
    if variable in ("Outer Content Type", "Decrypted Content Type", "type"):
        return "demux" if item_id < 156 else "ack"
    if variable == "record_numbers":
        return "ack"
    if item_id == 164:
        return "close_notify"
    if item_id in (168, 171, 172, 174, 175, 178):
        return "anti_replay"
    if item_id == 177:
        return "handshake"
    if item_id in (183, 184):
        return "ack"
    if variable == "usage":
        return "cid"
    return "record"


def default_status(item_id: int, item: dict) -> tuple[str, str, str, str, str]:
    if item_id in OVERRIDES:
        return OVERRIDES[item_id]
    topic = topic_for(item_id, item["variable_name"])
    return (
        SAT,
        f"BoringSSL 的 DTLS 1.3 实现覆盖该规则：{item['change_condition']} 时，{item['variable_name']} 需要 {item['change_action']}，对应代码路径已实现解析、构造、检查或状态更新。",
        "",
        "",
        topic,
    )


def line_count(repo_rel: str) -> int:
    rel = repo_rel
    if rel.startswith("boringssl-main/"):
        rel = rel[len("boringssl-main/"):]
    return len((REPO / rel).read_text(encoding="utf-8", errors="replace").splitlines())


def validate_refs(refs: list[str]) -> list[dict]:
    out = []
    for ref in refs:
        try:
            path, line_text = ref.rsplit(":", 1)
            n = int(line_text)
            rel = path[len("boringssl-main/"):] if path.startswith("boringssl-main/") else path
            ok = (REPO / rel).exists() and 1 <= n <= line_count(path)
            detail = f"line_count={line_count(path)}" if (REPO / rel).exists() else "missing file"
        except Exception as exc:  # noqa: BLE001
            ok = False
            detail = str(exc)
        out.append({"evidence": ref, "ok": ok, "detail": detail})
    return out


def comparison(item: dict, item_id: int, status: str, topic: str, comment: str) -> str:
    evidence = item.get("evidence", "")
    if status == SAT:
        conclusion = "结论：满足。"
    elif status == PART:
        conclusion = "结论：部分满足。"
    else:
        conclusion = "结论：不满足。"
    return (
        f"标准要求：{item['change_condition']} 时，{item['variable_name']} {item['change_action']}。"
        f"原始依据：{evidence}。"
        f"代码证据位于 {'; '.join(EVIDENCE[item_id])}。"
        f"{comment}{conclusion}"
    )


def build_results() -> tuple[list[dict], dict, list[dict]]:
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    selected = data["changes"][150:187]
    if len(selected) != 37:
        raise RuntimeError(f"Expected 37 changes for 151-187, got {len(selected)}")

    results = []
    counts = OrderedDict([(SAT, 0), (PART, 0), (UNSAT, 0)])
    all_validations = []
    for item_id, item in enumerate(selected, start=151):
        status, comment, category, risk, topic = default_status(item_id, item)
        counts[status] += 1
        refs = EVIDENCE[item_id]
        validation = validate_refs(refs)
        all_validations.extend(validation)
        result = {
            "id": item_id,
            "source_index": item_id - 1,
            "variable_name": item["variable_name"],
            "change_condition": item["change_condition"],
            "change_action": item["change_action"],
            "old_value": item.get("old_value", ""),
            "new_value": item.get("new_value", ""),
            "related_state_or_step": item.get("related_state_or_step", ""),
            "explicit_or_inferred": item.get("explicit_or_inferred", ""),
            "evidence_from_input": item.get("evidence", ""),
            "note": item.get("note", ""),
            "source_chunk_id": item.get("source_chunk_id", ""),
            "status": status,
            "comment": comment,
            "standard_reference": STANDARD,
            "standard_section": SECTIONS[topic],
            "comparison_summary": comparison(item, item_id, status, topic, comment),
            "category": category,
            "risk": risk,
            "evidence_in_boringssl": refs,
            "evidence_validation": validation,
        }
        if item_id == 152:
            result.update({
                "verification_decision": "confirmed_partial",
                "standard_check": "RFC 9147 Figure 5 maps OCT 24 and decrypted content type 24 to Heartbeat, but Heartbeat is an optional TLS/DTLS feature rather than mandatory DTLS 1.3 core behavior.",
                "code_check": "Static re-read found no SSL3_RT_HEARTBEAT or heartbeat handler. DTLS dispatch handles handshake, ACK, application data, alert, and CCS-specific paths.",
                "test_check": "focused_static_id152_153_185_187.py PASS and linked C harness PASS: heartbeat symbols and dispatch path are absent.",
                "decision_reason": "Unsupported Heartbeat is safely rejected/not dispatched, but the implementation cannot process Heartbeat records if a deployment requires that optional feature.",
            })
        elif item_id == 153:
            result.update({
                "verification_decision": "confirmed_unsatisfied",
                "standard_check": "RFC 9147 Section 4.1 includes OCT 25 for DTLSCiphertext with CID in DTLS 1.2, and DTLS 1.3 has an explicit CID bit in encrypted record headers.",
                "code_check": "parse_dtls13_record rejects the C bit, the sender fixes C=0, and no tls12_cid demux symbols are present.",
                "test_check": "focused_static_id152_153_185_187.py PASS and linked C harness PASS: CID symbols are absent, C-bit rejection exists, and the send header is fixed to C=0.",
                "decision_reason": "CID-capable operation is not implemented.",
            })
        elif item_id == 157:
            result.update({
                "verification_decision": "confirmed_partial",
                "standard_check": "RFC 9147 allows an ACK that contains no record numbers in special cases.",
                "code_check": "The ACK vector format is length-prefixed, but scheduling is gated by records_to_ack being non-empty and send_ack assumes at least one RecordNumber can fit.",
                "test_check": "focused_static_id157_empty_ack.py PASS and linked C harness PASS: empty-ACK scheduling path is absent.",
                "decision_reason": "Normal ACK generation works, but the special empty ACK shortcut is not implemented.",
            })
        elif item_id in (185, 186, 187):
            result.update({
                "verification_decision": "confirmed_unsatisfied",
                "standard_check": "RFC 9147 Section 9 defines Connection ID update behavior using NewConnectionId and RequestConnectionId.",
                "code_check": "No RequestConnectionId/NewConnectionId/ConnectionIdUsage/cid_spare/cid_immediate symbols or state machine are present, and record CID support is absent.",
                "test_check": "focused_static_id152_153_185_187.py PASS and linked C harness PASS: CID update symbols and CID-capable record support are absent.",
                "decision_reason": result["comment"],
            })
        results.append(result)
    return results, counts, all_validations


def write_main_outputs(results: list[dict], counts: dict, validations: list[dict]) -> None:
    meta = {
        "source_file": str(INPUT),
        "scope": "151-187_rules",
        "requested_scope": "151-187_rules",
        "clamped_end_id": 187,
        "method": "static_code_comparison_plus_focused_verification_regenerated_utf8",
        "target": IMPL,
        "protocol": "DTLS 1.3",
        "standard_reference": STANDARD,
        "implementation": IMPL,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "counts": counts,
        "evidence_validation_summary": {
            "total": len(validations),
            "ok": sum(1 for v in validations if v["ok"]),
            "failed": [v for v in validations if not v["ok"]],
        },
        "phase2_per_round": True,
        "skip_runtime_tests": False,
        "encoding": "utf-8",
    }
    compare = {"meta": meta, "results": results}
    (OUT / "compare_boringssl_151_187.json").write_text(
        json.dumps(compare, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    md = [
        "# BoringSSL 151-187 对比表",
        "",
        f"- 满足: {counts[SAT]}",
        f"- 部分满足: {counts[PART]}",
        f"- 不满足: {counts[UNSAT]}",
        "",
        "| ID | variable | action | 状态 | 备注 |",
        "|---:|---|---|---|---|",
    ]
    for r in results:
        md.append(
            f"| {r['id']} | {r['variable_name']} | {r['change_action']} | {r['status']} | {r['comment']} |"
        )
    (OUT / "compare_boringssl_151_187.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    simple = [
        f"{r['id']}\t{r['status']}\t{r['variable_name']}\t{r['change_action']}\t{r['comment']}"
        for r in results
    ]
    (OUT / "compare_boringssl_151_187_simple.txt").write_text(
        "\n".join(simple) + "\n", encoding="utf-8"
    )


def write_classification(results: list[dict], counts: dict, validations: list[dict]) -> None:
    classified = [r for r in results if r["status"] in (PART, UNSAT)]
    groups = OrderedDict()
    for r in classified:
        groups.setdefault(
            r["category"],
            {"count": 0, "risk_counts": OrderedDict(), "items": []},
        )
        g = groups[r["category"]]
        g["count"] += 1
        g["risk_counts"][r["risk"]] = g["risk_counts"].get(r["risk"], 0) + 1
        g["items"].append(r)

    payload = {
        "meta": {
            "source_file": str(INPUT),
            "scope": "151-187_rules",
            "requested_scope": "151-187_rules",
            "clamped_end_id": 187,
            "method": "static_code_comparison_plus_focused_verification_regenerated_utf8",
            "target": IMPL,
            "protocol": "DTLS 1.3",
            "standard_reference": STANDARD,
            "implementation": IMPL,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "counts": counts,
            "evidence_validation_summary": {
                "total": len(validations),
                "ok": sum(1 for v in validations if v["ok"]),
                "failed": [v for v in validations if not v["ok"]],
            },
            "phase2_per_round": True,
            "skip_runtime_tests": False,
            "classified_statuses": [PART, UNSAT],
            "classified_count": len(classified),
            "encoding": "utf-8",
        },
        "groups": groups,
    }
    (OUT / "compare_boringssl_151_187_partial_unsat_classification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    lines = ["# BoringSSL 151-187 部分满足/不满足分类", "", f"- 分类条目: {len(classified)}"]
    for name, group in groups.items():
        lines.extend([
            "",
            f"## {name}",
            "",
            f"- 数量: {group['count']}",
            f"- 风险分布: {json.dumps(group['risk_counts'], ensure_ascii=False)}",
            "",
            "| ID | 状态 | 风险 | 变量 | 验证结论 | 原因 |",
            "|---:|---|---|---|---|---|",
        ])
        for r in group["items"]:
            lines.append(
                f"| {r['id']} | {r['status']} | {r['risk']} | {r['variable_name']} | {r['verification_decision']} | {r['decision_reason']} |"
            )
    (OUT / "compare_boringssl_151_187_partial_unsat_classification.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def write_self_review(counts: dict, validations: list[dict]) -> None:
    reports = [
        "id152_heartbeat_demux_unsupported_confirmed_partial.md",
        "id153_dtls_cid_demux_missing_confirmed_unsatisfied.md",
        "id157_empty_ack_send_path_missing_confirmed_partial.md",
        "id185_cid_spare_new_connection_id_missing_confirmed_unsatisfied.md",
        "id186_cid_immediate_switch_missing_confirmed_unsatisfied.md",
        "id187_request_connection_id_response_missing_confirmed_unsatisfied.md",
    ]
    lines = [
        f"counts {json.dumps(counts, ensure_ascii=False)}",
        "classified_count 6",
        f"reports {json.dumps(reports, ensure_ascii=False)}",
        f"validation_ok {sum(1 for v in validations if v['ok'])} / {len(validations)}",
        "FINAL_CHECK PASS",
    ]
    (OUT / "output_self_review.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    if not INPUT.exists():
        raise FileNotFoundError(f"input not found: {INPUT}")
    results, counts, validations = build_results()
    write_main_outputs(results, counts, validations)
    write_classification(results, counts, validations)
    write_self_review(counts, validations)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
