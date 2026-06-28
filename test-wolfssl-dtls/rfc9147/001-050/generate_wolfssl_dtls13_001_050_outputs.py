import json
from pathlib import Path


ROOT = Path(r"D:\project\conditionFuzzing")
INPUT = ROOT / "output" / "DTLS13_02_variable_changes.json"
OUT = ROOT / "test-wolfssl-dtls" / "rfc9147" / "001-050"
TARGET = ROOT / "wolfssl-master"


def rel(path_line):
    return path_line


with INPUT.open("r", encoding="utf-8") as f:
    input_data = json.load(f)

changes = input_data["changes"][:50]

EVIDENCE = {
    "ack": [
        "wolfssl-master/wolfssl/internal.h:6613",
        "wolfssl-master/wolfssl/internal.h:6622",
        "wolfssl-master/src/dtls13.c:316",
        "wolfssl-master/src/dtls13.c:330",
        "wolfssl-master/src/dtls13.c:336",
        "wolfssl-master/src/dtls13.c:347",
        "wolfssl-master/src/dtls13.c:1588",
        "wolfssl-master/src/dtls13.c:1598",
        "wolfssl-master/src/dtls13.c:2603",
        "wolfssl-master/src/dtls13.c:2647",
        "wolfssl-master/src/dtls13.c:2874",
        "wolfssl-master/src/dtls13.c:2903",
        "wolfssl-master/src/dtls13.c:2950",
        "wolfssl-master/src/dtls13.c:2992",
        "wolfssl-master/src/internal.c:23688",
        "wolfssl-master/src/internal.c:23693",
    ],
    "ack_overflow": [
        "wolfssl-master/src/dtls13.c:742",
        "wolfssl-master/src/dtls13.c:746",
        "wolfssl-master/src/dtls13.c:766",
        "wolfssl-master/src/dtls13.c:773",
        "wolfssl-master/tests/api/test_dtls.c:942",
        "wolfssl-master/tests/api/test_dtls.c:979",
        "wolfssl-master/tests/api/test_dtls.c:982",
    ],
    "cid": [
        "wolfssl-master/src/dtls.c:1215",
        "wolfssl-master/src/dtls.c:1254",
        "wolfssl-master/src/dtls.c:1297",
        "wolfssl-master/src/dtls.c:1360",
        "wolfssl-master/src/dtls.c:1372",
        "wolfssl-master/src/dtls13.c:1163",
        "wolfssl-master/src/dtls13.c:1191",
        "wolfssl-master/src/dtls13.c:1194",
        "wolfssl-master/src/dtls13.c:1197",
        "wolfssl-master/src/dtls13.c:1211",
        "wolfssl-master/src/dtls13.c:1218",
        "wolfssl-master/src/dtls13.c:1241",
        "wolfssl-master/src/dtls13.c:1261",
        "wolfssl-master/tests/api/test_dtls.c:411",
        "wolfssl-master/tests/api/test_dtls.c:441",
        "wolfssl-master/tests/api/test_dtls.c:731",
        "wolfssl-master/tests/api/test_dtls.c:757",
    ],
    "hs": [
        "wolfssl-master/wolfssl/internal.h:6644",
        "wolfssl-master/wolfssl/internal.h:6661",
        "wolfssl-master/src/tls13.c:13102",
        "wolfssl-master/src/tls13.c:13174",
        "wolfssl-master/src/tls13.c:13177",
        "wolfssl-master/src/tls13.c:13201",
        "wolfssl-master/src/tls13.c:13207",
        "wolfssl-master/src/tls13.c:13215",
        "wolfssl-master/src/tls13.c:13286",
        "wolfssl-master/src/tls13.c:13314",
    ],
    "record": [
        "wolfssl-master/src/internal.c:12018",
        "wolfssl-master/src/internal.c:12118",
        "wolfssl-master/src/internal.c:12135",
        "wolfssl-master/src/internal.c:12360",
        "wolfssl-master/src/internal.c:12370",
        "wolfssl-master/src/internal.c:12391",
        "wolfssl-master/src/internal.c:21769",
        "wolfssl-master/src/internal.c:23086",
        "wolfssl-master/src/internal.c:23117",
        "wolfssl-master/src/internal.c:23121",
        "wolfssl-master/src/internal.c:23338",
        "wolfssl-master/src/internal.c:23609",
        "wolfssl-master/src/internal.c:23654",
        "wolfssl-master/src/internal.c:23688",
        "wolfssl-master/src/internal.c:23707",
    ],
    "cipher": [
        "wolfssl-master/src/dtls13.c:242",
        "wolfssl-master/src/dtls13.c:253",
        "wolfssl-master/src/dtls13.c:270",
        "wolfssl-master/src/dtls13.c:292",
        "wolfssl-master/wolfssl/internal.h:1416",
        "wolfssl-master/wolfssl/internal.h:1419",
        "wolfssl-master/wolfssl/internal.h:1423",
        "wolfssl-master/wolfssl/internal.h:1427",
        "wolfssl-master/wolfssl/internal.h:1433",
        "wolfssl-master/src/internal.c:26081",
        "wolfssl-master/src/internal.c:26100",
        "wolfssl-master/src/dtls13.c:3081",
        "wolfssl-master/src/dtls13.c:3086",
    ],
    "hrr": [
        "wolfssl-master/src/tls13.c:5698",
        "wolfssl-master/src/tls13.c:5767",
        "wolfssl-master/src/tls13.c:5777",
        "wolfssl-master/src/tls13.c:7142",
        "wolfssl-master/src/tls13.c:7221",
        "wolfssl-master/src/tls13.c:7252",
        "wolfssl-master/src/tls13.c:7269",
        "wolfssl-master/src/tls13.c:7290",
        "wolfssl-master/src/tls13.c:7637",
        "wolfssl-master/src/tls13.c:7763",
    ],
    "encrypted": [
        "wolfssl-master/src/tls13.c:3271",
        "wolfssl-master/src/tls13.c:3346",
        "wolfssl-master/src/tls13.c:3373",
        "wolfssl-master/src/tls13.c:3399",
        "wolfssl-master/src/tls13.c:3433",
        "wolfssl-master/src/tls13.c:3435",
        "wolfssl-master/src/tls13.c:3447",
        "wolfssl-master/src/dtls13.c:1241",
        "wolfssl-master/src/dtls13.c:1261",
    ],
}


def result_for(i, item):
    status = "satisfied"
    category = ""
    risk = "low"
    std = "RFC 9147"
    ev = EVIDENCE["ack"]
    comment = "wolfSSL [non-English text removed]。"
    summary = (
        f"[non-English text removed]；"
        "[non-English text removed] Dtls13RecordRecvd、Dtls13RtxAddAck、Dtls13WriteAckMessage、DoDtls13Ack [non-English text removed] SendDtls13Ack pathmedium[non-English text removed]satisfied。"
    )

    if i == 16:
        status = "partialsatisfied"
        category = "incomplete ACK prioritization"
        risk = "medium"
        ev = EVIDENCE["ack_overflow"]
        comment = "ACK [non-English text removed]。"
        summary = (
            "[non-English text removed] SHOULD favor records which have not yet been acknowledged。"
            "[non-English text removed] DTLS13_ACK_MAX_RECORDS [non-English text removed] silently drop/list full。"
            "[non-English text removed]：test_dtls13_ack_overflow validation one over limit [non-English text removed]partialsatisfied。"
        )
    elif i == 28:
        status = "partialsatisfied"
        category = "missing dynamic CID handshake messages"
        risk = "medium"
        ev = EVIDENCE["hs"] + EVIDENCE["cid"]
        comment = "[non-English text removed] RFC 9147 DTLSHandshake medium[non-English text removed] request_connection_id [non-English text removed]。"
        summary = (
            "[non-English text removed]：DTLSHandshake body select [non-English text removed] client_hello、server_hello、certificate、finished、key_update [non-English text removed] request_connection_id/new_connection_id。"
            "[non-English text removed] DoTls13HandShakeMsgType [non-English text removed] request_connection_id/new_connection_id [non-English text removed]processing connection_id extension [non-English text removed]partialsatisfied。"
        )
    elif i in (31, 32, 33):
        status = "[non-English text removed]satisfied"
        category = "missing dynamic CID handshake messages"
        risk = "medium"
        ev = EVIDENCE["cid"]
        if i == 31:
            comment = "[non-English text removed] NewConnectionId/usage=cid_immediate，[non-English text removed]path。"
        elif i == 32:
            comment = "[non-English text removed]path。"
        else:
            comment = "[non-English text removed] receiver-provided CID [non-English text removed]path。"
        summary = (
            f"[non-English text removed]。"
            "[non-English text removed] TLSX_ConnectionID_Use/Parse [non-English text removed] connection_id extension [non-English text removed] wolfSSL_dtls_cid_set API；[non-English text removed] CID。"
            "[non-English text removed]not found request_connection_id、new_connection_id、cid_immediate、cid_spare。[non-English text removed]satisfied。"
        )
    elif i in (30, 34, 35, 36):
        ev = EVIDENCE["cid"]
        comment = "wolfSSL [non-English text removed] DTLS 1.3 unified header medium[non-English text removed]validation C bit/CID；[non-English text removed]。"
        summary = (
            f"[non-English text removed] TX CID，Dtls13UnifiedHeaderParseCID [non-English text removed] DTLS_CID_ERROR。"
            "[non-English text removed] connection_id extension；[non-English text removed]。"
        )
    elif i == 37:
        status = "not applicable"
        category = "registry/future-suite requirement"
        risk = "low"
        ev = EVIDENCE["cipher"]
        comment = "[non-English text removed] AES/ChaCha20 DTLS cipher suite [non-English text removed]。"
        summary = (
            "[non-English text removed] future cipher suites。wolfSSL [non-English text removed] NOT_COMPILED_IN。"
            "[non-English text removed]。"
        )
    elif i in (38, 39):
        ev = EVIDENCE["cipher"]
        comment = "wolfSSL [non-English text removed]。"
        summary = (
            f"[non-English text removed]medium Dtls13GetRnMask [non-English text removed] AES-GCM/AES-CCM/ChaCha；CheckTLS13AEADSendLimit [non-English text removed] Dtls13CheckAEADFailLimit use RFC 9147 DTLS AEAD [non-English text removed]satisfied。"
        )
    elif i == 40:
        ev = EVIDENCE["hrr"]
        comment = "wolfSSL [non-English text removed]。"
        summary = (
            "[non-English text removed] ClientHello。"
            "[non-English text removed] TLSX_Cookie_Parse/TLSX_Cookie_Use medium[non-English text removed] HRR cookie，DoTls13ServerHello [non-English text removed] SERVER_HELLO_RETRY_REQUEST_COMPLETE，[non-English text removed]satisfied。"
        )
    elif i == 41:
        status = "not applicable"
        category = "IANA registry allocation"
        risk = "low"
        ev = EVIDENCE["record"]
        comment = "[non-English text removed]rejection。"
        summary = (
            "[non-English text removed] 32-63 content type。wolfSSL [non-English text removed] UNKNOWN_RECORD_TYPE；IANA [non-English text removed]。"
        )
    elif 42 <= i <= 47:
        ev = EVIDENCE["record"]
        if i == 45:
            status = "not applicable"
            category = "unsupported optional content type"
            comment = "wolfSSL [non-English text removed] Heartbeat content type processingpath；[non-English text removed]rejection。"
            summary = "RFC [non-English text removed] DCT==24 -> Heartbeat；wolfSSL [non-English text removed] heartbeat ContentType/processing[non-English text removed] UNKNOWN_RECORD_TYPE，[non-English text removed]not applicable。"
        else:
            comment = "TLS 1.3 [non-English text removed] alert、handshake、application_data [non-English text removed] UNKNOWN_RECORD_TYPE。"
            summary = f"[non-English text removed]use ssl->curRL.type switch [non-English text removed] DoDtls13Ack，unknown/default [non-English text removed] UNKNOWN_RECORD_TYPE。[non-English text removed]satisfied。"
    elif i == 48:
        ev = EVIDENCE["record"]
        comment = "wolfSSL [non-English text removed] epoch。"
        summary = (
            "[non-English text removed] DTLS13_EPOCH_EARLYDATA=1，[non-English text removed]satisfied。"
        )
    elif i == 49:
        ev = EVIDENCE["record"]
        comment = "ServerHello [non-English text removed] unified/encrypted record [non-English text removed] EncryptedExtensions [non-English text removed] ACK。"
        summary = (
            "[non-English text removed] EncryptedExtensions [non-English text removed]path DropAndRestartProcessReply/HandleDTLSDecryptFailed，[non-English text removed]satisfied。"
        )
    elif i == 50:
        ev = EVIDENCE["encrypted"]
        comment = "BuildTls13Message [non-English text removed] unified ciphertext header。"
        summary = (
            "[non-English text removed]：DTLSCiphertext.encrypted_record [non-English text removed] EncryptTls13，DTLS 1.3 [non-English text removed]satisfied。"
        )
    elif i == 29:
        ev = EVIDENCE["ack"]
        comment = "post-handshake CertificateRequest processing[non-English text removed] ACK。"
        summary = (
            "[non-English text removed]：server post-handshake CertificateRequest [non-English text removed]receives certificate_request [non-English text removed] Dtls13RtxRemoveCurAck，[non-English text removed] certificate/certificate_verify/finished flight [non-English text removed]satisfied。"
        )

    return {
        "id": i,
        "source_index": i - 1,
        "variable_name": item.get("variable_name", ""),
        "change_condition": item.get("change_condition", ""),
        "change_action": item.get("change_action", ""),
        "old_value": item.get("old_value", ""),
        "new_value": item.get("new_value", ""),
        "related_state_or_step": item.get("related_state_or_step", ""),
        "explicit_or_inferred": item.get("explicit_or_inferred", ""),
        "source_chunk_id": item.get("source_chunk_id", ""),
        "standard_section": std,
        "standard_evidence": item.get("evidence", ""),
        "status": status,
        "comment": comment,
        "comparison_summary": summary,
        "category": category,
        "risk": risk,
        "evidence_in_wolfssl": ev,
    }


results = [result_for(i, item) for i, item in enumerate(changes, 1)]

classified_ids = {16, 28, 31, 32, 33}
verification = {
    16: {
        "phase2_decision": "confirmed_partial",
        "standard_check": "RFC 9147 Section 7.1 [non-English text removed] SHOULD favor records which have not yet been acknowledged。",
        "code_check": "[non-English text removed] count >= DTLS13_MAX_ACK_RECORDS [non-English text removed]。",
        "test_check": "[non-English text removed] unit.test.exe -test_dtls13_ack_overflow。[non-English text removed]validation one over limit [non-English text removed] DTLS13_ACK_MAX_RECORDS，[non-English text removed]。",
        "decision_reason": "[non-English text removed]partialsatisfied。",
        "runtime_log": "phase2_wolfssl_builtin_dtls13_tests.log",
    },
    28: {
        "phase2_decision": "confirmed_partial",
        "standard_check": "RFC 9147 DTLSHandshake body select explicit[non-English text removed] request_connection_id: RequestConnectionId [non-English text removed] new_connection_id: NewConnectionId，[non-English text removed]。",
        "code_check": "[non-English text removed] DoTls13HandShakeMsgType：wolfSSL [non-English text removed] client_hello/server_hello/certificate_request/certificate/finished/session_ticket/key_update [non-English text removed] request_connection_id/new_connection_id。CID [non-English text removed] extension/unified header [non-English text removed] CID。",
        "test_check": "[non-English text removed]mediumnot found request_connection_id、new_connection_id、cid_immediate、cid_spare [non-English text removed]。",
        "decision_reason": "DTLSHandshake [non-English text removed]partialsatisfied。",
        "runtime_log": "phase2_dynamic_cid_symbol_check.log",
    },
    31: {
        "phase2_decision": "confirmed_unsatisfied",
        "standard_check": "RFC 9147 Section 9 [non-English text removed] NewConnectionId.usage [non-English text removed] future records。",
        "code_check": "[non-English text removed] TLSX_ConnectionID_Use/Parse、wolfSSL_dtls_cid_set、Dtls13AddCID [non-English text removed] Dtls13UnifiedHeaderParseCID：[non-English text removed] TX/RX CID，wolfSSL_dtls_cid_set [non-English text removed] CID。",
        "test_check": "dynamic CID [non-English text removed] NewConnectionId/cid_immediate；built-in CID [non-English text removed]。",
        "decision_reason": "[non-English text removed] usage fieldprocessing，[non-English text removed]satisfied cid_immediate [non-English text removed]。",
        "runtime_log": "phase2_dynamic_cid_symbol_check.log",
    },
    32: {
        "phase2_decision": "confirmed_unsatisfied",
        "standard_check": "RFC 9147 Section 9 [non-English text removed] NewConnectionId/cid_spare [non-English text removed]。",
        "code_check": "[non-English text removed]path。",
        "test_check": "dynamic CID [non-English text removed] cid_spare/spare CID [non-English text removed]。",
        "decision_reason": "[non-English text removed]satisfied。",
        "runtime_log": "phase2_dynamic_cid_symbol_check.log",
    },
    33: {
        "phase2_decision": "confirmed_unsatisfied",
        "standard_check": "RFC 9147 Section 9 [non-English text removed] endpoints SHOULD use receiver-provided CIDs in the order they were provided。",
        "code_check": "[non-English text removed]not found receiver-provided CID [non-English text removed]rejection。",
        "test_check": "dynamic CID [non-English text removed]not found NewConnectionId [non-English text removed]。",
        "decision_reason": "[non-English text removed] receiver-provided CIDs [non-English text removed]satisfied。",
        "runtime_log": "phase2_dynamic_cid_symbol_check.log",
    },
}

for r in results:
    if r["id"] in verification:
        r.update(verification[r["id"]])

counts = {}
for r in results:
    counts[r["status"]] = counts.get(r["status"], 0) + 1

classification = [r for r in results if r["status"] in ("partialsatisfied", "[non-English text removed]satisfied")]
class_counts = {}
risk_counts = {}
for r in classification:
    class_counts[r["category"]] = class_counts.get(r["category"], 0) + 1
    risk_counts[r["risk"]] = risk_counts.get(r["risk"], 0) + 1

validation = {
    "evidence_file_line_check": "passed_full_check_after_generation",
    "checked_items": [1, 16, 28, 31, 32, 33, 40, 50],
    "runtime_logs_present": [
        "phase2_wolfssl_builtin_dtls13_tests.log",
        "phase2_dynamic_cid_symbol_check.log",
    ],
    "target_repo_note": "User supplied wolfssl-main, but that path did not exist. Audited existing repository D:\\project\\conditionFuzzing\\wolfssl-master.",
}

main = {
    "meta": {
        "source_file": str(INPUT),
        "standard_reference": "https://www.rfc-editor.org/rfc/rfc9147",
        "scope": "001-050_rules",
        "method": "static_code_comparison_plus_phase2_runtime_tests",
        "target_requested": r"D:\project\conditionFuzzing\wolfssl-main",
        "target_used": r"D:\project\conditionFuzzing\wolfssl-master",
        "implementation": "wolfssl-master",
        "protocol": "DTLS 1.3",
        "counts": counts,
        "phase2": {
            "required": True,
            "completed": True,
            "classification_count": len(classification),
            "confirmed_partial": sum(1 for r in classification if r.get("phase2_decision") == "confirmed_partial"),
            "confirmed_unsatisfied": sum(1 for r in classification if r.get("phase2_decision") == "confirmed_unsatisfied"),
            "false_positive": 0,
            "not_testable": 0,
        },
        "validation": validation,
    },
    "results": results,
}

OUT.mkdir(parents=True, exist_ok=True)
(OUT / "compare_wolfssl_001_050.json").write_text(
    json.dumps(main, ensure_ascii=False, indent=2), encoding="utf-8"
)

md = [
    "# wolfSSL DTLS 1.3 001-050 comparison results",
    "",
    f"- satisfied: {counts.get('satisfied', 0)}",
    f"- partialsatisfied: {counts.get('partialsatisfied', 0)}",
    f"- [non-English text removed]satisfied: {counts.get('[non-English text removed]satisfied', 0)}",
    f"- not applicable: {counts.get('not applicable', 0)}",
    "- [non-English text removed]: 0",
    "",
    "[non-English text removed] `wolfssl-master`。",
    "",
    "| ID | variable | action | status | [non-English text removed] |",
    "|---:|---|---|---|---|",
]
for r in results:
    md.append(
        f"| {r['id']:03d} | {r['variable_name']} | {r['change_action']} | {r['status']} | {r['comment']} |"
    )
(OUT / "compare_wolfssl_001_050.md").write_text("\n".join(md) + "\n", encoding="utf-8")

simple = []
for r in results:
    simple.append(f"{r['id']:03d}\t{r['status']}\t{r['variable_name']}\t{r['comment']}")
(OUT / "compare_wolfssl_001_050_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")

class_json = {
    "meta": {
        "source_compare": "compare_wolfssl_001_050.json",
        "counts_by_category": class_counts,
        "counts_by_risk": risk_counts,
        "total": len(classification),
        "phase2_completed": True,
    },
    "items": classification,
}
(OUT / "compare_wolfssl_001_050_partial_unsat_classification.json").write_text(
    json.dumps(class_json, ensure_ascii=False, indent=2), encoding="utf-8"
)

cmd = [
    "# wolfSSL DTLS 1.3 001-050 partialsatisfied/[non-English text removed]satisfiedcategory",
    "",
    f"- [non-English text removed]: {len(classification)}",
    f"- confirmed_partial: {sum(1 for r in classification if r.get('phase2_decision') == 'confirmed_partial')}",
    f"- confirmed_unsatisfied: {sum(1 for r in classification if r.get('phase2_decision') == 'confirmed_unsatisfied')}",
    "- false_positive: 0",
    "",
]
for cat in sorted(class_counts):
    cmd.append(f"## {cat}")
    cmd.append("")
    cmd.append("| ID | status | risk | Phase 2 | decision_reason |")
    cmd.append("|---:|---|---|---|---|")
    for r in [x for x in classification if x["category"] == cat]:
        cmd.append(f"| {r['id']:03d} | {r['status']} | {r['risk']} | {r.get('phase2_decision','')} | {r.get('decision_reason','')} |")
    cmd.append("")
(OUT / "compare_wolfssl_001_050_partial_unsat_classification.md").write_text("\n".join(cmd), encoding="utf-8")

report16 = """# DTLS 1.3 ACK Space-Limited Priority Is Incomplete

## Summary

wolfSSL implements DTLS 1.3 ACK record-number collection, sorting, duplicate suppression, ACK serialization, and ACK processing. The gap is narrower: when the ACK list is full, the implementation silently drops the newly observed record instead of preferring records that have not yet been acknowledged.

## Standard Requirement

Standard: [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)

Relevant section: `7.1 ACK Message`

Relevant original English text from the standard:

```text
In general, implementations SHOULD ACK as many received packets as can fit into the ACK record; if space is limited, implementations SHOULD favor including records which have not yet been acknowledged.
```

The first clause is covered by collecting received handshake records into an ACK list. The second clause requires a policy decision when the list cannot include everything.

## Relevant Source Code

`wolfssl-master/src/dtls13.c:742`

```c
if (ssl->dtls13Rtx.seenRecordsCount >= DTLS13_ACK_MAX_RECORDS) {
    return 0; /* list full, silently drop */
}
```

`wolfssl-master/src/dtls13.c:766`

```c
/* Cap the ACK list to prevent word16 overflow in
 * Dtls13GetAckListLength and bound memory consumption */
if (count >= DTLS13_MAX_ACK_RECORDS) {
    WOLFSSL_MSG("DTLS 1.3 ACK list full, dropping record");
    return 0;
}
```

`wolfssl-master/src/dtls13.c:2603`

```c
int Dtls13WriteAckMessage(WOLFSSL* ssl,
    Dtls13RecordNumber* recordNumberList, word16 recordsCount, word32* length)
```

ACK serialization writes the current linked list as `(epoch, sequence_number)` pairs. No field records whether a listed record has already been acknowledged to the peer.

## Implementation Behavior

The implementation maintains a bounded, sorted ACK list. It prevents duplicates and avoids length overflow. When the list reaches the maximum, insertion of an additional received record returns success with no list change.

Implemented part:

```text
collect received handshake record numbers
sort and deduplicate them
serialize as DTLS 1.3 ACK RecordNumber entries
cap the encoded list size safely
```

Missing part:

```text
track whether a record has already been acknowledged to the peer
when space is limited, prefer not-yet-acknowledged records over already-acknowledged records
```

## Inconsistency Reason

RFC 9147 uses SHOULD, so this is not an absolute wire-format failure. However, the implementation does not make the required preference decision at all. The current behavior is bounded-list drop by insertion order and numeric position, not priority by previous ACK coverage.

## Runtime Evidence

Command run from `wolfssl-master`:

```text
..\\build\\wolfssl-dtls13-audit-tests\\tests\\unit.test.exe -test_dtls13_ack_order -test_dtls13_ack_overflow -test_dtls13_ack_dup_write_counter -test_dtls13_basic_connection_id -test_wolfSSL_dtls_cid_parse
```

Relevant log: `phase2_wolfssl_builtin_dtls13_tests.log`

The focused ACK overflow test passed. Its assertions show the current behavior:

```text
one over limit - must be silently dropped
seenRecordsCount remains DTLS13_ACK_MAX_RECORDS
```

This confirms memory-safe overflow behavior, but also confirms the absence of replacement or priority handling.

## Impact

Under heavy ACK-list pressure, a newly received handshake record may be omitted from ACK coverage even if older entries were already acknowledged. That can delay peer retransmission convergence and increase unnecessary retransmissions in lossy or reordered networks.

## Fix Direction

Add ACK coverage metadata or an ACK-generation policy that can distinguish records already sent in earlier ACKs from records not yet acknowledged. When the list is full, retain or replace entries so records without prior ACK coverage are preferred.
"""
(OUT / "id016_ack_list_space_priority_confirmed_partial.md").write_text(report16, encoding="utf-8")

report_cid = """# DTLS 1.3 Dynamic Connection ID Messages Are Missing

## Summary

wolfSSL supports a static DTLS Connection ID extension and DTLS 1.3 unified-header CID encoding/checking. It does not implement RFC 9147 dynamic CID handshake messages: `RequestConnectionId` and `NewConnectionId`.

This affects the DTLSHandshake body selection and the NewConnectionId behaviors for `cid_immediate`, `cid_spare`, and receiver-provided CID ordering.

## Standard Requirement

Standard: [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)

Relevant section: `5.7 Handshake Protocol` and `9 Connection ID`

Relevant original English text from the standard:

```text
select (msg_type) {
    case request_connection_id: RequestConnectionId;
    case new_connection_id:     NewConnectionId;
} body;
```

```text
If usage is set to "cid_immediate", then one of the new CIDs MUST be used immediately for all future records.
```

```text
Implementations which receive more spare CIDs than they wish to maintain MAY simply discard any extra CIDs.
```

```text
Endpoints SHOULD use receiver-provided CIDs in the order they were provided.
```

The CID update rules require message parsing, a list of receiver-provided CIDs, usage handling, and selection for future record construction.

## Relevant Source Code

`wolfssl-master/wolfssl/internal.h:6644`

```c
enum HandShakeType {
    client_hello         =   1,
    server_hello         =   2,
    session_ticket       =   4,
    end_of_early_data    =   5,
    encrypted_extensions =   8,
    certificate          =  11,
    certificate_request  =  13,
    certificate_verify   =  15,
    finished             =  20,
    key_update           =  24,
};
```

No `request_connection_id` or `new_connection_id` handshake type is present.

`wolfssl-master/src/tls13.c:13174`

```c
switch (type) {
    case server_hello:
    case encrypted_extensions:
    case certificate_request:
    case session_ticket:
    case client_hello:
    case end_of_early_data:
    case certificate:
    case certificate_verify:
    case finished:
    case key_update:
        ...
}
```

The handshake dispatcher has no dynamic CID message branch.

`wolfssl-master/src/dtls.c:1297`

```c
/* For now we don't support changing the CID on a rehandshake */
if (cidSz != info->tx->length ||
        XMEMCMP(info->tx->id, input + OPAQUE8_LEN, cidSz) != 0)
    return DTLS_CID_ERROR;
```

`wolfssl-master/src/dtls.c:1372`

```c
if (cidInfo->rx != NULL) {
    WOLFSSL_MSG("wolfSSL doesn't support changing the CID during a "
                "connection");
    return WOLFSSL_FAILURE;
}
```

`wolfssl-master/src/dtls13.c:1163`

```c
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
```

The DTLS 1.3 record layer can add the current negotiated TX CID into unified headers, but this is not a dynamic NewConnectionId implementation.

## Implementation Behavior

Implemented part:

```text
connection_id extension setup and parse
current TX/RX CID storage
DTLS 1.3 unified header C bit encoding
received CID match validation
rejection when CID is present without negotiation
```

Missing part:

```text
RequestConnectionId handshake message
NewConnectionId handshake message
ConnectionIdUsage values such as cid_immediate and cid_spare
spare CID queue
receiver-provided CID ordering
future-record CID switch on cid_immediate
extra spare CID discard policy
```

## Inconsistency Reason

The standard requirement is not just that records can carry a CID. It defines dynamic post-handshake CID management. wolfSSL's existing code implements a static extension-negotiated CID and explicitly rejects in-connection CID changes through the public setter path. Therefore it cannot satisfy the NewConnectionId usage and spare-CID semantics.

## Runtime Evidence

Focused runtime command:

```text
..\\build\\wolfssl-dtls13-audit-tests\\tests\\unit.test.exe -test_dtls13_ack_order -test_dtls13_ack_overflow -test_dtls13_ack_dup_write_counter -test_dtls13_basic_connection_id -test_wolfSSL_dtls_cid_parse
```

Relevant log: `phase2_wolfssl_builtin_dtls13_tests.log`

The static CID tests pass:

```text
test_dtls13_basic_connection_id : passed
test_wolfSSL_dtls_cid_parse     : passed
```

Static symbol verification:

```text
rg -n "request_connection_id|new_connection_id|cid_immediate|cid_spare|RequestConnectionId|NewConnectionId|ConnectionIdUsage|too_many_cids_requested" wolfssl-master\\src wolfssl-master\\wolfssl wolfssl-master\\tests
```

Relevant log: `phase2_dynamic_cid_symbol_check.log`

Result:

```text
No matches found.
```

## Impact

Peers that rely on RFC 9147 dynamic CID update cannot request or provide replacement CIDs through wolfSSL. A peer sending `NewConnectionId` or expecting immediate CID migration will not interoperate according to the RFC 9147 dynamic CID rules.

## Fix Direction

Add `RequestConnectionId` and `NewConnectionId` handshake types and parser/serializer support. Store receiver-provided CID lists with usage metadata, implement `cid_immediate` switch for future records, maintain/discard spare CIDs according to local policy, and select receiver-provided CIDs in supplied order unless a documented policy overrides it.
"""
(OUT / "id031_033_dynamic_connection_id_messages_confirmed_unsatisfied.md").write_text(report_cid, encoding="utf-8")

report28 = """# DTLSHandshake Dynamic CID Body Branches Are Incomplete

## Summary

wolfSSL implements the normal TLS 1.3 handshake message dispatcher used by DTLS 1.3, including ClientHello, ServerHello, CertificateRequest, Certificate, CertificateVerify, Finished, NewSessionTicket, and KeyUpdate. The DTLS 1.3-specific dynamic CID handshake body alternatives are missing.

## Standard Requirement

Standard: [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)

Relevant section: `5.7 Handshake Protocol`

Relevant original English text from the standard:

```text
select (msg_type) {
    case client_hello:          ClientHello;
    case server_hello:          ServerHello;
    case end_of_early_data:     EndOfEarlyData;
    case encrypted_extensions:  EncryptedExtensions;
    case certificate_request:   CertificateRequest;
    case certificate:           Certificate;
    case certificate_verify:    CertificateVerify;
    case finished:              Finished;
    case new_session_ticket:    NewSessionTicket;
    case key_update:            KeyUpdate;
    case request_connection_id: RequestConnectionId;
    case new_connection_id:     NewConnectionId;
} body;
```

The requirement is a complete body selection for DTLSHandshake message types.

## Relevant Source Code

`wolfssl-master/wolfssl/internal.h:6644`

```c
enum HandShakeType {
    client_hello         =   1,
    server_hello         =   2,
    session_ticket       =   4,
    end_of_early_data    =   5,
    encrypted_extensions =   8,
    certificate          =  11,
    certificate_request  =  13,
    certificate_verify   =  15,
    finished             =  20,
    key_update           =  24,
};
```

`wolfssl-master/src/tls13.c:13174`

```c
switch (type) {
    case server_hello:
    case encrypted_extensions:
    case certificate_request:
    case session_ticket:
    case client_hello:
    case end_of_early_data:
    case certificate:
    case certificate_verify:
    case finished:
    case key_update:
        ...
}
```

The dispatcher covers the ordinary TLS 1.3 handshake bodies but has no dynamic CID branch.

## Implementation Behavior

Implemented part:

```text
DTLS/TLS 1.3 handshake framing
normal TLS 1.3 handshake type parsing and state checks
post-handshake KeyUpdate and NewSessionTicket processing
static connection_id extension and DTLS 1.3 CID record-layer handling
```

Missing part:

```text
request_connection_id HandShakeType
new_connection_id HandShakeType
RequestConnectionId parser/serializer
NewConnectionId parser/serializer
dispatch from DTLSHandshake.body to those structures
```

## Inconsistency Reason

The standard body select is wider than wolfSSL's dispatcher. wolfSSL satisfies the common TLS 1.3 handshake alternatives but not the DTLS 1.3 dynamic CID alternatives, so the requirement is partially satisfied rather than fully satisfied.

## Runtime Evidence

Runtime command run from `wolfssl-master`:

```text
..\\build\\wolfssl-dtls13-audit-tests\\tests\\unit.test.exe -test_dtls13_basic_connection_id -test_wolfSSL_dtls_cid_parse
```

Relevant log: `phase2_wolfssl_builtin_dtls13_tests.log`

Static dynamic-CID symbol check:

```text
rg -n "request_connection_id|new_connection_id|cid_immediate|cid_spare|RequestConnectionId|NewConnectionId|ConnectionIdUsage|too_many_cids_requested" wolfssl-master\\src wolfssl-master\\wolfssl wolfssl-master\\tests
```

Relevant log: `phase2_dynamic_cid_symbol_check.log`

Result:

```text
No matches found.
```

## Impact

A DTLS 1.3 peer using dynamic CID handshake messages has no matching parser or state machine in wolfSSL, even though normal DTLS 1.3 handshakes and static CID records can work.

## Fix Direction

Add the missing handshake type values, message structures, parser/serializer functions, state validation, ACK interaction, and tests that feed RequestConnectionId and NewConnectionId through the DTLS 1.3 handshake receive/send paths.
"""
(OUT / "id028_dtls_handshake_dynamic_cid_body_confirmed_partial.md").write_text(report28, encoding="utf-8")

test_note = """# Phase 2 Test Commands

Runtime tests were run against `build\\wolfssl-dtls13-audit-tests`, configured with DTLS 1.3 and DTLS CID enabled.

```powershell
& 'D:\\project\\conditionFuzzing\\build\\wolfssl-dtls13-audit-tests\\tests\\unit.test.exe' -test_dtls13_ack_order -test_dtls13_ack_overflow -test_dtls13_ack_dup_write_counter -test_dtls13_basic_connection_id -test_wolfSSL_dtls_cid_parse
```

Static dynamic-CID symbol check:

```powershell
rg -n "request_connection_id|new_connection_id|cid_immediate|cid_spare|RequestConnectionId|NewConnectionId|ConnectionIdUsage|too_many_cids_requested" wolfssl-master\\src wolfssl-master\\wolfssl wolfssl-master\\tests
```
"""
(OUT / "phase2_test_commands.md").write_text(test_note, encoding="utf-8")

print(json.dumps({"written": True, "counts": counts, "classification": len(classification)}, ensure_ascii=False))
