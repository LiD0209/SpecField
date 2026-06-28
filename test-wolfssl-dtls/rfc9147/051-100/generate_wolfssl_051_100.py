import json
import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
SRC = ROOT / "wolfssl-master"
INPUT = ROOT / "output" / "DTLS13_02_variable_changes.json"
OUT = ROOT / "test-wolfssl-dtls" / "rfc9147" / "051-100"

IMPL = "wolfssl-main"
ACTUAL_TARGET = "wolfssl-master"
RFC = "https://www.rfc-editor.org/rfc/rfc9147"

SAT = "satisfied"
PARTIAL = "partialsatisfied"
UNSAT = "[non-English text removed]satisfied"
NA = "not applicable"


def load_changes():
    return json.loads(INPUT.read_text(encoding="utf-8"))["changes"]


def rel(path_line):
    return f"{ACTUAL_TARGET}/{path_line}"


def evidence(*items):
    return [rel(x) for x in items]


GROUPS = {
    "ciphertext_min": {
        "section": "RFC 9147 Section 4.2.3, Sequence Number Encryption",
        "standard": "This procedure requires the ciphertext length to be at least 16 bytes. Receivers MUST reject shorter records as if they had failed deprotection. Senders MUST pad short plaintexts out (using the conventional record padding mechanism) in order to make a suitable-length ciphertext.",
        "comment": "wolfSSL [non-English text removed] Dtls13ParseUnifiedRecordLayer [non-English text removed] ciphertext。",
        "summary": "[non-English text removed]：DTLS 1.3 sequence number encryption [non-English text removed] deprotection failure processing，[non-English text removed] record number deprotection [non-English text removed]：DTLS13_MIN_CIPHERTEXT=16，Dtls13MinimumRecordLength() [non-English text removed] BuildTls13Message() [non-English text removed] Dtls13ParseUnifiedRecordLayer() [non-English text removed] hdrInfo->recordLength < 16 [non-English text removed]：satisfied。",
        "evidence": evidence("src/dtls13.c:112", "src/dtls13.c:1303", "src/dtls13.c:1330", "src/dtls13.c:1561", "src/tls13.c:3350", "src/tls13.c:3401"),
    },
    "epoch_basic": {
        "section": "RFC 9147 Sections 4.1, 4.2.2, 4.2.3, 5.3, 5.8 and Appendix A",
        "standard": "The epoch number is initially zero; the DTLSPlaintext epoch is set as the least significant 2 bytes of the connection epoch; the unified header E bits carry the low-order two bits of the epoch; epoch values are assigned to unencrypted, early data, handshake, and application traffic secrets.",
        "comment": "wolfSSL use 64-bit w64wrapper [non-English text removed] early/handshake/application/update secret [non-English text removed] record number reconstruction mediumuselow[non-English text removed]。",
        "summary": "[non-English text removed] epoch 1/2/3，Dtls13GetEpochBits() [non-English text removed]，Dtls13RlAddCiphertextHeader() [non-English text removed] epoch bits，DeriveTls13Keys() [non-English text removed] epoch，Dtls13SetEpochKeys() [non-English text removed]：satisfied。",
        "evidence": evidence("wolfssl/internal.h:5844", "wolfssl/internal.h:5845", "wolfssl/internal.h:5846", "src/dtls.c:75", "src/dtls13.c:1156", "src/dtls13.c:1241", "src/tls13.c:1653", "src/dtls13.c:2372", "src/dtls13.c:2411"),
    },
    "epoch_reconstruct": {
        "section": "RFC 9147 Section 4.2.2, Reconstructing the Sequence Number and Epoch",
        "standard": "After the handshake is complete, if the epoch bits do not match those from the current epoch, implementations SHOULD use the most recent past epoch which has matching bits.",
        "comment": "wolfSSL [non-English text removed] epoch。",
        "summary": "[non-English text removed]：Dtls13ReconstructEpochNumber() [non-English text removed]use ssl->dtls13PeerEpoch，[non-English text removed] ssl->dtls13Epochs[]，[non-English text removed]：satisfied。",
        "evidence": evidence("src/dtls13.c:1449", "src/dtls13.c:1457", "src/dtls13.c:1464", "src/dtls13.c:1473", "src/dtls13.c:1484"),
    },
    "ack_epoch": {
        "section": "RFC 9147 Section 7, ACK Message",
        "standard": "During the handshake, ACK records MUST be sent with an epoch which is equal to or higher than the record which is being acknowledged. After the handshake, implementations MUST use the highest available sending epoch. Implementations SHOULD simply use the highest current sending epoch.",
        "comment": "wolfSSL [non-English text removed]semantic。",
        "summary": "[non-English text removed]：Dtls13RecordRecvd() [non-English text removed] epoch/seq；SendDtls13Ack() [non-English text removed] dtls13Epoch>=traffic0 [non-English text removed]use handshake epoch；Dtls13WriteAckMessage() [non-English text removed]：satisfied。",
        "evidence": evidence("src/dtls13.c:1592", "src/dtls13.c:1598", "src/dtls13.c:2603", "src/dtls13.c:2657", "src/dtls13.c:2971", "src/dtls13.c:2976", "src/dtls13.c:2979"),
    },
    "fixed_bits": {
        "section": "RFC 9147 Section 4.2.1, Record Header",
        "standard": "Fixed Bits: The three high bits of the first byte of the unified header are set to 001. If the first byte is any other value, then receivers MUST check to see if the leading bits of the first byte are 001. Otherwise, the record MUST be rejected as if it had failed deprotection.",
        "comment": "wolfSSL [non-English text removed] mask/value 0xe0/0x20，[non-English text removed] alert/handshake/ack [non-English text removed]mediumrejection。",
        "summary": "[non-English text removed]：DTLS13_FIXED_BITS_MASK [non-English text removed]；Dtls13RlAddCiphertextHeader() [non-English text removed]；Dtls13IsUnifiedHeader() [non-English text removed] alert/handshake/ack [non-English text removed]：satisfied。",
        "evidence": evidence("src/dtls13.c:95", "src/dtls13.c:98", "src/dtls13.c:1255", "src/dtls13.c:1391", "src/dtls13.c:1397", "src/internal.c:12309"),
    },
    "fragment_header": {
        "section": "RFC 9147 Section 3.3, Fragmentation",
        "standard": "Each DTLS handshake message contains both a fragment offset and a fragment length.",
        "comment": "wolfSSL [non-English text removed] DTLS 1.3 handshake header [non-English text removed] offset=0、fragmentLength=message length，[non-English text removed] offset/length。",
        "summary": "[non-English text removed] DTLS handshake message [non-English text removed]：Dtls13HandshakeHeader [non-English text removed] fragmentOffset/fragmentLength；Dtls13HandshakeAddHeader() [non-English text removed]length；Dtls13SendFragmented() [non-English text removed]：satisfied。",
        "evidence": evidence("src/dtls13.c:59", "src/dtls13.c:63", "src/dtls13.c:64", "src/dtls13.c:1296", "src/dtls13.c:1298", "src/dtls13.c:1109"),
    },
    "cookie": {
        "section": "RFC 9147 Sections 5.2 and 5.3, Cookie Exchange",
        "standard": "The client MUST send a new ClientHello with the cookie added as an extension. The server then verifies the cookie and proceeds with the handshake only if it is valid. A DTLS 1.3-only client MUST set the legacy_cookie field to zero length.",
        "comment": "wolfSSL [non-English text removed] server stateless path medium[non-English text removed] cookie extension；server [non-English text removed] retried ClientHello [non-English text removed] cookie extension length[non-English text removed]；DTLS 1.3 path use TLS cookie extension [non-English text removed] DTLS 1.2 legacy_cookie。",
        "summary": "[non-English text removed]：DTLS 1.3 cookie exchange use TLS cookie extension，validation[non-English text removed] DTLS 1.3-only client[non-English text removed] HRR cookie extension；DoClientHelloStateless() [non-English text removed] TLSX_COOKIE；CheckDtlsCookie() [non-English text removed] DTLS 1.3 cookie extension [non-English text removed] TlsCheckCookie；cookieGood [non-English text removed]：satisfied。",
        "evidence": evidence("src/dtls.c:269", "src/dtls.c:274", "src/dtls.c:847", "src/dtls.c:973", "src/dtls.c:1003", "src/dtls.c:1014", "src/dtls.c:1033"),
    },
    "key_update_ack": {
        "section": "RFC 9147 Sections 5.8 and 7.1, KeyUpdate and ACK",
        "standard": "As with other handshake messages with no built-in response, KeyUpdates MUST be acknowledged. Implementations MUST NOT send records with the new keys or send a new KeyUpdate until the previous KeyUpdate has been acknowledged.",
        "comment": "wolfSSL [non-English text removed] retransmission-tracked handshake [non-English text removed] dtls13WaitKeyUpdateAck，ACK processing[non-English text removed] epoch。",
        "summary": "[non-English text removed]：Dtls13HandshakeSend() [non-English text removed] epoch/seq；DoDtls13Ack() [non-English text removed] retransmit record；DoDtls13KeyUpdateAck() [non-English text removed] Dtls13KeyUpdateAckReceived()；[non-English text removed] DeriveTls13Keys(update_traffic_key) [non-English text removed]：satisfied。",
        "evidence": evidence("src/dtls13.c:2092", "src/dtls13.c:2099", "src/dtls13.c:2688", "src/dtls13.c:2692", "src/dtls13.c:2696", "src/dtls13.c:2861", "src/dtls13.c:2903", "src/dtls13.c:2931"),
    },
}


PARTIALS = {
    57: {
        "status": PARTIAL,
        "category": "close_notify [non-English text removed]missing epoch/sequence pair [non-English text removed]",
        "risk": "medium",
        "section": "RFC 9147 Section 5.8, Closure Alerts",
        "standard": "Any data received with an epoch/sequence number pair after that of a valid received closure alert MUST be ignored.",
        "comment": "wolfSSL receives close_notify [non-English text removed] epoch/sequence pair，[non-English text removed] DTLS 1.3 record receive path medium[non-English text removed]。",
        "summary": "[non-English text removed] epoch/sequence pair [non-English text removed] ssl->options.closeNotify；ProcessReply [non-English text removed] close_notify_epoch/sequence [non-English text removed]：close_notify statusprocessing[non-English text removed] DTLS 1.3 epoch/sequence pair [non-English text removed]，partialsatisfied。",
        "evidence": evidence("src/internal.c:22226", "src/internal.c:23663", "src/internal.c:23668", "wolfssl/internal.h:5046", "wolfssl/internal.h:6212"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 [non-English text removed] valid closure alert [non-English text removed] epoch/sequence number pair [non-English text removed] close_notify。",
        "code_check": "DoAlert() [non-English text removed] closeNotify；ProcessReply [non-English text removed] ZERO_RETURN；WOLFSSL [non-English text removed]。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_close_notify_lacks_epoch_sequence_gate [non-English text removed] closeNotifyEpoch/closeNotifySeq [non-English text removed] post-close pair comparison。",
        "decision_reason": "[non-English text removed] close_notify semantic[non-English text removed] epoch/sequence pair [non-English text removed] confirmed_partial。",
        "report": "id057_close_notify_epoch_sequence_gate_confirmed_partial.md",
    },
    62: {
        "status": PARTIAL,
        "category": "[non-English text removed]",
        "risk": "medium",
        "section": "RFC 9147 Section 5.8, Key Updates",
        "standard": "sending implementations MUST NOT allow the epoch to exceed 2^48-1. However, receiving implementations MUST NOT enforce this rule.",
        "comment": "wolfSSL use 64-bit epoch [non-English text removed]。",
        "summary": "[non-English text removed]：Dtls13KeyUpdateAckReceived() [non-English text removed]：partialsatisfied。",
        "evidence": evidence("src/dtls13.c:2696", "src/dtls13.c:2699", "src/dtls13.c:2326", "src/dtls13.c:2330", "src/dtls13.c:1449", "src/dtls13.c:1479"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 [non-English text removed] sending implementation [non-English text removed] receiving implementation mandatory[non-English text removed]。",
        "code_check": "[non-English text removed] 0x0000ffffffffffff、2^48、281474976710655 [non-English text removed] Dtls13ReconstructEpochNumber() [non-English text removed]。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_epoch_send_limit_is_64bit_wrap_not_2p48 [non-English text removed]。",
        "decision_reason": "[non-English text removed] confirmed_partial。",
        "report": "id062_epoch_send_limit_confirmed_partial.md",
    },
    76: {
        "alias_of": 62,
        "status": PARTIAL,
        "category": "[non-English text removed]",
        "risk": "medium",
        "section": "RFC 9147 Section 5.8, Key Updates",
        "standard": "Note that epoch values do not wrap. If a DTLS implementation would need to wrap the epoch value, it MUST terminate the connection.",
        "comment": "wolfSSL [non-English text removed]。",
        "summary": "[non-English text removed]：partialsatisfied。",
        "evidence": evidence("src/dtls13.c:2696", "src/dtls13.c:2699", "src/dtls13.c:2326", "src/dtls13.c:2330"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 [non-English text removed] epoch values do not wrap，[non-English text removed]。",
        "code_check": "wolfSSL [non-English text removed]connection。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_epoch_send_limit_is_64bit_wrap_not_2p48 [non-English text removed]。",
        "decision_reason": "[non-English text removed]，confirmed_partial。",
        "report": "id062_epoch_send_limit_confirmed_partial.md",
    },
    87: {
        "alias_of": 62,
        "status": PARTIAL,
        "category": "[non-English text removed]",
        "risk": "medium",
        "section": "RFC 9147 Section 4.2.2 and Section 5.8",
        "standard": "Implementations MUST NOT allow the epoch to wrap; sending implementations MUST NOT allow the epoch to exceed 2^48-1.",
        "comment": "wolfSSL [non-English text removed] DTLS 1.3 sending epoch 2^48-1 [non-English text removed]。",
        "summary": "[non-English text removed]processing 64-bit wrap。[non-English text removed]：partialsatisfied。",
        "evidence": evidence("src/dtls13.c:2696", "src/dtls13.c:2699", "src/dtls13.c:2326", "src/dtls13.c:2330"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 [non-English text removed]。",
        "code_check": "[non-English text removed]。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_epoch_send_limit_is_64bit_wrap_not_2p48 [non-English text removed]。",
        "decision_reason": "[non-English text removed]，confirmed_partial。",
        "report": "id062_epoch_send_limit_confirmed_partial.md",
    },
    93: {
        "status": PARTIAL,
        "category": "PMTU [non-English text removed]",
        "risk": "low",
        "section": "RFC 9147 Section 4.4, Handshake Message Fragmentation and Reassembly",
        "standard": "If repeated retransmissions do not result in a response, and the PMTU is unknown, subsequent retransmissions SHOULD back off to a smaller record size, fragmenting the handshake message as appropriate.",
        "comment": "wolfSSL [non-English text removed] DTLS 1.3 handshake record；[non-English text removed] repeated retransmission timeout [non-English text removed]。",
        "summary": "[non-English text removed]：Dtls13HandshakeSend() [non-English text removed] wolfssl_local_GetMaxPlaintextSize() [non-English text removed]；Dtls13RtxTimeout()/Dtls13RtxSendBuffered() [non-English text removed]satisfied，PMTU unknown [non-English text removed]，partialsatisfied。",
        "evidence": evidence("src/dtls13.c:1109", "src/dtls13.c:2054", "src/dtls13.c:2089", "src/dtls13.c:2115", "src/dtls13.c:2810", "src/dtls13.c:2844", "src/internal.c:42146"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 [non-English text removed] repeated retransmissions [non-English text removed] handshake fragmentation。",
        "code_check": "[non-English text removed] Dtls13RtxTimeout()/Dtls13RtxSendBuffered() [non-English text removed] record size。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_retransmission_pmtu_backoff_not_present [non-English text removed] retransmission-timeout backoff [non-English text removed]status。",
        "decision_reason": "[non-English text removed]，missing repeated retransmission + unknown PMTU [non-English text removed]，confirmed_partial。",
        "report": "id093_pmtu_retransmission_backoff_confirmed_partial.md",
    },
    97: {
        "alias_of": 62,
        "status": PARTIAL,
        "category": "KeyUpdate [non-English text removed]",
        "risk": "medium",
        "section": "RFC 9147 Section 5.8, Key Updates",
        "standard": "If a sending implementation receives a KeyUpdate with request_update set to \"update_requested\", it MUST NOT send its own KeyUpdate if that would cause it to exceed these limits.",
        "comment": "wolfSSL [non-English text removed] 2^48-1 epoch/key usage limit [non-English text removed]。",
        "summary": "[non-English text removed]：receives update_requested [non-English text removed] keyUpdateRespond；SendTls13KeyUpdate() [non-English text removed]clears keyUpdateRespond [non-English text removed]：partialsatisfied。",
        "evidence": evidence("src/tls13.c:11929", "src/tls13.c:11961", "src/tls13.c:11970", "src/tls13.c:11803", "src/dtls13.c:2696", "src/dtls13.c:2699"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 [non-English text removed] KeyUpdate response decision [non-English text removed] epoch/key usage limits [non-English text removed]。",
        "code_check": "[non-English text removed]rejection。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_keyupdate_response_lacks_2p48_limit_gate [non-English text removed]。",
        "decision_reason": "[non-English text removed]；missing limits-based response suppression，confirmed_partial。",
        "report": "id062_epoch_send_limit_confirmed_partial.md",
    },
}


ID_GROUP = {
    51: "ciphertext_min", 52: "ciphertext_min", 53: "ciphertext_min",
    54: "epoch_basic", 55: "key_update_ack", 56: "epoch_reconstruct",
    58: "epoch_basic", 59: "epoch_reconstruct", 60: "epoch_basic",
    61: "epoch_reconstruct", 63: "epoch_basic", 64: "epoch_basic",
    65: "ack_epoch", 66: "ack_epoch", 67: "ack_epoch", 68: "ack_epoch",
    69: "key_update_ack", 70: "epoch_basic", 71: "epoch_basic",
    72: "epoch_basic", 73: "epoch_basic", 74: "epoch_basic",
    75: "epoch_reconstruct", 77: "epoch_basic", 78: "epoch_basic",
    79: "epoch_basic", 80: "epoch_basic", 81: "epoch_basic",
    82: "key_update_ack", 83: "epoch_reconstruct", 84: "epoch_basic",
    85: "epoch_basic", 86: "epoch_basic", 88: "cookie", 89: "cookie",
    90: "fixed_bits", 91: "fixed_bits", 92: "fixed_bits",
    94: "fragment_header", 95: "fragment_header", 96: "fragment_header",
    98: "key_update_ack", 99: "cookie", 100: "cookie",
}


def build_results():
    changes = load_changes()
    results = []
    for item_id in range(51, 101):
        change = changes[item_id - 1]
        if item_id in PARTIALS:
            p = PARTIALS[item_id]
            base = {
                "status": p["status"],
                "category": p["category"],
                "risk": p["risk"],
                "standard_section": p["section"],
                "standard_text": p["standard"],
                "comment": p["comment"],
                "comparison_summary": p["summary"],
                "evidence_in_wolfssl": p["evidence"],
                "verification_decision": p["decision"],
                "standard_check": p["standard_check"],
                "code_check": p["code_check"],
                "test_check": p["test_check"],
                "decision_reason": p["decision_reason"],
            }
            if "alias_of" in p:
                base["verification_alias_of"] = p["alias_of"]
        else:
            g = GROUPS[ID_GROUP[item_id]]
            base = {
                "status": SAT,
                "category": "[non-English text removed]satisfied",
                "risk": "low",
                "standard_section": g["section"],
                "standard_text": g["standard"],
                "comment": g["comment"],
                "comparison_summary": g["summary"],
                "evidence_in_wolfssl": g["evidence"],
            }
        rec = {
            "id": item_id,
            "source_index": item_id - 1,
            "variable_name": change.get("variable_name", ""),
            "change_condition": change.get("change_condition", ""),
            "change_action": change.get("change_action", ""),
            "old_value": change.get("old_value", ""),
            "new_value": change.get("new_value", ""),
            "related_state_or_step": change.get("related_state_or_step", ""),
            "explicit_or_inferred": change.get("explicit_or_inferred", ""),
            "source_chunk_id": change.get("source_chunk_id", ""),
            "extracted_evidence": change.get("evidence", ""),
            "note": change.get("note", ""),
        }
        rec.update(base)
        results.append(rec)
    return results


def validate_evidence(results):
    validation = []
    for r in results:
        for ev in r["evidence_in_wolfssl"]:
            m = re.match(r"wolfssl-master/(.*):(\d+)$", ev)
            if not m:
                validation.append({"id": r["id"], "evidence": ev, "ok": False, "reason": "bad format"})
                continue
            path = SRC / m.group(1)
            line = int(m.group(2))
            if not path.exists():
                validation.append({"id": r["id"], "evidence": ev, "ok": False, "reason": "missing file"})
                continue
            count = sum(1 for _ in path.open("r", encoding="utf-8", errors="replace"))
            validation.append({"id": r["id"], "evidence": ev, "ok": 1 <= line <= count, "line_count": count})
    return validation


def write_json(results, validation):
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    data = {
        "meta": {
            "protocol": "DTLS 1.3",
            "standard_reference": RFC,
            "input_json": str(INPUT),
            "requested_target_repo": str(ROOT / "wolfssl-main"),
            "actual_target_repo": str(SRC),
            "implementation_name": IMPL,
            "scope": "051-100",
            "method": "static_code_comparison_plus_phase2_verification",
            "counts": counts,
            "path_note": "Requested target_repo wolfssl-main was not present; wolfssl-master in the same workspace was used as the concrete wolfSSL source tree.",
            "evidence_validation": {
                "checked": len(validation),
                "failed": [v for v in validation if not v.get("ok")],
            },
        },
        "results": results,
    }
    (OUT / "compare_wolfssl-main_051_100.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def write_md(results):
    lines = [
        "# wolfssl-main DTLS 1.3 RFC 9147 051-100 comparison results",
        "",
        f"- [non-English text removed]: {RFC}",
        f"- [non-English text removed]: `{ROOT / 'wolfssl-main'}`",
        f"- [non-English text removed]: `{SRC}`",
        "- [non-English text removed]。",
        "",
        "| ID | [non-English text removed] |",
        "|---:|---|---|---|---|---|",
    ]
    for r in results:
        ev = "<br>".join(r["evidence_in_wolfssl"][:5])
        lines.append(
            f"| {r['id']} | `{r['variable_name']}` | {r['status']} | {r['standard_section']} | {r['comparison_summary']} | {ev} |"
        )
    (OUT / "compare_wolfssl-main_051_100.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_simple(results):
    lines = []
    for r in results:
        lines.append(f"{r['id']:03d} {r['status']} {r['variable_name']} - {r['comment']}")
    (OUT / "compare_wolfssl-main_051_100_simple.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def classification(results):
    findings = [r for r in results if r["status"] in (PARTIAL, UNSAT)]
    categories = {}
    risks = {}
    for r in findings:
        cat = r["category"]
        categories.setdefault(cat, {"count": 0, "partial": 0, "unsatisfied": 0})
        categories[cat]["count"] += 1
        if r["status"] == PARTIAL:
            categories[cat]["partial"] += 1
        else:
            categories[cat]["unsatisfied"] += 1
        risks[r["risk"]] = risks.get(r["risk"], 0) + 1
    data = {
        "scope": "wolfssl-main 051-100 partial+unsatisfied",
        "total_reviewed": len(findings),
        "status_summary": {PARTIAL: sum(1 for r in findings if r["status"] == PARTIAL), UNSAT: sum(1 for r in findings if r["status"] == UNSAT)},
        "risk_summary": risks,
        "category_summary": categories,
        "results": findings,
    }
    (OUT / "compare_wolfssl-main_051_100_partial_unsat_classification.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# wolfssl-main DTLS 1.3 RFC 9147 051-100 partial/[non-English text removed]satisfiedcategory",
        "",
        f"- [non-English text removed]: {len(findings)}",
        f"- partialsatisfied: {sum(1 for r in findings if r['status'] == PARTIAL)}",
        f"- [non-English text removed]satisfied: {sum(1 for r in findings if r['status'] == UNSAT)}",
        "",
        "| ID | status | risk | category | [non-English text removed] | decision_reason |",
        "|---:|---|---|---|---|---|",
    ]
    for r in findings:
        lines.append(f"| {r['id']} | {r['status']} | {r['risk']} | {r['category']} | {r.get('verification_decision','')} | {r.get('decision_reason','')} |")
    (OUT / "compare_wolfssl-main_051_100_partial_unsat_classification.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return findings


def write_verify_script():
    script = r'''import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
SRC = ROOT / "wolfssl-master"

def read(rel):
    return (SRC / rel).read_text(encoding="utf-8", errors="replace")

def require(name, cond, detail):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    print(f"PASS {name}: {detail}")

def test_close_notify_lacks_epoch_sequence_gate():
    ih = read("wolfssl/internal.h")
    internal = read("src/internal.c")
    require("close notify state", "word16            closeNotify:1" in ih and "ssl->options.closeNotify = 1" in internal, "close_notify is represented as a state flag")
    absent = ["closeNotifyEpoch", "closeNotifySeq", "closureEpoch", "closureSeq", "close_notify_epoch", "close_notify_seq"]
    require("no stored closure pair", not any(term in ih + internal for term in absent), "no stored closure alert epoch/sequence pair")
    post_close_window = re.search(r"closeNotify.{0,160}(curEpoch64|curSeq|epoch/sequence|sequence)", internal, re.S)
    require("no post-close pair comparison", post_close_window is None, "no code compares later records with a stored closure pair")

def test_epoch_send_limit_is_64bit_wrap_not_2p48():
    dtls13 = read("src/dtls13.c")
    require("64-bit wrap checks", "w64Increment(&ssl->dtls13Epoch)" in dtls13 and "if (w64IsZero(ssl->dtls13Epoch))" in dtls13, "epoch update detects wrap to zero")
    forbidden = ["0x0000ffffffffffff", "0xffffffffffff", "281474976710655", "2^48", "1ULL << 48", "W64_MAX_48"]
    require("no 2^48 send limit", not any(term in dtls13 for term in forbidden), "no explicit 2^48-1 sending epoch limit found")
    require("receiver has no upper-bound gate", "Dtls13ReconstructEpochNumber" in dtls13 and "return SEQUENCE_ERROR" in dtls13, "receiver reconstructs by known epoch slots, not by enforcing 2^48")

def test_retransmission_pmtu_backoff_not_present():
    dtls13 = read("src/dtls13.c")
    internal = read("src/internal.c")
    require("fragmentation path exists", "Dtls13SendFragmented" in dtls13 and "wolfssl_local_GetMaxPlaintextSize" in dtls13, "handshake fragmentation uses current max plaintext size")
    require("retransmission path exists", "Dtls13RtxTimeout" in dtls13 and "Dtls13RtxSendBuffered" in dtls13, "retransmission timer resends buffered records")
    body = dtls13[dtls13.find("int Dtls13RtxTimeout"):dtls13.find("static int Dtls13RtxHasKeyUpdateBuffered")]
    backoff_terms = ["pmtu", "PMTU", "mtu", "Mtu", "maxFrag", "smaller", "back off", "backoff"]
    require("no rtx pmtu backoff", not any(term in body for term in backoff_terms), "timeout retransmission path does not shrink record size")
    require("mtu sizing elsewhere", "adjust plaintext size to fit in MTU" in internal, "MTU sizing exists for normal send sizing, not repeated retransmission backoff")

def test_keyupdate_response_lacks_2p48_limit_gate():
    tls13 = read("src/tls13.c")
    require("keyupdate response exists", "case update_requested:" in tls13 and "ssl->keys.keyUpdateRespond = 1" in tls13 and "return SendTls13KeyUpdate(ssl)" in tls13, "update_requested schedules a response")
    require("dtls wait gate exists", "ssl->options.dtls && ssl->dtls13WaitKeyUpdateAck" in tls13, "DTLS suppresses concurrent KeyUpdate while waiting for ACK")
    response_region = tls13[tls13.find("if (ssl->keys.keyUpdateRespond)"):tls13.find("WOLFSSL_LEAVE(\"DoTls13KeyUpdate\"", tls13.find("if (ssl->keys.keyUpdateRespond)"))]
    limit_terms = ["2^48", "281474976710655", "0x0000ffffffffffff", "1ULL << 48", "W64_MAX_48"]
    require("no limit gate in response", not any(term in response_region for term in limit_terms), "response decision is not gated by the RFC 2^48-1 epoch limit")

if __name__ == "__main__":
    test_close_notify_lacks_epoch_sequence_gate()
    test_epoch_send_limit_is_64bit_wrap_not_2p48()
    test_retransmission_pmtu_backoff_not_present()
    test_keyupdate_response_lacks_2p48_limit_gate()
'''
    (OUT / "verify_wolfssl_dtls13_051_100.py").write_text(script, encoding="utf-8")


def report(title, summary, standard, source, behavior, reason, runtime, impact, fix):
    return f"""# {title}

## Summary
{summary}

## Standard Requirement
Official standard: {RFC}

{standard}

## Relevant Source Code
{source}

## Implementation Behavior
{behavior}

## Inconsistency Reason
{reason}

## Runtime Evidence
{runtime}

## Impact
{impact}

## Fix Direction
{fix}
"""


def write_reports():
    close_report = report(
        "DTLS 1.3 close_notify does not preserve the closure record-number boundary",
        "wolfSSL records that a close_notify alert was received, but the audited DTLS 1.3 path does not preserve the alert's epoch/sequence number pair and does not compare later records against that boundary.",
        """Section 5.8, Closure Alerts:

```text
Any data received with an epoch/sequence number pair after that of a valid received closure alert MUST be ignored.
```

[non-English text removed] API shutdown status，[non-English text removed]。""",
        """`src/internal.c:22226`

```c
if (*type == close_notify) {
    ssl->options.closeNotify = 1;
}
```

`src/internal.c:23663`

```c
if (type == close_notify) {
    ssl->buffers.inputBuffer.idx =
        ssl->buffers.inputBuffer.length;
    ssl->options.processReply = doProcessInit;
    return ssl->error = ZERO_RETURN;
}
```""",
        "The implementation handles close_notify as a shutdown signal and returns ZERO_RETURN for the current read. The WOLFSSL object keeps current DTLS record fields such as curEpoch64/curSeq, but no closeNotifyEpoch/closeNotifySeq-style boundary is stored.",
        "The standard requires an ordering boundary based on the valid closure alert's epoch/sequence pair. wolfSSL implements close_notify state but does not retain or enforce that pair for future datagrams, so later DTLS records are not filtered by the required boundary in the audited code path.",
        "`verify_wolfssl_dtls13_051_100.py::test_close_notify_lacks_epoch_sequence_gate` passed. The test confirms close_notify state exists and no stored closure pair or post-close pair comparison is present.",
        "A peer that sends data after a valid close_notify should have that later data ignored according to RFC 9147. Without a record-number boundary, behavior depends on higher-level shutdown handling rather than the required DTLS ordering rule.",
        "Store the epoch and sequence number of the valid received closure alert. In DTLS 1.3 record receive processing, ignore records whose reconstructed epoch/sequence pair is later than the stored closure boundary."
    )
    (OUT / "id057_close_notify_epoch_sequence_gate_confirmed_partial.md").write_text(close_report, encoding="utf-8")

    epoch_report = report(
        "DTLS 1.3 sending epoch limit is not explicitly capped at 2^48-1",
        "wolfSSL prevents 64-bit epoch wrap, but the audited code does not explicitly enforce RFC 9147's sending-side epoch limit of 2^48-1. The same root cause affects KeyUpdate response decisions that would advance the sending epoch.",
        """Section 5.8, Key Updates:

```text
sending implementations MUST NOT allow the epoch to exceed 2^48-1.
```

```text
receiving implementations MUST NOT enforce this rule.
```

```text
If a sending implementation receives a KeyUpdate with request_update set to "update_requested", it MUST NOT send its own KeyUpdate if that would cause it to exceed these limits.
```

[non-English text removed]rejection。""",
        """`src/dtls13.c:2696`

```c
w64Increment(&ssl->dtls13Epoch);

/* Epoch wrapped up */
if (w64IsZero(ssl->dtls13Epoch))
    return BAD_STATE_E;
```

`src/tls13.c:11929`

```c
case update_requested:
    /* New key update requiring a response. */
    ssl->keys.keyUpdateRespond = 1;
    break;
```""",
        "The implementation increments a 64-bit epoch and rejects only wrap-to-zero. It also suppresses overlapping DTLS KeyUpdate while waiting for ACK, but no 2^48-1 limit check was found in the sending epoch increment or KeyUpdate response decision.",
        "The 64-bit wrap check implements part of the no-wrap requirement but is much later than RFC 9147's sending-side 2^48-1 limit. A response KeyUpdate decision similarly lacks a check that the response would not exceed the sending limit.",
        "`verify_wolfssl_dtls13_051_100.py::test_epoch_send_limit_is_64bit_wrap_not_2p48` and `test_keyupdate_response_lacks_2p48_limit_gate` passed. The tests confirm 64-bit wrap checks and KeyUpdate response logic exist, while no explicit 2^48-1 gate is present.",
        "The gap is relevant only near extreme KeyUpdate counts, but it is a normative sending-side limit. It can also make KeyUpdate response behavior diverge from the required limits-based suppression rule.",
        "Add a helper that checks the sending epoch before any local KeyUpdate or KeyUpdate response can advance it. Reject or terminate the connection when advancing would exceed 2^48-1, while leaving receive-side reconstruction free of that upper-bound enforcement."
    )
    (OUT / "id062_epoch_send_limit_confirmed_partial.md").write_text(epoch_report, encoding="utf-8")

    pmtu_report = report(
        "DTLS 1.3 retransmission path lacks PMTU-unknown record-size backoff evidence",
        "wolfSSL supports DTLS 1.3 handshake fragmentation and retransmission, but the audited retransmission timeout path does not show a strategy to back off to smaller record sizes after repeated retransmissions when PMTU is unknown.",
        """Section 4.4, Handshake Message Fragmentation and Reassembly:

```text
If repeated retransmissions do not result in a response, and the PMTU is unknown, subsequent retransmissions SHOULD back off to a smaller record size, fragmenting the handshake message as appropriate.
```

[non-English text removed]。""",
        """`src/dtls13.c:2089`

```c
maxFrag = wolfssl_local_GetMaxPlaintextSize(ssl);
maxLen = length;

if (maxLen < maxFrag) {
    ret = Dtls13SendOneFragmentRtx(...);
}
else {
    ret = Dtls13SendFragmented(...);
}
```

`src/dtls13.c:2810`

```c
/* Send ACKs when available after a timeout but only retransmit the last
 * flight after a long timeout */
int Dtls13RtxTimeout(WOLFSSL* ssl)
```
""",
        "Initial send uses current max plaintext/MTU sizing and can fragment. Timeout handling resends buffered messages through Dtls13RtxSendBuffered(), but the reviewed path does not adjust PMTU, shrink max fragment size, or re-fragment to smaller records as retransmissions repeat.",
        "The implementation covers basic fragmentation and retransmission. The missing part is the adaptive backoff condition: repeated no-response retransmissions with unknown PMTU should lead to smaller records.",
        "`verify_wolfssl_dtls13_051_100.py::test_retransmission_pmtu_backoff_not_present` passed. The test confirms fragmentation and retransmission functions exist, but the retransmission timeout body lacks PMTU/backoff/size-shrink logic.",
        "On paths where PMTU discovery is unavailable and large handshake records are black-holed, retransmissions may keep using the same size instead of converging to smaller fragments.",
        "Track repeated retransmission failures when PMTU is unknown, reduce the record-size target, and re-fragment queued handshake messages before subsequent retransmissions."
    )
    (OUT / "id093_pmtu_retransmission_backoff_confirmed_partial.md").write_text(pmtu_report, encoding="utf-8")


def summary(results, findings):
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    data = {
        "round": "051-100",
        "protocol": "DTLS 1.3",
        "implementation": IMPL,
        "actual_target_repo": str(SRC),
        "counts": counts,
        "phase2_reviewed": len(findings),
        "confirmed_partial": [r["id"] for r in findings if r.get("verification_decision") == "confirmed_partial"],
        "confirmed_unsatisfied": [r["id"] for r in findings if r.get("verification_decision") == "confirmed_unsatisfied"],
        "false_positive": [r["id"] for r in findings if r.get("verification_decision") == "false_positive"],
        "reports": sorted({r.get("report") for r in PARTIALS.values() if r.get("report")}),
        "next_round": "101-150 if continuing multi_round beyond the requested overall_end_id=100; current request ends at 100.",
    }
    (OUT / "round_summary_051_100.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    md = [
        "# Round Summary 051-100",
        "",
        f"- protocol: DTLS 1.3 ({RFC})",
        f"- [non-English text removed]: {IMPL}",
        f"- [non-English text removed]: `{SRC}`",
        f"- [non-English text removed]: {counts}",
        f"- Phase 2 [non-English text removed]: {len(findings)}",
        f"- confirmed_partial: {data['confirmed_partial']}",
        f"- confirmed_unsatisfied: {data['confirmed_unsatisfied']}",
        f"- [non-English text removed]: {', '.join(data['reports'])}",
        f"- [non-English text removed]range: {data['next_round']}",
    ]
    (OUT / "round_summary_051_100.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    results = build_results()
    validation = validate_evidence(results)
    write_json(results, validation)
    write_md(results)
    write_simple(results)
    findings = classification(results)
    write_verify_script()
    write_reports()
    summary(results, findings)
    if any(not v.get("ok") for v in validation):
        raise SystemExit("evidence validation failed")
    print(f"generated {len(results)} comparison results and {len(findings)} phase2 findings in {OUT}")


if __name__ == "__main__":
    main()
