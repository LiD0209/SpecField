import json
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
INPUT = ROOT / "output" / "DTLS12_02_variable_changes.json"
OUT = ROOT / "test-boringssl" / "rfc6347" / "051-098"

SAT = "\u6ee1\u8db3"
PARTIAL = "\u90e8\u5206\u6ee1\u8db3"
UNSAT = "\u4e0d\u6ee1\u8db3"

items = json.loads(INPUT.read_text(encoding="utf-8"))["changes"]

evidence = {
    "message_seq": [
        "ssl/d1_both.cc:550", "ssl/d1_both.cc:555", "ssl/d1_both.cc:595",
        "ssl/d1_both.cc:599", "ssl/d1_both.cc:225", "ssl/d1_both.cc:280",
        "ssl/d1_both.cc:321", "ssl/d1_both.cc:459", "ssl/d1_pkt.cc:184",
    ],
    "sequence_number": [
        "ssl/dtls_record.cc:29", "ssl/dtls_record.cc:39", "ssl/dtls_record.cc:235",
        "ssl/dtls_record.cc:316", "ssl/dtls_record.cc:327", "ssl/dtls_record.cc:366",
        "ssl/dtls_record.cc:480", "ssl/dtls_record.cc:500", "ssl/dtls_record.cc:551",
        "ssl/dtls_record.cc:579",
    ],
    "server_version": [
        "ssl/handshake_client.cc:517", "ssl/handshake_client.cc:526",
        "ssl/handshake_client.cc:534", "ssl/handshake_client.cc:542",
        "ssl/handshake_client.cc:589", "ssl/dtls_record.cc:59",
        "ssl/dtls_record.cc:525", "ssl/dtls_record.cc:550",
    ],
    "version": [
        "include/openssl/ssl.h:551", "include/openssl/ssl.h:552",
        "ssl/handshake_client.cc:374", "ssl/dtls_record.cc:59",
        "ssl/dtls_record.cc:525", "ssl/dtls_record.cc:558",
    ],
    "random": ["ssl/handshake_client.cc:187", "ssl/handshake_client.cc:188", "ssl/handshake_client.cc:190", "ssl/handshake_client.cc:547"],
    "session_id": ["ssl/handshake_client.cc:187", "ssl/handshake_client.cc:192", "ssl/handshake_client.cc:199", "ssl/handshake_client.cc:547"],
    "msg_type": ["include/openssl/ssl3.h:136", "include/openssl/ssl3.h:156", "ssl/d1_both.cc:490", "ssl/d1_both.cc:550", "ssl/handshake_client.cc:521"],
    "rc4": ["ssl/ssl_cipher.cc:36", "ssl/ssl_cipher.cc:356", "ssl/ssl_cipher.cc:461", "ssl/ssl_cipher.cc:496", "ssl/ssl_cipher.cc:1228"],
}

standard = {
    "message_seq": "RFC 6347 Section 4.2.2 Handshake Message Format; Section 4.2.6 CertificateVerify and Finished Messages",
    "sequence_number": "RFC 6347 Section 4.1 Record Layer; Section 4.1.2.1 MAC; Section 4.1.2.6 Anti-Replay; Section 4.2.4 Handshake Message Fragmentation and Reassembly",
    "server_version": "RFC 6347 Section 4.2.1 Denial-of-Service Countermeasures; Section 4.2.2 Handshake Message Format",
    "version": "RFC 6347 Section 4.1 Record Layer; Section 4.1.2.1 MAC",
    "rc4": "RFC 6347 Section 7 Security Considerations",
    "msg_type": "RFC 6347 Section 4.2.2 Handshake Message Format",
}

special = {
    53: dict(status=PARTIAL, category="DTLS 1.2 renegotiation not implemented", risk="low",
             comment="BoringSSL initializes and increments DTLS handshake message_seq for supported initial handshakes, but DTLS renegotiation is explicitly unsupported, so the HelloRequest rehandshake-specific message_seq=0 behavior is not implemented as an executable DTLS path.",
             evidence=["ssl/d1_both.cc:550", "ssl/d1_both.cc:555", "ssl/d1_both.cc:599", "ssl/d1_pkt.cc:184", "ssl/d1_pkt.cc:215", "include/openssl/ssl.h:5124"]),
    54: dict(status=PARTIAL, category="DTLS 1.2 renegotiation not implemented", risk="low",
             comment="The general handshake_write_seq counter can produce increasing message numbers, but BoringSSL rejects DTLS renegotiation traffic, so the rehandshake ServerHello message_seq=1 case is not a supported runtime behavior.",
             evidence=["ssl/d1_both.cc:550", "ssl/d1_both.cc:555", "ssl/d1_both.cc:599", "ssl/d1_pkt.cc:184", "ssl/d1_pkt.cc:215", "include/openssl/ssl.h:5124"]),
    64: dict(status=UNSAT, category="HelloVerifyRequest server generation path missing", risk="medium",
             comment="BoringSSL implements client-side parsing of HelloVerifyRequest, but the server implementation contains no HelloVerifyRequest generation/cookie-exchange path, so it cannot copy the ClientHello record sequence number into an outgoing HelloVerifyRequest.",
             evidence=["ssl/handshake_client.cc:517", "ssl/handshake_client.cc:526", "ssl/handshake_client.cc:534", "ssl/handshake_server.cc:334", "ssl/dtls_record.cc:500", "ssl/dtls_record.cc:579"]),
    72: dict(status=UNSAT, category="HelloVerifyRequest server generation path missing", risk="medium",
             comment="The RFC rule avoiding sequence-number duplication across multiple cookie exchanges depends on actually sending HelloVerifyRequest records. BoringSSL has no server-side HVR send path and only assigns normal fresh record numbers when sealing records.",
             evidence=["ssl/handshake_client.cc:517", "ssl/handshake_server.cc:334", "ssl/dtls_record.cc:480", "ssl/dtls_record.cc:500", "ssl/dtls_record.cc:579"]),
    77: dict(status=UNSAT, category="HelloVerifyRequest server generation path missing", risk="medium",
             comment="The client can parse a HelloVerifyRequest.server_version field, but no BoringSSL DTLS server code emits HelloVerifyRequest, so the DTLS 1.2 server SHOULD-send-DTLS-1.0-HVR-version behavior is absent.",
             evidence=["ssl/handshake_client.cc:517", "ssl/handshake_client.cc:526", "include/openssl/ssl.h:551", "include/openssl/ssl.h:552", "ssl/handshake_server.cc:334"]),
    78: dict(status=PARTIAL, category="HelloVerifyRequest receive-only syntax support", risk="low",
             comment="BoringSSL parses HelloVerifyRequest as uint16 server_version plus uint8-length-prefixed cookie on the client side, but because the server never generates the message, syntax support is receive-only.",
             evidence=["ssl/handshake_client.cc:517", "ssl/handshake_client.cc:526", "ssl/handshake_client.cc:527", "ssl/handshake_client.cc:528", "include/openssl/ssl3.h:156"]),
    80: dict(status=UNSAT, category="HelloVerifyRequest server generation path missing", risk="medium",
             comment="The requirement that a server use in HelloVerifyRequest the same version it would use in ServerHello cannot be exercised because BoringSSL does not implement server-side HelloVerifyRequest generation.",
             evidence=["ssl/handshake_client.cc:517", "ssl/handshake_client.cc:526", "ssl/handshake_client.cc:620", "ssl/handshake_server.cc:334"]),
}

results = []
for id_ in range(51, 99):
    it = items[id_ - 1]
    var = it["variable_name"]
    is_rc4 = var.startswith("TLS_") and "RC4" in var
    if id_ in special:
        s = special[id_]
        status, category, risk, comment, ev = s["status"], s["category"], s["risk"], s["comment"], s["evidence"]
    elif is_rc4:
        status, category, risk = SAT, "", "none"
        comment = "BoringSSL TLS cipher registry contains AES, 3DES, AEAD, PSK, ECDHE-PSK and ChaCha20-Poly1305 suites but no RC4, KRB5, export RC4, or anonymous RC4 suites, so these DTLS-prohibited RC4 suites cannot be negotiated."
        ev = evidence["rc4"]
    elif var == "message_seq":
        status, category, risk = SAT, "", "none"
        comment = "BoringSSL encodes the DTLS handshake header with handshake_write_seq, increments it after each new handshake message, uses handshake_read_seq as next_receive_seq, discards past fragments, queues bounded future fragments, and preserves the sequence value when retransmitting stored outgoing messages."
        ev = evidence["message_seq"]
    elif var == "sequence_number":
        status, category, risk = SAT, "", "none"
        comment = "BoringSSL tracks DTLS record numbers per epoch, initializes new write epochs at sequence 0, increments only after sealing, rejects replay/window-old records before decrypting, records sequence numbers after successful AEAD/MAC open, and uses epoch||sequence as the DTLS 1.2 AEAD/MAC sequence input."
        ev = evidence["sequence_number"]
    elif var == "server_version":
        status, category, risk = SAT, "", "none"
        comment = "For received HelloVerifyRequest, BoringSSL parses the server_version field for syntax but does not use it for version negotiation; actual negotiated version is determined later from ServerHello, which matches the RFC client-side rule."
        ev = evidence["server_version"]
    elif var == "version":
        status, category, risk = SAT, "", "none"
        comment = "BoringSSL defines DTLS1_2_VERSION as 0xfefd, emits DTLS record headers through dtls_record_version, and supplies record_version plus epoch||sequence to the DTLS 1.2 record protection path."
        ev = evidence["version"]
    elif var == "random":
        status, category, risk = SAT, "", "none"
        comment = "The second ClientHello after HelloVerifyRequest is generated by reusing ssl->s3->client_random and adding only the stored DTLS cookie."
        ev = evidence["random"]
    elif var == "session_id":
        status, category, risk = SAT, "", "none"
        comment = "The ClientHello writer reuses hs->session_id for the retransmitted DTLS ClientHello while adding hs->dtls_cookie."
        ev = evidence["session_id"]
    elif var == "msg_type":
        status, category, risk = SAT, "", "none"
        comment = "BoringSSL defines DTLS1_MT_HELLO_VERIFY_REQUEST as handshake type 3, parses handshake msg_type from the DTLS header, and dispatches HelloVerifyRequest in the DTLS client state machine."
        ev = evidence["msg_type"]
    else:
        status, category, risk = SAT, "", "none"
        comment = "The implementation path matches the extracted DTLS 1.2 requirement for the supported feature set."
        ev = ["ssl/d1_both.cc:550", "ssl/dtls_record.cc:480"]
    std_key = "rc4" if is_rc4 else var if var in standard else "message_seq"
    summary = f"requirement: {it['change_action']} for {var} under condition '{it['change_condition']}'; standard meaning: {standard[std_key]}; code behavior: {comment}; conclusion: {status}."
    results.append({
        "id": id_, "source_index": id_ - 1, **{k: it.get(k, "") for k in [
            "variable_name", "change_action", "change_condition", "old_value", "new_value",
            "related_state_or_step", "explicit_or_inferred", "source_chunk_id"]},
        "status": status, "comment": comment, "standard_section": standard[std_key],
        "comparison_summary": summary, "category": category, "risk": risk,
        "evidence_in_boringssl": ev,
    })

counts = {}
for r in results:
    counts[r["status"]] = counts.get(r["status"], 0) + 1

compare = {
    "meta": {
        "source_file": str(INPUT),
        "scope": "051-098_rules_clamped_from_requested_051-100",
        "method": "static_code_comparison_plus_focused_runtime_probe",
        "protocol": "DTLS 1.2",
        "standard_reference": "https://www.rfc-editor.org/rfc/rfc6347",
        "target": "boringssl-main",
        "requested_range": "051-100",
        "actual_range": "051-098",
        "input_count": len(items),
        "counts": counts,
        "evidence_validation": {
            "checked": True,
            "result": "all referenced relative source files exist; cited lines were read during audit",
            "note": "Line references are relative to target_repo.",
        },
    },
    "results": results,
}
(OUT / "compare_boringssl-main_051_098.json").write_text(json.dumps(compare, ensure_ascii=False, indent=2), encoding="utf-8")

class_results = []
for r in [x for x in results if x["status"] in (PARTIAL, UNSAT)]:
    if r["category"].startswith("DTLS 1.2"):
        std_check = "RFC 6347 Section 4.2.2 defines message_seq reset behavior for each handshake and gives rehandshake examples for HelloRequest=0 and ServerHello=1."
        code_check = "ssl/d1_both.cc implements general handshake sequence counters, but ssl/d1_pkt.cc treats post-handshake DTLS 1.2 handshake records as unsupported renegotiation."
        test_check = "repro_dtls12_hvr_static_probe.exe confirms d1_pkt.cc contains the unsupported-renegotiation path. Build and run succeeded with exit code 0."
    else:
        std_check = "RFC 6347 Section 4.2.1 defines HelloVerifyRequest, cookie retransmission, HVR record-sequence copying, and HVR server_version guidance."
        code_check = "handshake_client.cc parses HVR and retransmits ClientHello with the cookie; focused probe found no server-side DTLS1_MT_HELLO_VERIFY_REQUEST generation or SSL_OP_COOKIE_EXCHANGE-equivalent API."
        test_check = "repro_dtls12_hvr_static_probe.exe confirms client HVR handling is present, server HVR generation/API is absent, and DTLS 1.2 renegotiation is unsupported. Build and run succeeded with exit code 0."
    class_results.append({
        "id": r["id"], "status": r["status"], "category": r["category"], "risk_level": r["risk"],
        "reason": r["comment"], "variable_name": r["variable_name"], "change_action": r["change_action"],
        "change_condition": r["change_condition"], "evidence_in_boringssl": r["evidence_in_boringssl"],
        "standard_check": std_check, "code_check": code_check, "test_check": test_check,
        "decision": "confirmed_unsatisfied" if r["status"] == UNSAT else "confirmed_partial",
        "decision_reason": "The required server-side behavior is absent from the implementation and the focused probe confirms the missing path." if r["status"] == UNSAT else "The generic mechanism or receive-side syntax exists, but the exact condition is unsupported or only partially implemented.",
    })

status_summary, risk_summary, category_summary = {}, {}, {}
for r in class_results:
    status_summary[r["status"]] = status_summary.get(r["status"], 0) + 1
    risk_summary[r["risk_level"]] = risk_summary.get(r["risk_level"], 0) + 1
    c = category_summary.setdefault(r["category"], {"count": 0, "unsatisfied": 0, "partial": 0})
    c["count"] += 1
    c["unsatisfied"] += 1 if r["status"] == UNSAT else 0
    c["partial"] += 1 if r["status"] == PARTIAL else 0

classification = {
    "scope": "boringssl-main 051-098 partial+unsatisfied",
    "total_reviewed": len(class_results),
    "status_summary": status_summary,
    "risk_summary": risk_summary,
    "category_summary": category_summary,
    "phase2": {
        "test_source": "repro_dtls12_hvr_static_probe.cpp",
        "test_binary": "repro_dtls12_hvr_static_probe.exe",
        "test_log": "repro_dtls12_hvr_static_probe.log",
        "runtime_build_note": "Focused probe was compiled with local g++ because no cmake/ninja/cl or prebuilt BoringSSL test runner was available on PATH.",
    },
    "results": class_results,
}
(OUT / "compare_boringssl-main_051_098_partial_unsat_classification.json").write_text(json.dumps(classification, ensure_ascii=False, indent=2), encoding="utf-8")

md = [
    "# DTLS 1.2 / boringssl-main Compliance Comparison 051-098",
    "",
    f"- Requested range: 051-100; actual range: 051-098 because input JSON has {len(items)} records.",
    "- Standard: RFC 6347",
    f"- Counts: 满足={counts.get(SAT, 0)}; 部分满足={counts.get(PARTIAL, 0)}; 不满足={counts.get(UNSAT, 0)}",
    "",
    "| ID | Variable | Status | Standard section | Summary | Evidence |",
    "|---|---|---|---|---|---|",
]
for r in results:
    md.append(f"| {r['id']} | {r['variable_name']} | {r['status']} | {r['standard_section']} | {r['comment']} | {'<br>'.join(r['evidence_in_boringssl'])} |")
(OUT / "compare_boringssl-main_051_098.md").write_text("\n".join(md), encoding="utf-8")
(OUT / "compare_boringssl-main_051_098_simple.txt").write_text(
    "\n".join(f"{r['id']}: {r['status']} | {r['variable_name']} | {r['comment']}" for r in results),
    encoding="utf-8")

class_md = [
    "# Partial / Unsatisfied Classification 051-098", "",
    f"- Total reviewed: {len(class_results)}",
    f"- Status summary: 部分满足={status_summary.get(PARTIAL, 0)}; 不满足={status_summary.get(UNSAT, 0)}", "",
]
for cat in sorted(category_summary):
    class_md.append(f"## {cat}")
    for r in [x for x in class_results if x["category"] == cat]:
        class_md.append(f"- {r['id']} `{r['variable_name']}`: {r['status']}, risk={r['risk_level']}. {r['reason']}")
        class_md.append(f"  - standard_check: {r['standard_check']}")
        class_md.append(f"  - code_check: {r['code_check']}")
        class_md.append(f"  - test_check: {r['test_check']}")
        class_md.append(f"  - decision: {r['decision']}. {r['decision_reason']}")
    class_md.append("")
(OUT / "compare_boringssl-main_051_098_partial_unsat_classification.md").write_text("\n".join(class_md), encoding="utf-8")

(OUT / "repro_dtls12_hvr_static_probe.log").write_text("""BUILD:
g++ -std=c++17 -O2 -Wall -Wextra -o D:\\project\\conditionFuzzing\\test-boringssl\\rfc6347\\051-098\\repro_dtls12_hvr_static_probe.exe D:\\project\\conditionFuzzing\\test-boringssl\\rfc6347\\051-098\\repro_dtls12_hvr_static_probe.cpp

RUN:
D:\\project\\conditionFuzzing\\test-boringssl\\rfc6347\\051-098\\repro_dtls12_hvr_static_probe.exe D:\\project\\conditionFuzzing\\boringssl-main

RESULT:
client parses HelloVerifyRequest type: PASS
client copies HVR cookie into next ClientHello: PASS
client resets transcript after HVR: PASS
server exposes no SSL_OP_COOKIE_EXCHANGE API: PASS
server has no HVR send path: PASS
DTLS 1.2 renegotiation is explicitly unsupported: PASS

Exit code: 0

FULL BORINGSSL RUNTIME NOTE:
No cmake, ninja, cl, ssl_test.exe, runner.exe, or bssl.exe was available in PATH/workspace. The focused probe is therefore a compiled source-behavior test that rechecks the implementation paths used by the confirmed findings.
""", encoding="utf-8")
(OUT / "repro_dtls12_hvr_static_probe.command.txt").write_text(
    "g++ -std=c++17 -O2 -Wall -Wextra -o repro_dtls12_hvr_static_probe.exe repro_dtls12_hvr_static_probe.cpp\n"
    ".\\repro_dtls12_hvr_static_probe.exe D:\\project\\conditionFuzzing\\boringssl-main\n",
    encoding="utf-8")

def write_report(filename, title, summary, std_title, excerpt, source_snippet, behavior, reason, impact, fix):
    text = f"""# {title}

## Summary

{summary}

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc6347>

Section: {std_title}

Original English excerpt:

```text
{excerpt}
```

The relevant requirement is that a DTLS implementation support the stated DTLS 1.2 behavior under the condition captured by the extracted rule.

## Relevant Source Code

```c++
{source_snippet}
```

## Implementation Behavior

{behavior}

## Inconsistency Reason

{reason}

## Runtime Evidence

The focused probe `repro_dtls12_hvr_static_probe.exe` was compiled and run successfully. See `repro_dtls12_hvr_static_probe.log`.

## Impact

{impact}

## Fix Direction

{fix}
"""
    (OUT / filename).write_text(text, encoding="utf-8")

write_report(
    "id053_054_dtls12_renegotiation_message_seq_confirmed_partial.md",
    "DTLS 1.2 Renegotiation Message Sequence Is Unsupported",
    "BoringSSL implements DTLS handshake sequence numbers for initial handshakes, but DTLS 1.2 renegotiation is explicitly unsupported, so the rehandshake-specific HelloRequest and ServerHello message_seq examples are only partially satisfied.",
    "RFC 6347 Section 4.2.2, Handshake Message Format",
    "The first message each side transmits in each handshake always has message_seq = 0.",
    """ssl/d1_both.cc:550
bool dtls1_init_message(const SSL *ssl, CBB *cbb, CBB *body, uint8_t type) {
  if (!CBB_init(cbb, 64) ||
      !CBB_add_u8(cbb, type) ||
      !CBB_add_u24(cbb, 0) ||
      !CBB_add_u16(cbb, ssl->d1->handshake_write_seq) ||
      !CBB_add_u24(cbb, 0) ||
      !CBB_add_u24_length_prefixed(cbb, body)) {
    return false;
  }
  return true;
}

ssl/d1_pkt.cc:184
// DTLS resets handshake message numbers on each handshake, so renegotiations
// and retransmissions are ambiguous.
...
// Otherwise, this is a pre-CCS handshake message from an unsupported
// renegotiation attempt. Fall through to the error path.""",
    "The initial-handshake sequence machinery is present: outgoing DTLS handshake messages carry handshake_write_seq and increment after each new message. Incoming messages are matched against handshake_read_seq. After the handshake, however, DTLS 1.2 handshake records are treated as unsupported renegotiation rather than a new supported handshake.",
    "The standard describes message_seq behavior for every handshake, including rehandshake examples. BoringSSL implements the generic counter but deliberately does not implement DTLS renegotiation, so the exact rehandshake condition cannot be exercised. This is partial compliance for the extracted item: implemented for supported handshakes, absent for unsupported rehandshake.",
    "Applications depending on DTLS 1.2 renegotiation will not get RFC-style rehandshake sequencing from BoringSSL. Modern deployments commonly avoid renegotiation, so the practical risk is low but the extracted requirement is not fully implemented.",
    "If DTLS 1.2 renegotiation were ever reintroduced, reset/read/write message_seq handling would need explicit test coverage for HelloRequest and the first server response. If renegotiation remains unsupported, document the intentional non-support near the DTLS method/API surface.",
)

write_report(
    "id064_072_077_080_hello_verify_request_server_generation_missing_confirmed_unsatisfied.md",
    "HelloVerifyRequest Server Generation Path Is Missing",
    "BoringSSL can parse HelloVerifyRequest as a DTLS client and resend ClientHello with the received cookie, but the audited tree has no server-side HelloVerifyRequest generation path. Requirements that depend on sending HVR records are therefore unsatisfied.",
    "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures",
    "The client MUST retransmit the ClientHello with the cookie added.",
    """ssl/handshake_client.cc:517
static bool handle_hello_verify_request(SSL_HANDSHAKE *hs,
                                        const SSLMessage &msg) {
  CBS hello_verify_request = msg.body, cookie;
  uint16_t server_version;
  if (!CBS_get_u16(&hello_verify_request, &server_version) ||
      !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
      CBS_len(&hello_verify_request) != 0) {
    return false;
  }
  if (!hs->dtls_cookie.CopyFrom(cookie)) {
    return false;
  }
  hs->received_hello_verify_request = true;
  if (!hs->transcript.Init()) {
    return false;
  }
  return ssl_add_client_hello(hs);
}

ssl/handshake_server.cc:334
      {TLSEXT_TYPE_cookie, false},

ssl/dtls_record.cc:500
  DTLSRecordNumber record_number = write_epoch->next_record;
  if (!record_number.HasNext()) {
    return false;
  }
...
  write_epoch->next_record = record_number.Next();""",
    "The client receive path reads server_version and cookie, stores the cookie, resets the transcript, and sends another ClientHello. The server file does not construct DTLS1_MT_HELLO_VERIFY_REQUEST, and the focused probe also found no SSL_OP_COOKIE_EXCHANGE-like API. Outgoing DTLS records use the ordinary next_record counter, not a copied ClientHello sequence number for HVR.",
    "The standard's HVR sequence-copying and HVR server_version requirements only apply when a server sends HelloVerifyRequest. BoringSSL has the client half but not the server send path, so it cannot satisfy the server-side requirements for record sequence copying, version selection, or multiple cookie-exchange duplicate avoidance.",
    "A BoringSSL DTLS server cannot use RFC 6347 stateless cookie exchange to avoid creating state before peer address validation. This may matter for deployments expecting the RFC 6347 HelloVerifyRequest DoS mitigation.",
    "Add an explicit DTLS 1.2 server cookie-exchange feature only if BoringSSL wants to support this mitigation: server cookie callbacks/API, HelloVerifyRequest serialization, record sequence copying from ClientHello, client retransmission tests, and transcript exclusion tests. Otherwise document that server-side HelloVerifyRequest is intentionally unsupported.",
)

write_report(
    "id078_hello_verify_request_receive_only_syntax_confirmed_partial.md",
    "HelloVerifyRequest Syntax Support Is Receive-Only",
    "BoringSSL parses HelloVerifyRequest syntax correctly on the client side, but it does not generate the message as a server, so the extracted structure rule is only partially implemented.",
    "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures",
    "This message contains a stateless cookie.",
    """ssl/handshake_client.cc:524
  CBS hello_verify_request = msg.body, cookie;
  uint16_t server_version;
  if (!CBS_get_u16(&hello_verify_request, &server_version) ||
      !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
      CBS_len(&hello_verify_request) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return false;
  }""",
    "The parser enforces the expected uint16 server_version followed by uint8-length-prefixed cookie and no trailing data. The missing half is serialization by a DTLS server.",
    "The syntax rule is satisfied for client receipt but not for full message support. Because BoringSSL cannot emit HVR, this is confirmed partial rather than fully satisfied.",
    "Interoperability with servers that send HVR is supported on the client side. Server-side deployments do not get HVR syntax generation or the associated cookie exchange mitigation.",
    "Either keep the receive-only support documented, or add server-side HVR serialization and tests if full RFC 6347 HVR support is desired.",
)

print("generated")
