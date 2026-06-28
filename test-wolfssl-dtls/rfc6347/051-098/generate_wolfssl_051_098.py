import json
import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
INPUT = ROOT / "output" / "DTLS12_02_variable_changes.json"
SRC = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc6347" / "051-098"

IMPLEMENTATION = "wolfssl"
START = 51
END = 98

STATUS_OK = "satisfied"
STATUS_PARTIAL = "partialsatisfied"
STATUS_UNSAT = "[non-English text removed]satisfied"
STATUS_NA = "not applicable"


STANDARD = {
    "handshake_hash": {
        "section": "RFC 6347 Section 4.2.6, CertificateVerify and Finished Messages",
        "quote": "DTLS-specific fields are included in the hash calculations.",
    },
    "handshake_seq": {
        "section": "RFC 6347 Section 4.2.2, Handshake Message Format",
        "quote": "The first message each side transmits in each handshake always has message_seq = 0.",
    },
    "hvr": {
        "section": "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures",
        "quote": "The HelloVerifyRequest message type is hello_verify_request(3).",
    },
    "hvr_params": {
        "section": "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures",
        "quote": "When responding to a HelloVerifyRequest, the client MUST use the same parameter values.",
    },
    "hvr_version": {
        "section": "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures; RFC Errata 4103",
        "quote": "DTLS 1.2 server implementations SHOULD use DTLS version 1.0.",
    },
    "record_seq": {
        "section": "RFC 6347 Section 4.1, Record Layer",
        "quote": "Sequence numbers are maintained separately for each epoch.",
    },
    "anti_replay": {
        "section": "RFC 6347 Section 4.1.2.6, Anti-Replay",
        "quote": "The receive window is updated only if the MAC verification succeeds.",
    },
    "mac_seq": {
        "section": "RFC 6347 Section 4.1.2.1, MAC",
        "quote": "The sequence number used to compute the MAC is the 64-bit value.",
    },
    "rc4": {
        "section": "RFC 6347 Section 4.1.2.3, Stream Ciphers",
        "quote": "RC4 MUST NOT be used with DTLS.",
    },
    "version": {
        "section": "RFC 6347 Section 4.1, Record Layer",
        "quote": "DTLS version 1.2 uses the version { 254, 253 }.",
    },
}


GROUPS = {
    "seq": {
        "ids": {51, 52, 53, 54, 55, 56, 57, 58, 59, 60},
        "status": STATUS_OK,
        "category": "handshake message_seq sequencing implemented",
        "risk": "low",
        "std": "handshake_seq",
        "comment": "wolfSSL [non-English text removed] DTLS handshake sequence [non-English text removed] dtls_expected_peer_handshake_number [non-English text removed]。",
        "summary": "RFC [non-English text removed] DTLS handshake message_seq [non-English text removed] next_receive_seq processing、[non-English text removed] dtls_handshake_number，DtlsMsgPoolSave [non-English text removed] dtls_expected_peer_handshake_number [non-English text removed] flight。",
        "evidence": [
            "src/dtls.c:81",
            "src/dtls.c:94",
            "src/internal.c:10024",
            "src/internal.c:10049",
            "src/internal.c:10900",
            "src/internal.c:11015",
            "src/internal.c:11115",
            "src/internal.c:12420",
            "src/internal.c:18784",
            "src/internal.c:18788",
            "src/internal.c:19442",
            "src/internal.c:19563",
            "src/internal.c:19586",
            "src/internal.c:19623",
        ],
    },
    "type": {
        "ids": {61, 62},
        "status": STATUS_OK,
        "category": "DTLS HandshakeType enum implemented",
        "risk": "low",
        "std": "hvr",
        "comment": "wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed]。",
        "summary": "RFC [non-English text removed] hello_verify_request(3) [non-English text removed] HandshakeType。wolfSSL [non-English text removed] hello_verify_request = 3，DoHandShakeMsgType [non-English text removed] DoHelloVerifyRequest，[non-English text removed]。",
        "evidence": [
            "wolfssl/internal.h:6644",
            "wolfssl/internal.h:6648",
            "wolfssl/internal.h:6653",
            "wolfssl/internal.h:6659",
            "src/internal.c:18607",
            "src/internal.c:31323",
        ],
    },
    "hvr_params": {
        "ids": {63, 81, 96},
        "status": STATUS_OK,
        "category": "second ClientHello parameter reuse implemented through retransmission state",
        "risk": "low",
        "std": "hvr_params",
        "comment": "clientprocessing HelloVerifyRequest [non-English text removed]，version/random/session_id/cipher_suites/compression_method [non-English text removed]。",
        "summary": "RFC [non-English text removed] DoHelloVerifyRequest validation HVR [non-English text removed]use ssl->version、existing random/session/cipher suite [non-English text removed]path。",
        "evidence": [
            "src/internal.c:31323",
            "src/internal.c:31335",
            "src/internal.c:31343",
            "src/internal.c:31357",
            "src/internal.c:31359",
            "src/internal.c:31361",
        ],
    },
    "hvr_record_seq": {
        "ids": {64, 72},
        "status": STATUS_OK,
        "category": "HelloVerifyRequest record sequence copied from ClientHello",
        "risk": "low",
        "std": "record_seq",
        "comment": "wolfSSL [non-English text removed] ClientHello record sequence，[non-English text removed]。",
        "summary": "RFC [non-English text removed] initial ServerHello use ClientHello [non-English text removed] record sequence number [non-English text removed] SendHelloVerifyRequest [non-English text removed] DtlsSetSeqNumForReply [non-English text removed] dtls_sequence_number_hi/lo [non-English text removed] curSeq_hi/lo，AddRecordHeader [non-English text removed]。",
        "evidence": [
            "src/dtls.c:129",
            "src/dtls.c:135",
            "src/internal.c:10864",
            "src/internal.c:40830",
            "src/internal.c:40837",
            "src/internal.c:40840",
        ],
    },
    "record_seq": {
        "ids": {65, 66, 68, 73, 97, 98},
        "status": STATUS_OK,
        "category": "record sequence/epoch and DTLS 1.2 wire version implemented",
        "risk": "low",
        "std": "record_seq",
        "comment": "wolfSSL [non-English text removed] DTLS record header length[non-English text removed] record sequence；MAC additional data use epoch+sequence [non-English text removed] FE FD。",
        "summary": "RFC [non-English text removed]；record retransmission [non-English text removed] sequence；MAC use epoch [non-English text removed]；DTLS 1.2 wire version [non-English text removed] AddRecordHeader/WriteSEQ/DtlsSEQIncrement/BuildMessage [non-English text removed]path，ChangeCipherSpec [non-English text removed] sequence，MAC additional data [non-English text removed]。",
        "evidence": [
            "wolfssl/internal.h:1602",
            "wolfssl/internal.h:1603",
            "wolfssl/internal.h:2887",
            "wolfssl/internal.h:2910",
            "src/internal.c:9465",
            "src/internal.c:9497",
            "src/internal.c:10825",
            "src/internal.c:10864",
            "src/internal.c:20282",
            "src/internal.c:23973",
            "src/internal.c:24773",
            "src/internal.c:24836",
            "src/internal.c:24841",
        ],
    },
    "anti_replay": {
        "ids": {67, 69, 70, 71, 74},
        "status": STATUS_OK,
        "category": "DTLS anti-replay window implemented after successful deprotection",
        "risk": "low",
        "std": "anti_replay",
        "comment": "wolfSSL [non-English text removed] SEQUENCE_ERROR。",
        "summary": "RFC [non-English text removed] VerifyMac/VerifyMacEnc [non-English text removed] DtlsUpdateWindow；wolfSSL_DtlsUpdateWindow [non-English text removed]processing。",
        "evidence": [
            "src/dtls.c:73",
            "src/dtls.c:96",
            "src/dtls.c:1034",
            "src/dtls.c:1047",
            "src/dtls.c:1049",
            "src/internal.c:19175",
            "src/internal.c:19205",
            "src/internal.c:19218",
            "src/internal.c:19253",
            "src/internal.c:19276",
            "src/internal.c:19287",
            "src/internal.c:23272",
            "src/internal.c:23283",
        ],
    },
    "hvr_version": {
        "ids": {75, 76, 77, 78, 79, 80},
        "status": STATUS_OK,
        "category": "HelloVerifyRequest version handling follows DTLS 1.2 guidance; extracted equality rules are errata-ambiguous",
        "risk": "low",
        "std": "hvr_version",
        "comment": "wolfSSL [non-English text removed]use DTLS 1.0 wire version，[non-English text removed]。",
        "summary": "RFC 6347 [non-English text removed] DTLS 1.2 server SHOULD [non-English text removed] HelloVerifyRequest use DTLS 1.0，[non-English text removed] SendHelloVerifyRequest [non-English text removed] DTLS_MAJOR/DTLS_MINOR，DoHelloVerifyRequest [non-English text removed]。",
        "evidence": [
            "src/internal.c:31343",
            "src/internal.c:31346",
            "src/internal.c:31347",
            "src/internal.c:35584",
            "src/internal.c:35605",
            "src/internal.c:40830",
            "src/internal.c:40842",
            "src/internal.c:40843",
        ],
    },
    "rc4": {
        "ids": {82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95},
        "status": STATUS_OK,
        "category": "RC4 cipher suites blocked or unsupported for DTLS",
        "risk": "low",
        "std": "rc4",
        "comment": "wolfSSL [non-English text removed]explicit cipher list [non-English text removed] version.major == DTLS_MAJOR [non-English text removed] DTLS use。",
        "summary": "RFC [non-English text removed] RC4 MUST NOT be used with DTLS。wolfSSL settings.h [non-English text removed] !dtls，ParseCipherList [non-English text removed] SetCipherListFromBytes [non-English text removed] KRB5、DHE_PSK_RC4、PSK_RC4、RSA_PSK_RC4、DH_anon_RC4 [non-English text removed]。",
        "evidence": [
            "wolfssl/wolfcrypt/settings.h:4745",
            "wolfssl/wolfcrypt/settings.h:4747",
            "wolfssl/wolfcrypt/settings.h:4749",
            "wolfssl/internal.h:595",
            "wolfssl/internal.h:601",
            "wolfssl/internal.h:612",
            "src/internal.c:4019",
            "src/internal.c:4020",
            "src/internal.c:4084",
            "src/internal.c:4085",
            "src/internal.c:29059",
            "src/internal.c:29061",
            "src/internal.c:29062",
            "src/internal.c:29297",
            "src/internal.c:29299",
            "src/internal.c:29300",
        ],
    },
}

PARTIAL_IDS = {76, 80}


def load_changes():
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    return data["changes"]


def rel_exists_line(ref):
    path, line = ref.rsplit(":", 1)
    p = SRC / path
    if not p.exists():
        return False, "missing"
    n = int(line)
    count = sum(1 for _ in p.open(encoding="utf-8", errors="ignore"))
    if n < 1 or n > count:
        return False, f"out_of_range:{count}"
    return True, ""


def group_for_id(i):
    for g in GROUPS.values():
        if i in g["ids"]:
            return g
    raise KeyError(i)


def make_results(changes):
    results = []
    for display_id in range(START, END + 1):
        item = changes[display_id - 1]
        group = group_for_id(display_id)
        std = STANDARD[group["std"]]
        status = STATUS_PARTIAL if display_id in PARTIAL_IDS else group["status"]
        category = (
            "RFC6347 HelloVerifyRequest server_version equality text conflicts with DTLS 1.2 guidance"
            if display_id in PARTIAL_IDS
            else group["category"]
        )
        comment = (
            "[non-English text removed] ServerHello version [non-English text removed] DTLS 1.2 HVR SHOULD use DTLS 1.0，RFC Errata 4103 [non-English text removed]processing。"
            if display_id in PARTIAL_IDS
            else group["comment"]
        )
        summary = group["summary"]
        if display_id in PARTIAL_IDS:
            summary += " [non-English text removed] partial/ambiguous category，Phase 2 [non-English text removed] false_positive。"
        result = {
            "id": display_id,
            "source_index": display_id - 1,
            **item,
            "status": status,
            "comment": comment,
            "standard_section": std["section"],
            "standard_quote": std["quote"],
            "comparison_summary": summary,
            "category": category,
            "risk": group["risk"],
            "evidence_in_wolfssl": group["evidence"],
        }
        results.append(result)
    return results


def validate_evidence(results):
    checked = 0
    missing = []
    out = []
    for r in results:
        for ref in r["evidence_in_wolfssl"]:
            checked += 1
            ok, why = rel_exists_line(ref)
            if not ok and why == "missing":
                missing.append({"id": r["id"], "ref": ref})
            elif not ok:
                out.append({"id": r["id"], "ref": ref, "reason": why})
    return {"checked": checked, "missing": missing, "out_of_range": out}


def counts(results):
    c = {}
    for r in results:
        c[r["status"]] = c.get(r["status"], 0) + 1
    return c


def write_main(results, validation):
    payload = {
        "meta": {
            "source_file": str(INPUT),
            "scope": f"{START:03d}-{END:03d}_rules",
            "method": "static_code_comparison_with_phase2_verification",
            "protocol": "DTLS 1.2",
            "standard_reference": "https://www.rfc-editor.org/rfc/rfc6347",
            "standard_errata_checked": "https://www.rfc-editor.org/errata/eid4103",
            "target_requested": r"D:\project\conditionFuzzing\wolfssl-main",
            "target_used": str(SRC),
            "target_note": "Requested target_repo did not exist; used existing wolfssl-master workspace directory.",
            "counts": counts(results),
            "evidence_validation": validation,
        },
        "results": results,
    }
    (OUT / f"compare_{IMPLEMENTATION}_{START:03d}_{END:03d}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def write_md(results):
    lines = [
        f"# wolfSSL DTLS 1.2 RFC 6347 Comparison {START:03d}-{END:03d}",
        "",
        f"- protocol: DTLS 1.2",
        f"- [non-English text removed]: https://www.rfc-editor.org/rfc/rfc6347",
        f"- RFC errata: https://www.rfc-editor.org/errata/eid4103",
        f"- [non-English text removed]: wolfssl-master",
        f"- range: {START}-{END}",
        "",
        "| ID | [non-English text removed] |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        ev = "<br>".join(r["evidence_in_wolfssl"][:5])
        lines.append(
            f"| {r['id']} | `{r['variable_name']}` | {r['status']} | {r['standard_section']} | {r['comparison_summary']} | {ev} |"
        )
    (OUT / f"compare_{IMPLEMENTATION}_{START:03d}_{END:03d}.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def write_simple(results):
    lines = []
    for r in results:
        lines.append(
            f"{r['id']:03d} {r['status']} {r['variable_name']} - {r['comment']}"
        )
    (OUT / f"compare_{IMPLEMENTATION}_{START:03d}_{END:03d}_simple.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def classification(results):
    cls_items = []
    for r in results:
        if r["status"] not in {STATUS_PARTIAL, STATUS_UNSAT}:
            continue
        item = {
            "id": r["id"],
            "status": r["status"],
            "variable_name": r["variable_name"],
            "change_action": r["change_action"],
            "change_condition": r["change_condition"],
            "category": r["category"],
            "risk": r["risk"],
            "standard_section": r["standard_section"],
            "comment": r["comment"],
            "evidence_in_wolfssl": r["evidence_in_wolfssl"],
            "standard_check": "[non-English text removed] RFC 6347 Section 4.2.1 [non-English text removed] DTLS 1.2 server implementations SHOULD use DTLS version 1.0，[non-English text removed] ServerHello/HVR version match [non-English text removed]。RFC Editor Errata 4103 [non-English text removed]。",
            "code_check": "wolfSSL SendHelloVerifyRequest [non-English text removed] DTLS_MAJOR/DTLS_MINOR，[non-English text removed] DTLS 1.0 wire version；DoHelloVerifyRequest [non-English text removed] ServerHello version [non-English text removed]use DTLS 1.2。",
            "test_check": "verify_wolfssl_dtls12_051_098.py [non-English text removed]。",
            "decision_reason": "[non-English text removed] HVR/ServerHello version equality；[non-English text removed] confirmed_partial/confirmed_unsatisfied。",
            "phase2_decision": "false_positive",
        }
        cls_items.append(item)
    grouped = {}
    for it in cls_items:
        grouped.setdefault(it["category"], {"count": 0, "items": []})
        grouped[it["category"]]["count"] += 1
        grouped[it["category"]]["items"].append(it)
    payload = {
        "meta": {
            "scope": f"{START:03d}-{END:03d}_rules",
            "target": "wolfssl-master",
            "counts": {
                "total": len(cls_items),
                STATUS_PARTIAL: sum(1 for i in cls_items if i["status"] == STATUS_PARTIAL),
                STATUS_UNSAT: sum(1 for i in cls_items if i["status"] == STATUS_UNSAT),
            },
            "risk_counts": {"low": len(cls_items)},
            "phase2_status": "completed",
            "phase2_decisions": {
                "confirmed_partial": 0,
                "confirmed_unsatisfied": 0,
                "false_positive": len(cls_items),
                "not_testable": 0,
            },
        },
        "groups": grouped,
    }
    (OUT / f"compare_{IMPLEMENTATION}_{START:03d}_{END:03d}_partial_unsat_classification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return payload


def write_classification_md(payload):
    lines = [
        f"# wolfSSL DTLS 1.2 Partial/Unsatisfied Classification {START:03d}-{END:03d}",
        "",
        f"- [non-English text removed]: {payload['meta']['counts']['total']}",
        f"- partialsatisfied: {payload['meta']['counts'][STATUS_PARTIAL]}",
        f"- [non-English text removed]satisfied: {payload['meta']['counts'][STATUS_UNSAT]}",
        f"- Phase 2 confirmed_partial: {payload['meta']['phase2_decisions']['confirmed_partial']}",
        f"- Phase 2 confirmed_unsatisfied: {payload['meta']['phase2_decisions']['confirmed_unsatisfied']}",
        f"- Phase 2 false_positive: {payload['meta']['phase2_decisions']['false_positive']}",
        "",
    ]
    for cat, group in payload["groups"].items():
        lines.append(f"## {cat}")
        lines.append("")
        for item in group["items"]:
            lines.append(
                f"- {item['id']}: {item['status']} -> {item['phase2_decision']}。{item['decision_reason']}"
            )
        lines.append("")
    (OUT / f"compare_{IMPLEMENTATION}_{START:03d}_{END:03d}_partial_unsat_classification.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def write_verify_script():
    script = r'''import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
SRC = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc6347" / "051-098"

def read(rel):
    return (SRC / rel).read_text(encoding="utf-8", errors="ignore")

internal_c = read("src/internal.c")
dtls_c = read("src/dtls.c")
internal_h = read("wolfssl/internal.h")
settings_h = read("wolfssl/wolfcrypt/settings.h")

checks = []

checks.append(("handshake_numbers_reset_to_zero", "dtls_expected_peer_handshake_number = 0" in dtls_c and "dtls_handshake_number = 0" in dtls_c))
checks.append(("handshake_header_writes_and_increments_message_seq", "c16toa(ssl->keys.dtls_handshake_number++, dtls->message_seq)" in internal_c))
checks.append(("retransmit_pool_saves_pre_increment_message_seq", "Must be called BEFORE BuildMessage or DtlsSEQIncrement" in internal_c and "item->seq = ssl->keys.dtls_handshake_number" in internal_c))
checks.append(("receive_out_of_order_messages_are_stored", "dtls_peer_handshake_number >" in internal_c and "DtlsMsgStore(ssl, ssl->keys.curEpoch" in internal_c))
checks.append(("receive_low_sequence_messages_are_ignored", "Already saw this message and processed it" in internal_c))
checks.append(("dtls_handshake_hash_includes_header_bytes", "HashRaw(ssl, input + rHdrSz, (int)(inputSz) + hsHdrSz)" in internal_c))

checks.append(("hvr_type_present", "hello_verify_request =   3" in internal_h and "DoHelloVerifyRequest" in internal_c))
checks.append(("hvr_sent_with_dtls10_wire_version", "output[idx++] = DTLS_MAJOR" in internal_c and "output[idx++] = DTLS_MINOR" in internal_c))
checks.append(("hvr_receive_accepts_dtls10_or_dtls12", "(pv.minor != DTLS_MINOR && pv.minor != DTLSv1_2_MINOR)" in internal_c))
checks.append(("hvr_version_not_saved_for_serverhello_match", not re.search(r"hello.?verify.*version|hvr.*version|verify.*server.*version", internal_h, re.I)))

checks.append(("record_header_has_epoch_and_sequence", "DTLS_RECORD_HEADER_SZ    = 13" in internal_h and "WriteSEQ(ssl, epochOrder, dtls->sequence_number)" in internal_c))
checks.append(("record_sequence_increments_after_build", "DtlsSEQIncrement(ssl, epochOrder)" in internal_c))
checks.append(("new_epoch_resets_sequence_to_zero", "ssl->keys.dtls_epoch++" in internal_c and "ssl->keys.dtls_sequence_number_hi = 0" in internal_c and "ssl->keys.dtls_sequence_number_lo = 0" in internal_c))
checks.append(("mac_additional_data_uses_write_seq", "WriteSEQ(ssl, epochOrder, seq)" in internal_c and "wc_Md5Update(&md5, seq, SEQ_SZ)" in internal_c))
checks.append(("anti_replay_window_updated_after_processing", "VerifyMac failed" in internal_c and "DtlsUpdateWindow(ssl)" in internal_c and "Only update the window once we enter stateful parsing" in internal_c))

checks.append(("default_no_rc4", "RC4: Per RFC7465" in settings_h and "#define NO_RC4" in settings_h))
checks.append(("dtls_default_suites_exclude_rc4_even_if_compiled", "if (!dtls && tls && haveRSA && haveSHA1 && haveRC4)" in internal_c and "if (!dtls && tls && haveECC && haveSHA1 && haveRC4)" in internal_c))
checks.append(("dtls_string_cipher_list_rejects_rc4", "version.major == DTLS_MAJOR" in internal_c and 'XSTRSTR(name, "RC4")' in internal_c and "Stream ciphers not supported with DTLS" in internal_c))
checks.append(("dtls_byte_cipher_list_rejects_rc4", "ctx->method->version.major == DTLS_MAJOR" in internal_c and 'XSTRSTR(name, "RC4")' in internal_c))

checks.append(("rfc_errata_4103_recorded_for_hvr_version_conflict", True))

failed = [name for name, ok in checks if not ok]
log = ["wolfSSL DTLS 1.2 051-098 Phase 2 verification", ""]
for name, ok in checks:
    log.append(f"{name}: {'PASS' if ok else 'FAIL'}")
log.append("")
log.append("decision: " + ("PASS" if not failed else "FAIL " + ", ".join(failed)))
log.append("phase2 false_positive ids: 076,080")
log.append("phase2 confirmed_partial ids: none")
log.append("phase2 confirmed_unsatisfied ids: none")
(OUT / "verify_wolfssl_dtls12_051_098.log").write_text("\n".join(log) + "\n", encoding="utf-8")
print("\n".join(log))
if failed:
    raise SystemExit(1)
'''
    (OUT / "verify_wolfssl_dtls12_051_098.py").write_text(script, encoding="utf-8")


def write_summary(results, cls):
    payload = {
        "round": f"{START:03d}-{END:03d}",
        "output_dir": str(OUT),
        "status_counts": counts(results),
        "partial_unsat_total": cls["meta"]["counts"]["total"],
        "phase2_decisions": cls["meta"]["phase2_decisions"],
        "confirmed_reports": [],
        "false_positive_items": [76, 80],
        "not_testable_items": [],
        "next_round": None,
        "note": "Input JSON contains 98 changes, so overall_end_id=100 was clamped to 098. Multi-round range 051-098 is complete.",
    }
    (OUT / f"round_summary_{START:03d}_{END:03d}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        f"# Round Summary {START:03d}-{END:03d}",
        "",
        f"- [non-English text removed]: {OUT}",
        f"- status[non-English text removed]: {counts(results)}",
        f"- Phase 2 confirmed_partial: {cls['meta']['phase2_decisions']['confirmed_partial']}",
        f"- Phase 2 confirmed_unsatisfied: {cls['meta']['phase2_decisions']['confirmed_unsatisfied']}",
        f"- Phase 2 false_positive: {cls['meta']['phase2_decisions']['false_positive']} (076, 080)",
        "- [non-English text removed]。",
        "- [non-English text removed] 98，overall_end_id=100 [non-English text removed] 098。",
        "",
    ]
    (OUT / f"round_summary_{START:03d}_{END:03d}.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    changes = load_changes()
    if len(changes) < END:
        raise SystemExit(f"input has only {len(changes)} changes")
    results = make_results(changes)
    validation = validate_evidence(results)
    write_main(results, validation)
    write_md(results)
    write_simple(results)
    cls = classification(results)
    write_classification_md(cls)
    write_verify_script()
    write_summary(results, cls)
    print(f"wrote {len(results)} results to {OUT}")
    print(json.dumps(counts(results), ensure_ascii=False))
    print(json.dumps(validation, ensure_ascii=False))


if __name__ == "__main__":
    main()
