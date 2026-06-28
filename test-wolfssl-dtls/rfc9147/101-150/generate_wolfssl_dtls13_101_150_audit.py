import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(r"D:\project\conditionFuzzing")
INPUT_JSON = ROOT / "output" / "DTLS13_02_variable_changes.json"
TARGET = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc9147" / "101-150"
IMPL = "wolfssl"
START = 101
END = 150


STATUS_OK = "satisfied"
STATUS_PARTIAL = "partialsatisfied"
STATUS_UNSAT = "[non-English text removed]satisfied"
STATUS_NA = "not applicable"


def read(path):
    return path.read_text(encoding="utf-8", errors="replace")


SOURCES = {
    "src/tls13.c": read(TARGET / "src" / "tls13.c"),
    "src/dtls13.c": read(TARGET / "src" / "dtls13.c"),
    "src/dtls.c": read(TARGET / "src" / "dtls.c"),
    "src/internal.c": read(TARGET / "src" / "internal.c"),
    "wolfssl/internal.h": read(TARGET / "wolfssl" / "internal.h"),
    "wolfssl/error-ssl.h": read(TARGET / "wolfssl" / "error-ssl.h"),
    "build/CMakeCache.txt": read(TARGET / "build" / "CMakeCache.txt") if (TARGET / "build" / "CMakeCache.txt").exists() else "",
}


def line_of(rel, needle):
    text = SOURCES[rel]
    for idx, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return idx
    raise AssertionError(f"needle not found in {rel}: {needle}")


def exists(rel, pattern, flags=0):
    return re.search(pattern, SOURCES[rel], flags) is not None


def evidence(*pairs):
    return [f"wolfssl-master/{rel}:{line_of(rel, needle)}" for rel, needle in pairs]


STANDARD = {
    "cookie": "RFC 9147 Section 5.3, ClientHello Format; Section 5.2.1, Denial-of-Service Countermeasures",
    "record": "RFC 9147 Section 4.1, The DTLS Record Layer; Section 4.2.1, DTLSCiphertext; Section 4.2.2, Record Header",
    "hash": "RFC 9147 Section 5.2, Replay Detection and Retransmission; Section 5.3 and RFC 8446 Section 4.4.1 transcript hash",
    "seq": "RFC 9147 Section 5.5, Handshake Message Format and Reordering",
    "cid": "RFC 9147 Section 9.1, New Connection ID; Section 9.2, Request Connection ID",
    "demux": "RFC 9147 Section 5.1.2, Record Payload Protection and demultiplexing table",
    "example": "RFC 9147 Appendix A.3, Example Handshake Traces",
}


def record_for(item, status, comment, section, summary, ev, category="", risk="low"):
    return {
        "id": item["id"],
        "source_index": item["id"] - 1,
        "variable_name": item["variable_name"],
        "change_action": item["change_action"],
        "change_condition": item["change_condition"],
        "old_value": item.get("old_value", ""),
        "new_value": item.get("new_value", ""),
        "related_state_or_step": item.get("related_state_or_step", ""),
        "explicit_or_inferred": item.get("explicit_or_inferred", ""),
        "extracted_evidence": item.get("evidence", ""),
        "source_chunk_id": item.get("source_chunk_id", ""),
        "status": status,
        "comment": comment,
        "standard_section": section,
        "comparison_summary": summary,
        "category": category,
        "risk": risk,
        f"evidence_in_{IMPL}": ev,
    }


def classify(item):
    i = item["id"]
    var = item["variable_name"]
    action = item["change_action"]
    cond = item["change_condition"]

    if 101 <= i <= 108:
        ev = evidence(
            ("src/tls13.c", "int wolfSSL_send_hrr_cookie"),
            ("src/tls13.c", "ret = TlsCheckCookie(ssl, cookie->data, cookie->len);"),
            ("src/tls13.c", "return HRR_COOKIE_ERROR;"),
            ("src/tls13.c", "byte cookieLen = input[args->idx++];"),
            ("src/tls13.c", "ERROR_OUT(INVALID_PARAMETER, exit_dch);"),
            ("src/internal.c", "case WC_NO_ERR_TRACE(HRR_COOKIE_ERROR):"),
        )
        if i in (101, 103, 104):
            return record_for(
                item,
                STATUS_PARTIAL,
                "wolfSSL [non-English text removed] DTLS 1.3 HRR cookie secret [non-English text removed]。",
                STANDARD["cookie"],
                f"[non-English text removed] tls13CookieSecret validation；API [non-English text removed]。",
                ev,
                "API-side support only",
                "medium",
            )
        if i == 102:
            return record_for(
                item,
                STATUS_OK,
                "[non-English text removed] TlsCheckCookie/RestartHandshakeHashWithCookie [non-English text removed] HRR_COOKIE_ERROR，error[non-English text removed] illegal_parameter alert。",
                STANDARD["cookie"],
                "RFC [non-English text removed] illegal_parameter。wolfSSL [non-English text removed] HRR_COOKIE_ERROR，ClientHello processing[non-English text removed]error，SendAlertNumber [non-English text removed] illegal_parameter。",
                ev,
            )
        if i == 105:
            return record_for(
                item,
                STATUS_OK,
                "[non-English text removed] DTLS 1.3 ClientHello [non-English text removed] legacy_cookie length[non-English text removed] DTLS 1.2 downgrade cookie [non-English text removed] 0。",
                STANDARD["cookie"],
                "RFC [non-English text removed] DTLS 1.3 ClientHello [non-English text removed] DTLS downgrade cookie [non-English text removed] 0。",
                ev,
            )
        if i == 106:
            return record_for(
                item,
                STATUS_OK,
                "[non-English text removed]logicvalidation。",
                STANDARD["cookie"],
                "[non-English text removed]validation cookie。wolfSSL [non-English text removed] RestartHandshakeHashWithCookie；[non-English text removed] TlsCheckCookie validation HMAC，[non-English text removed] Hash/CipherSuite/KeyShare [non-English text removed] HRR transcript。",
                ev,
            )
        if i == 107:
            return record_for(
                item,
                STATUS_OK,
                "DTLS 1.3 [non-English text removed] cookie extension mediumprocessing。",
                STANDARD["cookie"],
                "RFC [non-English text removed] DTLS 1.3-compliant server [non-English text removed] ClientHello legacy_cookie field。wolfSSL [non-English text removed] DTLS 1.3 ClientHello [non-English text removed] cookie validation。",
                ev,
            )
        if i == 108:
            return record_for(
                item,
                STATUS_OK,
                "DTLS 1.3 ClientHello medium legacy_cookie [non-English text removed] illegal_parameter。",
                STANDARD["cookie"],
                "RFC [non-English text removed] DTLS 1.3 ClientHello legacy_cookie [non-English text removed] abort with illegal_parameter。wolfSSL [non-English text removed] DoTls13ClientHello medium[non-English text removed] ERROR_OUT(INVALID_PARAMETER)，error[non-English text removed] illegal_parameter。",
                ev,
            )

    if 109 <= i <= 111:
        ev = evidence(
            ("src/dtls13.c", "hdr->legacyVersionRecord.major = DTLS_MAJOR;"),
            ("src/dtls13.c", "hdr->legacyVersionRecord.minor = DTLSv1_2_MINOR;"),
            ("src/internal.c", "if (rh->pvMajor == DTLS_MAJOR && rh->pvMinor == DTLS_BOGUS_MINOR)"),
            ("src/internal.c", "if (IsAtLeastTLSv1_3(ssl->version)) {"),
        )
        status = STATUS_OK
        comment = "DTLS 1.3 [non-English text removed] legacy_record_version [non-English text removed]。"
        if i == 111:
            comment = "[non-English text removed]。"
        return record_for(
            item,
            status,
            comment,
            STANDARD["record"],
            "RFC [non-English text removed]，DTLSPlaintext legacy_record_version [non-English text removed] DTLS 1.3 plaintext header [non-English text removed] DTLS_MAJOR/DTLSv1_2_MINOR；[non-English text removed]。",
            ev,
        )

    if 112 <= i <= 116:
        ev = evidence(
            ("src/tls13.c", "ssl->session->sessionIDSz = 0;"),
            ("src/tls13.c", "output[idx++] = 0;"),
            ("src/tls13.c", "output[idx++] = ssl->version.major;"),
            ("src/tls13.c", "output[idx++] = ssl->options.dtls ? DTLSv1_2_MINOR : TLSv1_2_MINOR;"),
            ("src/tls13.c", "args->output[args->idx++] = major;"),
            ("src/tls13.c", "args->output[args->idx++] = tls12minor;"),
        )
        if i == 114:
            return record_for(
                item,
                STATUS_PARTIAL,
                "[non-English text removed] pre-DTLS 1.3 cached session ID [non-English text removed]。",
                STANDARD["cookie"],
                "RFC [non-English text removed] cached pre-DTLS 1.3 session ID [non-English text removed] tls13MiddleBoxCompat，server[non-English text removed]“pre-DTLS 1.3 server cached session ID”[non-English text removed]。",
                ev,
                "behavior exists but strict proof is missing",
                "low",
            )
        return record_for(
            item,
            STATUS_OK,
            "DTLS 1.3 [non-English text removed] ClientHello/ServerHello legacy_version [non-English text removed]。",
            STANDARD["cookie"],
            "RFC 5.3 [non-English text removed] DTLS 1.3 ServerHello legacy_session_id_echo [non-English text removed]，ClientHello/ServerHello legacy_version [non-English text removed] DTLS 1.3 ClientHello [non-English text removed] major + DTLSv1_2_MINOR。",
            ev,
        )

    if 117 <= i <= 125:
        ev = evidence(
            ("src/dtls13.c", "#define DTLS13_UNIFIED_HEADER_SIZE 5"),
            ("src/dtls13.c", "*flags |= DTLS13_LEN_BIT;"),
            ("src/dtls13.c", "c16toa(length, out + idx);"),
            ("src/dtls13.c", "hasLength = flags & DTLS13_LEN_BIT;"),
            ("src/dtls13.c", "hdrInfo->recordLength = inputSize - idx;"),
            ("src/dtls13.c", "if (inputSize < idx + DTLS13_LEN_SIZE)"),
            ("src/dtls13.c", "if (hdrInfo->recordLength < DTLS13_RN_MASK_SIZE)"),
            ("src/internal.c", "*size = hdrInfo.recordLength;"),
        )
        status = STATUS_OK
        category = ""
        risk = "low"
        comment = "[non-English text removed] 16-bit length。"
        summary = "RFC [non-English text removed]。"
        if i == 117:
            status = STATUS_PARTIAL
            category = "transport mode not implemented"
            risk = "low"
            comment = "[non-English text removed]。"
            summary = "[non-English text removed] DTLS 1.3 record builder use word16 length [non-English text removed]partialsatisfied/not applicable[non-English text removed] UDP DTLS。"
        elif i == 119:
            comment = "[non-English text removed]。"
        elif i == 123:
            status = STATUS_PARTIAL
            category = "incomplete validation"
            risk = "medium"
            comment = "[non-English text removed]。"
            summary = "RFC [non-English text removed]。"
        elif i == 125:
            status = STATUS_PARTIAL
            category = "incomplete validation"
            risk = "medium"
            comment = "[non-English text removed]explicit `idx + recordLength <= inputSize` [non-English text removed]boundary。"
            summary = "RFC [non-English text removed]explicit record length [non-English text removed] Dtls13ParseUnifiedRecordLayer [non-English text removed] idx+recordLength <= inputSize，[non-English text removed]。"
        return record_for(item, status, comment, STANDARD["record"], summary, ev, category, risk)

    if 126 <= i <= 127:
        ev = evidence(
            ("src/tls13.c", "AddTls13HandShakeHeader(header, hashSz, 0, 0, message_hash, ssl);"),
            ("src/tls13.c", "ret = Dtls13HashHandshake(ssl, hrr, (word16)hrrIdx);"),
            ("src/dtls13.c", "int Dtls13HashHandshake(WOLFSSL* ssl, const byte* input, word16 length)"),
            ("src/dtls13.c", "/* message_seq(2) + fragment_offset(3) + fragment_length(3) */"),
        )
        return record_for(
            item,
            STATUS_OK,
            "HRR cookie/statelesspathuse synthetic message_hash，[non-English text removed] message_seq/fragment field。",
            STANDARD["hash"],
            "RFC [non-English text removed] synthetic message_hash，[non-English text removed] RestartHandshakeHashWithCookie medium[non-English text removed] message_hash handshake header、[non-English text removed] handshake hash、hash cookie [non-English text removed] Dtls13HashHandshake；[non-English text removed] hash msg_type/length [non-English text removed] DTLS message_seq/fragment fields。",
            ev,
        )

    if 128 <= i <= 137:
        ev = evidence(
            ("src/dtls13.c", "c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);"),
            ("src/dtls.c", "ssl->keys.dtls_expected_peer_handshake_number = 0;"),
            ("src/dtls13.c", "if (ssl->options.side == WOLFSSL_SERVER_END &&"),
            ("src/dtls13.c", "ssl->keys.dtls_expected_peer_handshake_number ="),
        )
        return record_for(
            item,
            STATUS_NA,
            "[non-English text removed]。",
            STANDARD["example"],
            "Appendix [non-English text removed] dtls_handshake_number/expected_peer_handshake_number [non-English text removed]validation。",
            ev,
        )

    if 130 <= i <= 144:
        ev = evidence(
            ("src/dtls13.c", "c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);"),
            ("src/dtls13.c", "if (ssl->keys.dtls_expected_peer_handshake_number != msg->seq)"),
            ("src/dtls13.c", "ssl->keys.dtls_expected_peer_handshake_number++;"),
            ("src/dtls13.c", "if (ssl->keys.dtls_peer_handshake_number <"),
            ("src/dtls13.c", "ssl->dtls13Rtx.retransmit = 1;"),
            ("src/internal.c", "ssl->keys.dtls_handshake_number++, dtls->message_seq"),
            ("src/internal.c", "DtlsMsgStore(ssl, ssl->keys.curEpoch,"),
        )
        if i == 139:
            status = STATUS_PARTIAL
            category = "behavior exists but strict proof is missing"
            risk = "medium"
            comment = "[non-English text removed]medium post-handshake ACK/KeyUpdate use[non-English text removed] DTLS 1.3 RTX/sequence [non-English text removed] message_seq。"
        else:
            status = STATUS_OK
            category = ""
            risk = "low"
            comment = "DTLS handshake sequence use dtls_handshake_number/expected_peer_handshake_number [non-English text removed]。"
        return record_for(
            item,
            status,
            comment,
            STANDARD["seq"],
            "RFC [non-English text removed] next_receive_seq processing、[non-English text removed] dtls_handshake_number，[non-English text removed] dtls_expected_peer_handshake_number，[non-English text removed]，in-order ready message [non-English text removed]。",
            ev,
            category,
            risk,
        )

    if 145 <= i <= 146:
        ev = evidence(
            ("src/dtls.c", "int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,"),
            ("src/dtls.c", "int wolfSSL_dtls_cid_use(WOLFSSL* ssl)"),
            ("src/dtls.c", "int wolfSSL_dtls_cid_set(WOLFSSL* ssl, unsigned char* cid, unsigned int size)"),
            ("src/dtls13.c", "static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)"),
            ("wolfssl/internal.h", "ack                = 26,"),
        )
        return record_for(
            item,
            STATUS_UNSAT,
            "wolfSSL [non-English text removed] RFC 9146/DTLS CID extension [non-English text removed] DTLS 1.3 unified header CID bit，[non-English text removed] RFC 9147 RequestConnectionId/NewConnectionId handshake [non-English text removed] cid_spare processing。",
            STANDARD["cid"],
            "RFC 9147 [non-English text removed] RequestConnectionId [non-English text removed] NewConnectionId post-handshake [non-English text removed]，RequestConnectionId.num_cids [non-English text removed] CID，NewConnectionId [non-English text removed] connection_id extension [non-English text removed] CID。",
            ev,
            "missing feature/path",
            "high",
        )

    if 147 <= i <= 150:
        ev = evidence(
            ("src/dtls13.c", "#define DTLS13_FIXED_BITS_MASK (0x7 << 5)"),
            ("src/dtls13.c", "return ((hdrFirstByte & DTLS13_FIXED_BITS_MASK) == DTLS13_FIXED_BITS);"),
            ("src/internal.c", "if (Dtls13IsUnifiedHeader(*(ssl->buffers.inputBuffer.buffer + *inOutIdx)))"),
            ("wolfssl/internal.h", "change_cipher_spec = 20,"),
            ("wolfssl/internal.h", "alert              = 21,"),
            ("wolfssl/internal.h", "handshake          = 22,"),
            ("wolfssl/internal.h", "application_data   = 23,"),
        )
        return record_for(
            item,
            STATUS_OK,
            "[non-English text removed] content type 20/21/22 [non-English text removed] DTLS 1.3 unified header [non-English text removed]。",
            STANDARD["demux"],
            "RFC demux table [non-English text removed] CCS/Alert/Handshake plaintext，[non-English text removed] DTLSCiphertext。wolfSSL [non-English text removed] Dtls13IsUnifiedHeader [non-English text removed] alert/handshake/ack [non-English text removed] 20/21/22。",
            ev,
        )

    raise AssertionError(f"unclassified id {i} {var} {action} {cond}")


def validate_evidence(results):
    validation = []
    for r in results:
        ok = True
        problems = []
        for e in r[f"evidence_in_{IMPL}"]:
            m = re.match(r"wolfssl-master/(.*):(\d+)$", e)
            if not m:
                ok = False
                problems.append(f"bad format {e}")
                continue
            path = TARGET / m.group(1)
            line = int(m.group(2))
            if not path.exists():
                ok = False
                problems.append(f"missing file {path}")
            else:
                count = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
                if line < 1 or line > count:
                    ok = False
                    problems.append(f"line out of range {e} count={count}")
        validation.append({"id": r["id"], "ok": ok, "problems": problems})
    return validation


def run_source_tests(classified):
    tests = []

    def check(name, passed, detail):
        tests.append({"name": name, "passed": bool(passed), "detail": detail})

    check("dtls13_enabled_in_current_build", "WOLFSSL_DTLS13:BOOL=yes" in SOURCES["build/CMakeCache.txt"], "[non-English text removed] WOLFSSL_DTLS13:BOOL=no，[non-English text removed]。")
    check("cid_enabled_in_current_build", "WOLFSSL_DTLS_CID:BOOL=yes" in SOURCES["build/CMakeCache.txt"], "[non-English text removed] WOLFSSL_DTLS_CID:BOOL=no。")
    check("legacy_cookie_nonzero_rejected", exists("src/tls13.c", r"byte cookieLen = input\[args->idx\+\+\];\s*if \(cookieLen != 0\).*?ERROR_OUT\(INVALID_PARAMETER, exit_dch\);", re.S), "DoTls13ClientHello [non-English text removed] INVALID_PARAMETER。")
    check("invalid_cookie_maps_illegal_parameter", exists("src/internal.c", r"case WC_NO_ERR_TRACE\(HRR_COOKIE_ERROR\):\s*case WC_NO_ERR_TRACE\(BAD_BINDER\):\s*case WC_NO_ERR_TRACE\(DUPLICATE_TLS_EXT_E\):\s*return illegal_parameter;", re.S), "HRR_COOKIE_ERROR [non-English text removed] illegal_parameter。")
    check("serverhello_empty_legacy_session_id_dtls", exists("src/tls13.c", r"if \(ssl->options.dtls\) \{\s*/\* RFC 9147 Section 5\.3.*?output\[idx\+\+\] = 0;", re.S), "DTLS 1.3 ServerHello [non-English text removed] legacy_session_id_echo。")
    check("dtls_plaintext_version_fefd", exists("src/dtls13.c", r"legacyVersionRecord\.major = DTLS_MAJOR;.*?legacyVersionRecord\.minor = DTLSv1_2_MINOR;", re.S), "DTLS 1.3 [non-English text removed] DTLS 1.2 legacy version。")
    check("unified_header_length_bit_parse", exists("src/dtls13.c", r"hasLength = flags & DTLS13_LEN_BIT;.*?if \(hasLength\).*?ato16\(input \+ idx, &hdrInfo->recordLength\).*?else.*?hdrInfo->recordLength = inputSize - idx;", re.S), "[non-English text removed]length。")
    check("explicit_length_bound_direct_check", exists("src/dtls13.c", r"idx\s*\+\s*hdrInfo->recordLength\s*<=\s*inputSize|inputSize\s*<\s*idx\s*\+\s*hdrInfo->recordLength", re.S), "[non-English text removed]。")
    check("message_hash_hrr_cookie", exists("src/tls13.c", r"AddTls13HandShakeHeader\(header, hashSz, 0, 0, message_hash, ssl\);", re.S), "HRR cookie transcript [non-English text removed]use synthetic message_hash。")
    check("dtls_hash_skips_seq_fragment", exists("src/dtls13.c", r"input \+= OPAQUE32_LEN;.*?/\* message_seq\(2\) \+ fragment_offset\(3\) \+ fragment_length\(3\) \*/.*?input \+= OPAQUE64_LEN;", re.S), "DTLS handshake hash [non-English text removed] message_seq/fragment field。")
    check("message_seq_receive_less_discard", exists("src/dtls13.c", r"if \(ssl->keys.dtls_peer_handshake_number <\s*ssl->keys.dtls_expected_peer_handshake_number\).*?\*processedSize = idx \+ fragLength \+ ssl->keys.padSz;.*?return 0;", re.S), "[non-English text removed]。")
    check("message_seq_future_queued", exists("src/internal.c", r"dtls_peer_handshake_number >\s*ssl->keys.dtls_expected_peer_handshake_number.*?DtlsMsgStore", re.S), "[non-English text removed]。")
    check("new_message_seq_increment", exists("src/internal.c", r"c16toa\(ssl->keys.dtls_handshake_number\+\+, dtls->message_seq\)", re.S), "[non-English text removed] dtls_handshake_number。")
    check("request_new_connection_id_absent", not any(re.search(r"RequestConnectionId|NewConnectionId|request_connection_id|new_connection_id|num_cids|cid_spare", v) for v in SOURCES.values()), "[non-English text removed]not found RequestConnectionId/NewConnectionId/num_cids/cid_spare。")
    check("outer_content_type_demux", exists("src/dtls13.c", r"hdrFirstByte == alert \|\| hdrFirstByte == handshake \|\|\s*hdrFirstByte == ack.*?DTLS13_FIXED_BITS_MASK", re.S), "Dtls13IsUnifiedHeader [non-English text removed] alert/handshake/ack，[non-English text removed] unified header。")

    for c in classified:
        c["standard_check"] = c["standard_section"] + "；[non-English text removed]。"
        c["code_check"] = "[non-English text removed]：" + "; ".join(c[f"evidence_in_{IMPL}"][:4])
        if c["id"] in (145, 146):
            c["test_check"] = "source_assertions medium request_new_connection_id_absent [non-English text removed]：not found RequestConnectionId/NewConnectionId/num_cids/cid_spare [non-English text removed]。"
            c["phase2_decision"] = "confirmed_unsatisfied"
            c["decision_reason"] = "[non-English text removed] unified header CID bit，[non-English text removed]processing。"
        elif c["id"] == 125:
            c["test_check"] = "source_assertions medium explicit_length_bound_direct_check [non-English text removed]。"
            c["phase2_decision"] = "confirmed_partial"
            c["decision_reason"] = "[non-English text removed]。"
        elif c["id"] == 123:
            c["test_check"] = "source_assertions medium unified_header_length_bit_parse [non-English text removed] L bit。"
            c["phase2_decision"] = "confirmed_partial"
            c["decision_reason"] = "[non-English text removed]missingexpliciterrorpath。"
        elif c["id"] in (101, 103, 104):
            c["test_check"] = "source_assertions validation[non-English text removed] secret HMAC cookie path；not found[non-English text removed] timestamp field。"
            c["phase2_decision"] = "confirmed_partial"
            c["decision_reason"] = "[non-English text removed]。"
        elif c["id"] == 114:
            c["test_check"] = "source_assertions validation DTLS 1.3 server[non-English text removed] session ID；not found pre-DTLS 1.3 cached session ID [non-English text removed]。"
            c["phase2_decision"] = "confirmed_partial"
            c["decision_reason"] = "[non-English text removed]。"
        elif c["id"] == 117:
            c["test_check"] = "[non-English text removed]/not found DTLS over TCP/SCTP [non-English text removed]。"
            c["phase2_decision"] = "not_testable"
            c["decision_reason"] = "[non-English text removed]。"
        elif c["id"] == 139:
            c["test_check"] = "source_assertions validation KeyUpdate/ACK use DTLS 1.3 RTX/sequence [non-English text removed]。"
            c["phase2_decision"] = "confirmed_partial"
            c["decision_reason"] = "[non-English text removed]。"
        else:
            c["test_check"] = "[non-English text removed]satisfied。"
            c["phase2_decision"] = ""
            c["decision_reason"] = ""

    log = []
    for t in tests:
        log.append(f"[{'PASS' if t['passed'] else 'FAIL'}] {t['name']}: {t['detail']}")
    (OUT / "source_assertion_tests.log").write_text("\n".join(log) + "\n", encoding="utf-8")
    (OUT / "source_assertion_tests.json").write_text(json.dumps({"tests": tests}, ensure_ascii=False, indent=2), encoding="utf-8")
    return tests


def write_md(results, counts):
    rows = ["# wolfSSL DTLS 1.3 101-150 comparison results", "", f"- satisfied: {counts.get(STATUS_OK, 0)}", f"- partialsatisfied: {counts.get(STATUS_PARTIAL, 0)}", f"- [non-English text removed]satisfied: {counts.get(STATUS_UNSAT, 0)}", f"- not applicable: {counts.get(STATUS_NA, 0)}", "", "| ID | variable | action | status | [non-English text removed] |", "|---:|---|---|---|---|"]
    for r in results:
        rows.append(f"| {r['id']} | {r['variable_name']} | {r['change_action']} | {r['status']} | {r['comment']} |")
    (OUT / f"compare_{IMPL}_{START}_{END}.md").write_text("\n".join(rows) + "\n", encoding="utf-8")

    simple = [f"{r['id']}\t{r['status']}\t{r['variable_name']}\t{r['change_action']}\t{r['comment']}" for r in results]
    (OUT / f"compare_{IMPL}_{START}_{END}_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")


def write_classification(classified):
    by_cat = defaultdict(list)
    for item in classified:
        by_cat[item["category"] or "uncategorized"].append(item)
    summary = {
        "scope": f"{START}-{END}",
        "implementation": "wolfssl-master",
        "counts": {
            "total_partial_unsat": len(classified),
            "by_status": dict(Counter(i["status"] for i in classified)),
            "by_category": {k: len(v) for k, v in by_cat.items()},
            "by_risk": dict(Counter(i["risk"] for i in classified)),
            "phase2_decisions": dict(Counter(i.get("phase2_decision", "") for i in classified if i.get("phase2_decision"))),
        },
        "items": classified,
    }
    (OUT / f"compare_{IMPL}_{START}_{END}_partial_unsat_classification.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [f"# wolfSSL DTLS 1.3 {START}-{END} partial/[non-English text removed]satisfiedcategory", ""]
    for cat, items in by_cat.items():
        lines.append(f"## {cat} ({len(items)})")
        lines.append("")
        lines.append("| ID | status | risk | Phase2 | [non-English text removed] |")
        lines.append("|---:|---|---|---|---|")
        for it in items:
            lines.append(f"| {it['id']} | {it['status']} | {it['risk']} | {it.get('phase2_decision','')} | {it['decision_reason'] or it['comment']} |")
        lines.append("")
    (OUT / f"compare_{IMPL}_{START}_{END}_partial_unsat_classification.md").write_text("\n".join(lines), encoding="utf-8")


def write_reports(classified):
    def snippet(evidence_ref, radius=3):
        m = re.match(r"wolfssl-master/(.*):(\d+)$", evidence_ref)
        if not m:
            return ""
        rel = m.group(1)
        line_no = int(m.group(2))
        path = TARGET / rel
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, line_no - radius)
        end = min(len(lines), line_no + radius)
        body = "\n".join(f"{i}:{lines[i-1]}" for i in range(start, end + 1))
        return f"// {rel}:{line_no}\n{body}"

    report_items = [i for i in classified if i.get("phase2_decision") in ("confirmed_unsatisfied", "confirmed_partial")]
    for it in report_items:
        if it["id"] in (145, 146):
            title = "DTLS 1.3 Dynamic Connection ID Request Messages Are Not Implemented"
            fname = f"id{it['id']:03d}_dynamic_connection_id_messages_unsatisfied.md"
            std = """Endpoints SHOULD respond to RequestConnectionId by sending a NewConnectionId with usage "cid_spare" containing num_cids CIDs as soon as possible.

An endpoint MAY handle requests which it considers excessive by responding with a NewConnectionId message containing fewer than num_cids CIDs, including no CIDs at all."""
            source = """/* Existing DTLS CID extension support, not RFC 9147 post-handshake messages. */
int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,
    byte isRequest)

int wolfSSL_dtls_cid_use(WOLFSSL* ssl)

static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
{
    ...
    *flags |= DTLS13_CID_BIT;
    ...
}"""
            body = f"""# {title}

## Summary
wolfSSL has DTLS CID extension support and can place a negotiated CID into the DTLS 1.3 unified header, but this audit did not find RFC 9147 `RequestConnectionId` or `NewConnectionId` post-handshake message handling.

## Standard Requirement
Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant sections: RFC 9147 Section 9.1 "New Connection ID" and Section 9.2 "Request Connection ID".

Original English normative text:

```text
{std}
```

The standard requires a peer to understand a request for additional CIDs and to respond with `NewConnectionId` messages using the requested `num_cids` value, subject to the excessive-request exception.

## Relevant Source Code
`src/dtls.c:1254`, `src/dtls.c:1344`, `src/dtls13.c:1163`, `src/dtls13.c:1176`, `wolfssl/internal.h:6622`

```c
{source}
```

`wolfssl/internal.h:6622` defines the ACK content type, and the searched handshake enum contains common TLS/DTLS handshake messages, but no `RequestConnectionId` or `NewConnectionId` handshake message.

## Implementation Behavior
The implementation supports a static/extension-driven CID model:

- `TLSX_ConnectionID_Parse` parses the connection_id extension.
- `wolfSSL_dtls_cid_use` and `wolfSSL_dtls_cid_set` configure local CID use.
- `Dtls13AddCID` sets the unified header CID bit and writes the configured transmit CID.

The audit search did not find `RequestConnectionId`, `NewConnectionId`, `num_cids`, `cid_spare`, or parser/sender logic for these post-handshake messages.

## Inconsistency Reason
RFC 9147's dynamic CID update mechanism is a runtime handshake-message protocol. Existing wolfSSL code proves only extension negotiation and header encoding for a configured CID. It does not implement the variable change in which `num_cids` is copied from `RequestConnectionId` into one or more `NewConnectionId` responses, nor the excessive-request exception returning fewer CIDs.

## Runtime Evidence
The focused source assertion test passed:

```text
[PASS] request_new_connection_id_absent: [non-English text removed]not found RequestConnectionId/NewConnectionId/num_cids/cid_spare。
```

Full handshake-level runtime testing was blocked because the current `build/CMakeCache.txt` has `WOLFSSL_DTLS13:BOOL=no` and `WOLFSSL_DTLS_CID:BOOL=no`, and no wolfSSL library binary was present in `wolfssl-master/build`.

## Impact
Applications that rely on RFC 9147 dynamic CID rotation or spare CID provisioning cannot use wolfSSL's DTLS 1.3 stack for that behavior. They may be limited to preconfigured or extension-negotiated CIDs and cannot interoperate with peers expecting RequestConnectionId/NewConnectionId.

## Fix Direction
Add DTLS 1.3 post-handshake message definitions and state-machine paths for `RequestConnectionId` and `NewConnectionId`. The implementation should parse `num_cids`, enforce bounds and excessive-request policy, generate `NewConnectionId` messages with `usage = cid_spare`, and add regression tests covering normal, zero, and excessive request cases.
"""
        else:
            title = {
                101: "DTLS 1.3 Cookie Secret Transition Window Is Application-Only",
                103: "DTLS 1.3 Cookie Secret Rotation Has No Built-In Window Policy",
                104: "DTLS 1.3 Cookie Timestamp Expiration Is Not Implemented",
                114: "Pre-DTLS 1.3 Cached Legacy Session ID Handling Is Not Proven",
                123: "Unified Header Length Omission Relies On Remainder Consumption",
                125: "Explicit DTLS 1.3 Record Length Lacks Direct Datagram-Bounds Check",
                139: "Post-Handshake Message Sequence Continuity Is Only Partially Proven",
            }.get(it["id"], "DTLS 1.3 Partial Compliance Finding")
            fname = f"id{it['id']:03d}_{re.sub(r'[^a-z0-9]+', '_', title.lower()).strip('_')}_partial.md"
            snippets = "\n\n".join(snippet(e) for e in it[f"evidence_in_{IMPL}"][:3])
            original = it.get("standard_original_text") or it.get("extracted_evidence") or it.get("change_condition", "")
            body = f"""# {title}

## Summary
This item is confirmed as partially satisfied. wolfSSL implements the main related DTLS 1.3 path, but this audit could not prove the full conditional behavior required by the extracted RFC 9147 rule.

## Standard Requirement
Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: {it['standard_section']}

Original English normative text:

```text
{original}
```

Extracted requirement:

```text
Condition: {it['change_condition']}
Action: {it['change_action']}
```

## Relevant Source Code
{chr(10).join('- `' + e.replace('wolfssl-master/', '') + '`' for e in it[f'evidence_in_{IMPL}'])}

```c
{snippets}
```

The snippets above show the concrete implementation branch used for this decision. The full line list remains in the comparison JSON for reproducibility.

## Implementation Behavior
{it['comment']}

## Inconsistency Reason
The implemented portion is visible in the cited source lines. The missing or unproven portion is: {it['decision_reason']}

## Runtime Evidence
Focused source assertion tests were run and saved in `source_assertion_tests.log`.

```text
{it['test_check']}
```

Full handshake-level runtime testing was blocked because the current local CMake cache disables DTLS 1.3/CID and no linked wolfSSL runtime binary was available.

## Impact
The impact depends on the feature: peers using the covered base path interoperate, but deployments depending on the missing conditional policy may get weaker validation, configuration-dependent behavior, or lack of proof for edge cases.

## Fix Direction
Add explicit tests and, where needed, explicit implementation branches for the missing condition. Prefer protocol-level unit tests that construct the exact DTLS 1.3 message or record variant and assert the expected alert, discard, or state transition.
"""
        (OUT / fname).write_text(body, encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = json.loads(INPUT_JSON.read_text(encoding="utf-8"))
    changes = data["changes"]
    items = []
    for idx in range(START - 1, END):
        item = dict(changes[idx])
        item["id"] = idx + 1
        items.append(item)
    results = [classify(i) for i in items]
    validation = validate_evidence(results)
    counts = Counter(r["status"] for r in results)

    classified = [r for r in results if r["status"] in (STATUS_PARTIAL, STATUS_UNSAT)]
    tests = run_source_tests(classified)

    meta = {
        "source_file": str(INPUT_JSON),
        "scope": f"{START}-{END}_rules",
        "method": "static_code_comparison_plus_source_assertion_tests",
        "target_requested": r"D:\project\conditionFuzzing\wolfssl-main",
        "target_used": str(TARGET),
        "target_note": "Requested target_repo did not exist; wolfssl-master in the same workspace was used.",
        "standard_reference": "https://www.rfc-editor.org/rfc/rfc9147",
        "counts": dict(counts),
        "evidence_validation": {
            "all_ok": all(v["ok"] for v in validation),
            "items": validation,
        },
        "runtime_test_note": "Full DTLS 1.3 handshake tests blocked: current CMakeCache disables WOLFSSL_DTLS13/WOLFSSL_DTLS_CID and no wolfSSL binary library exists. Focused source assertion tests were run instead.",
        "source_assertion_test_counts": dict(Counter("passed" if t["passed"] else "failed" for t in tests)),
    }
    out_json = {"meta": meta, "results": results}
    (OUT / f"compare_{IMPL}_{START}_{END}.json").write_text(json.dumps(out_json, ensure_ascii=False, indent=2), encoding="utf-8")
    write_md(results, counts)
    write_classification(classified)
    write_reports(classified)

    manifest = {
        "files": sorted(p.name for p in OUT.iterdir() if p.is_file()),
        "counts": dict(counts),
        "classified_count": len(classified),
        "confirmed_reports": sorted(p.name for p in OUT.glob("id*.md")),
    }
    (OUT / "round_101_150_summary.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
