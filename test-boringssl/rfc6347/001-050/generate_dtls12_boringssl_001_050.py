import json
import os
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
INPUT = ROOT / "output" / "DTLS12_02_variable_changes.json"
TARGET = ROOT / "boringssl-main"
OUT = ROOT / "test-boringssl" / "rfc6347" / "001-050"
IMPL = "boringssl-main"

SAT = "满足"
PART = "部分满足"
UNSAT = "不满足"
NA = "不适用"


RFC = {
    "handshake": {
        "section": "RFC 6347 Section 4.2.2, Handshake Message Format",
        "quote": "The DTLS handshake message format adds message_seq, fragment_offset, and fragment_length to the TLS Handshake structure and includes hello_verify_request(3) in HandshakeType.",
    },
    "cookie": {
        "section": "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures",
        "quote": "When responding to a HelloVerifyRequest, the client MUST use the same parameter values ... as it did in the original ClientHello. The client MUST retransmit the ClientHello with the cookie added. The server then verifies the cookie and proceeds with the handshake only if it is valid.",
    },
    "cookie_size": {
        "section": "RFC 6347 Section 4.2.1 and Section 4.2.2",
        "quote": "The ClientHello and HelloVerifyRequest cookie fields are opaque cookie<0..2^8-1>. This specification increases the cookie size limit to 255 bytes.",
    },
    "epoch": {
        "section": "RFC 6347 Section 4.1, Record Layer",
        "quote": "The epoch number is initially zero and is incremented each time the cipher state changes. Each epoch has a separate sequence number space. The epoch and sequence number are included in the MAC.",
    },
    "appdata": {
        "section": "RFC 6347 Section 4.1.2.6, Handling Invalid Records",
        "quote": "Implementations MUST either discard or buffer all application data packets for the new epoch until they have received the Finished message for that epoch.",
    },
    "fragment": {
        "section": "RFC 6347 Section 4.2.3, Handshake Message Fragmentation and Reassembly",
        "quote": "If repeated retransmissions do not result in a response, and PMTU is unknown, subsequent retransmissions SHOULD fragment the handshake messages.",
    },
    "alerts": {
        "section": "RFC 6347 Section 4.1.2.7, Handling Invalid Records",
        "quote": "Implementations which choose to generate an alert instead of silently discarding invalid records MUST generate fatal-level alerts.",
    },
}


def rel(path):
    return f"{IMPL}/{path}"


EV = {
    "types": [
        rel("include/openssl/ssl3.h:136"),
        rel("include/openssl/ssl3.h:156"),
        rel("ssl/d1_both.cc:550"),
        rel("ssl/handshake.cc:402"),
        rel("ssl/handshake.cc:477"),
        rel("ssl/handshake.cc:490"),
    ],
    "clienthello": [
        rel("ssl/handshake_client.cc:181"),
        rel("ssl/handshake_client.cc:203"),
        rel("ssl/handshake_client.cc:211"),
        rel("ssl/extensions.cc:138"),
        rel("ssl/extensions.cc:151"),
    ],
    "hvr_client": [
        rel("ssl/handshake_client.cc:517"),
        rel("ssl/handshake_client.cc:524"),
        rel("ssl/handshake_client.cc:534"),
        rel("ssl/handshake_client.cc:542"),
        rel("ssl/handshake_client.cc:547"),
    ],
    "server_cookie_absent": [
        rel("ssl/handshake_server.cc:334"),
        rel("include/openssl/ssl.h:5243"),
        rel("ssl/test/runner/handshake_server.go:299"),
        rel("ssl/test/runner/handshake_server.go:326"),
    ],
    "runner_cookie_32": [
        rel("ssl/test/runner/handshake_messages.go:2980"),
        rel("ssl/test/runner/handshake_messages.go:3007"),
        rel("ssl/test/runner/handshake_messages.go:3008"),
    ],
    "transcript": [
        rel("ssl/handshake_client.cc:542"),
        rel("ssl/handshake.cc:406"),
        rel("ssl/d1_both.cc:593"),
        rel("ssl/d1_both.cc:595"),
    ],
    "epoch": [
        rel("ssl/d1_lib.cc:56"),
        rel("ssl/dtls_method.cc:43"),
        rel("ssl/dtls_method.cc:59"),
        rel("ssl/dtls_method.cc:121"),
        rel("ssl/dtls_record.cc:551"),
        rel("ssl/dtls_record.cc:558"),
    ],
    "appdata": [
        rel("ssl/dtls_record.cc:257"),
        rel("ssl/dtls_record.cc:316"),
        rel("ssl/dtls_record.cc:318"),
        rel("ssl/dtls_record.cc:401"),
    ],
    "fragment": [
        rel("ssl/d1_both.cc:697"),
        rel("ssl/d1_both.cc:720"),
        rel("ssl/d1_both.cc:767"),
        rel("ssl/d1_both.cc:781"),
        rel("ssl/d1_both.cc:825"),
        rel("ssl/test/runner/dtls_tests.go:614"),
    ],
    "record_len": [
        rel("ssl/dtls_record.cc:235"),
        rel("ssl/dtls_record.cc:283"),
        rel("ssl/dtls_record.cc:515"),
        rel("ssl/dtls_record.cc:517"),
    ],
    "alerts": [
        rel("ssl/dtls_record.cc:308"),
        rel("ssl/dtls_record.cc:327"),
        rel("ssl/dtls_record.cc:413"),
        rel("ssl/dtls_record.cc:414"),
    ],
}


def base_result(idx, item):
    return {
        "id": idx,
        "source_index": idx - 1,
        "variable_name": item.get("variable_name", ""),
        "change_condition": item.get("change_condition", ""),
        "change_action": item.get("change_action", ""),
        "old_value": item.get("old_value", ""),
        "new_value": item.get("new_value", ""),
        "related_state_or_step": item.get("related_state_or_step", ""),
        "explicit_or_inferred": item.get("explicit_or_inferred", ""),
        "source_chunk_id": item.get("source_chunk_id", ""),
    }


def classify(idx, item):
    v = item["variable_name"]
    cond = item["change_condition"]
    act = item["change_action"]
    r = base_result(idx, item)
    r["risk"] = "low"
    r["category"] = "implemented"

    if idx <= 12:
        r.update(status=SAT, standard_section=RFC["handshake"]["section"], standard_quote=RFC["handshake"]["quote"],
                 evidence_in_boringssl=EV["types"],
                 comment="BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine.",
                 comparison_summary="RFC maps Handshake.msg_type to a concrete body. BoringSSL does not use a single switch over an ASN.1-like union; instead each state reads the expected type with ssl_check_message_type or dedicated parsers and writes messages through init_message. This satisfies the body-selection rule for implemented DTLS 1.2 handshake messages.")
    elif idx in (13, 16):
        r.update(status=SAT, standard_section=RFC["cookie"]["section"], standard_quote=RFC["cookie"]["quote"],
                 evidence_in_boringssl=EV["hvr_client"] + EV["clienthello"],
                 comment="客户端收到 HelloVerifyRequest 后只把 cookie 写入 hs->dtls_cookie 并重发 ClientHello；cipher_suites 与 compression_methods 仍由同一配置和固定 null compression 生成。",
                 comparison_summary="RFC requires the second ClientHello to keep the original ClientHello parameters except for adding the cookie. BoringSSL stores only the cookie from HelloVerifyRequest and calls ssl_add_client_hello again, while cipher list and compression list generation are unchanged.")
    elif idx == 14:
        r.update(status=SAT, standard_section=RFC["handshake"]["section"], standard_quote="CipherSuite cipher_suites<2..2^16-1>;",
                 evidence_in_boringssl=EV["clienthello"],
                 comment="SSL_parse_client_hello requires a u16-length-prefixed cipher_suites vector with length at least 2 and an even number of bytes.",
                 comparison_summary="The RFC vector lower bound is enforced. The u16 prefix bounds the upper length to 65535 bytes, matching 2^16-1.")
    elif idx == 15:
        r.update(status=SAT, standard_section="RFC 6347 Section 4.2.1",
                 standard_quote="The initial ClientHello and HelloVerifyRequest are not included in CertificateVerify or Finished MAC computations.",
                 evidence_in_boringssl=EV["transcript"] + EV["hvr_client"],
                 comment="BoringSSL resets the handshake transcript after processing HelloVerifyRequest, so the initial ClientHello and HelloVerifyRequest are excluded from later Finished/CertificateVerify transcript hashes.",
                 comparison_summary="The code explicitly calls hs->transcript.Init() after HelloVerifyRequest and before the second ClientHello is added, satisfying the RFC transcript exclusion rule.")
    elif idx == 17:
        r.update(status=SAT, standard_section=RFC["handshake"]["section"], standard_quote="CompressionMethod compression_methods<1..2^8-1>;",
                 evidence_in_boringssl=EV["clienthello"],
                 comment="解析端要求 compression_methods 为 u8-length-prefixed 且至少 1 字节；发送端固定发送一个 null compression method。",
                 comparison_summary="The RFC lower bound is enforced, and the u8 vector prefix imposes the upper bound.")
    elif idx in (18, 19, 20, 25, 27, 28):
        r.update(status=SAT, standard_section=RFC["cookie_size"]["section"], standard_quote=RFC["cookie_size"]["quote"],
                 evidence_in_boringssl=EV["hvr_client"] + EV["clienthello"],
                 comment="客户端 ClientHello 的 DTLS cookie 是 u8-length-prefixed；初次握手 hs->dtls_cookie 为空，收到 HelloVerifyRequest 后复制 cookie 并重发。",
                 comparison_summary="BoringSSL's client-side DTLS legacy cookie path matches the RFC field size and retransmission behavior. Empty and 255-byte cookies are feasible because CBS/CBB u8 vectors naturally encode 0..255.")
    elif idx in (21, 22, 24, 26, 29, 30, 31):
        r.update(status=UNSAT, standard_section=RFC["cookie"]["section"], standard_quote=RFC["cookie"]["quote"],
                 evidence_in_boringssl=EV["server_cookie_absent"],
                 category="missing server HelloVerifyRequest cookie generation/validation path",
                 risk="medium",
                 comment="libssl 产品代码中未发现 DTLS 1.2 服务端生成 HelloVerifyRequest、计算/验证 stateless cookie、无效 cookie 当作无 cookie 重新挑战、或 secret 轮换接受窗口的实现路径；这些逻辑只在 runner 测试服务端中出现。",
                 comparison_summary="RFC describes server-side cookie generation and validation. BoringSSL implements client response handling, but rg over ssl and include/openssl finds no DTLSv1_listen-style public API or server-side HelloVerifyRequest generation/verification path in libssl. Test runner code is not shipped as the implementation.")
    elif idx == 23:
        r.update(status=PART, standard_section=RFC["cookie_size"]["section"], standard_quote=RFC["cookie_size"]["quote"],
                 evidence_in_boringssl=EV["hvr_client"] + EV["runner_cookie_32"],
                 category="test runner parser keeps obsolete 32-byte HelloVerifyRequest limit",
                 risk="low",
                 comment="libssl 客户端解析 HelloVerifyRequest 使用 u8-length-prefixed，可接受 255 字节；但 BoringSSL runner 的 helloVerifyRequestMsg.unmarshal 仍拒绝 cookieLen > 32，与 DTLS 1.2 的 255 字节上限不一致。",
                 comparison_summary="For production client behavior, the RFC 255-byte limit is satisfied. For the in-repo protocol runner used to test DTLS peers, the parser retains the old 32-byte limit, so conformance evidence is partial across the repository.")
    elif idx in (32, 34, 35, 39):
        r.update(status=SAT, standard_section=RFC["epoch"]["section"], standard_quote=RFC["epoch"]["quote"],
                 evidence_in_boringssl=EV["epoch"],
                 comment="DTLS 初始读写 epoch 使用 null cipher；cipher state 更新时 next_epoch 递增或映射 DTLS 1.3 固定 epoch；记录 MAC/AEAD 序列使用 epoch 与 sequence 的组合值。",
                 comparison_summary="The code initializes epoch zero, creates new read/write epochs on cipher changes, starts each write epoch at sequence zero, and serializes the combined epoch/sequence value into DTLS 1.2 record headers and AEAD sequence input.")
    elif idx == 33:
        r.update(status=SAT, standard_section="RFC 6347 Section 4.1 and Appendix A changes summary",
                 standard_quote="A prohibition on epoch wrapping in Section 4.1.",
                 evidence_in_boringssl=[rel("ssl/dtls_method.cc:59"), rel("ssl/dtls_record.cc:499")],
                 comment="next_epoch refuses to advance beyond 0xffff and dtls_seal_record checks record sequence overflow before sending.",
                 comparison_summary="Epoch wrap and sequence wrap are checked before state advancement or record sealing, so wrapping is not silently allowed.")
    elif idx == 36:
        r.update(status=SAT, standard_section=RFC["appdata"]["section"], standard_quote=RFC["appdata"]["quote"],
                 evidence_in_boringssl=EV["appdata"],
                 comment="DTLS 1.2 只查找当前 read_epoch；未知或未来 epoch 的记录被丢弃。应用数据只允许 epoch >= 1，握手完成前的新 epoch 数据无法匹配当前 read_epoch 时会被丢弃。",
                 comparison_summary="RFC allows discard or buffering before the corresponding Finished. BoringSSL chooses discard for unrecognized/future epochs in DTLS 1.2 rather than buffering.")
    elif idx == 37:
        r.update(status=SAT, standard_section=RFC["appdata"]["section"],
                 standard_quote="Receipt of application data with a new epoch before Finished may be treated as evidence of reordering or packet loss.",
                 evidence_in_boringssl=EV["appdata"],
                 comment="该条是 MAY 语义；BoringSSL 丢弃未知 epoch 记录并依赖 DTLS 丢包/重传处理，符合允许的处理范围。",
                 comparison_summary="The implementation does not need to surface a special signal; discarding and relying on retransmission is consistent with DTLS loss handling.")
    elif idx == 38:
        r.update(status=NA, standard_section="RFC 6347 Section 4.2.8, Rehandshake and New Associations",
                 standard_quote="A new handshake on an existing host/port quartet appears as epoch=0 ClientHello.",
                 evidence_in_boringssl=[rel("ssl/dtls_record.cc:246"), rel("ssl/dtls_record.cc:257")],
                 category="application association management outside libssl scope",
                 comment="该条涉及 UDP 5-tuple/association 调度策略；BoringSSL record layer 可解析 epoch 0，但是否把同一地址上的 epoch 0 ClientHello 视为新关联由应用的 BIO/连接管理决定。",
                 comparison_summary="The library exposes DTLS records on a connection but does not own datagram demultiplexing across associations, so this requirement is not directly applicable to the audited libssl path.")
    elif idx in (40, 41):
        r.update(status=PART, standard_section=RFC["epoch"]["section"],
                 standard_quote="Receivers MUST retain the previous epoch until the handshake has completed and MAY retain keying material for up to twice the TCP MSL.",
                 evidence_in_boringssl=[rel("ssl/dtls_method.cc:96"), rel("ssl/dtls_method.cc:104"), rel("ssl/dtls_record.cc:257"), rel("ssl/dtls_record.cc:368")],
                 category="DTLS 1.2 old epoch retention not implemented",
                 risk="medium",
                 comment="BoringSSL 为 DTLS 1.3 保留 prev_read_epoch，但 DTLS 1.2 set_read_state 直接替换 read_epoch；代码注释说明 DTLS 1.2 会忽略旧 epoch 记录。",
                 comparison_summary="RFC 6347 is a DTLS 1.2 requirement. BoringSSL's DTLS 1.2 path does not retain previous read epoch after cipher change, while newer DTLS 1.3 code has a retention mechanism. Thus the requirement is only partially met across DTLS code, not for DTLS 1.2.")
    elif idx in (42, 43):
        r.update(status=SAT, standard_section=RFC["fragment"]["section"], standard_quote=RFC["fragment"]["quote"],
                 evidence_in_boringssl=EV["fragment"],
                 comment="发送端根据当前 MTU 和 dtls_seal_max_input_len 将握手消息切分为 DTLS fragments；测试 runner 包含 ChangeMTU/retransmit 场景。",
                 comparison_summary="The implementation fragments handshake messages according to available record capacity, and retransmission paths reuse unacked ranges, satisfying the practical fragmentation requirement.")
    elif idx in (44, 45):
        r.update(status=SAT, standard_section="RFC 6347 Section 4.2.6, CertificateVerify and Finished Messages",
                 standard_quote="Hash calculations include entire handshake messages, including DTLS-specific fields: message_seq, fragment_offset, and fragment_length.",
                 evidence_in_boringssl=EV["transcript"] + [rel("ssl/d1_both.cc:550")],
                 comment="发送端把完整 DTLS handshake header 写入消息数组后更新 transcript；接收端重组后保留 offset=0 和完整 fragment_length 的 header。",
                 comparison_summary="BoringSSL hashes the full encoded DTLS handshake message, including DTLS-specific header fields, before Finished/CertificateVerify MAC computation.")
    elif idx == 46:
        r.update(status=SAT, standard_section="RFC 6347 Section 7.2, IANA Considerations",
                 standard_quote="hello_verify_request value 3 has been assigned by IANA.",
                 evidence_in_boringssl=[rel("include/openssl/ssl3.h:156"), rel("ssl/handshake_client.cc:521")],
                 comment="BoringSSL defines DTLS1_MT_HELLO_VERIFY_REQUEST as 3 and uses it in client state handling.",
                 comparison_summary="The constant matches the RFC allocation.")
    elif idx == 47:
        r.update(status=SAT, standard_section="RFC 6347 Section 4.2.1",
                 standard_quote="The initial ClientHello and HelloVerifyRequest are not included in CertificateVerify or Finished MAC computations.",
                 evidence_in_boringssl=EV["hvr_client"] + EV["transcript"],
                 comment="处理 HelloVerifyRequest 后重置 transcript，因此该消息不进入后续 Finished/CertificateVerify MAC。",
                 comparison_summary="This is the same transcript-exclusion behavior as the initial ClientHello rule and is directly implemented after HVR parsing.")
    elif idx == 48:
        r.update(status=SAT, standard_section="RFC 6347 Section 4.1, Record Layer",
                 standard_quote="The DTLSPlaintext length MUST NOT exceed 2^14.",
                 evidence_in_boringssl=EV["record_len"],
                 comment="输入记录长度受 SSL3_RT_MAX_ENCRYPTED_LENGTH 限制；输出密文长度计算失败会返回 RECORD_TOO_LARGE。",
                 comparison_summary="BoringSSL bounds parsed and sealed record lengths before decryption/encryption.")
    elif idx in (49, 50):
        r.update(status=SAT, standard_section=RFC["alerts"]["section"], standard_quote=RFC["alerts"]["quote"],
                 evidence_in_boringssl=EV["alerts"],
                 comment="BoringSSL 多数 DTLS 无效记录选择静默丢弃；当选择发送 alert 时，调用 ssl_send_alert 的路径使用 SSL3_AL_FATAL。",
                 comparison_summary="RFC permits silent discard. The audited alert-generating paths use fatal level, so the conditional requirement is met.")
    else:
        raise AssertionError(idx)
    return r


def validate_evidence(results):
    checks = []
    for r in results:
        for e in r.get("evidence_in_boringssl", []):
            if ":" not in e:
                checks.append({"id": r["id"], "evidence": e, "exists": False, "line_in_range": False})
                continue
            path_part, line_s = e.rsplit(":", 1)
            rel_path = path_part.replace(IMPL + "/", "")
            file_path = TARGET / rel_path
            exists = file_path.exists()
            try:
                line = int(line_s)
            except ValueError:
                line = -1
            line_count = 0
            if exists:
                with file_path.open("r", encoding="utf-8", errors="replace") as f:
                    line_count = sum(1 for _ in f)
            checks.append({
                "id": r["id"],
                "evidence": e,
                "exists": exists,
                "line_in_range": exists and 1 <= line <= line_count,
                "line_count": line_count,
            })
    return checks


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    changes = data["changes"][:50]
    results = [classify(i + 1, item) for i, item in enumerate(changes)]
    checks = validate_evidence(results)
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    meta = {
        "source_file": str(INPUT),
        "scope": "001-050_rules",
        "method": "static_code_comparison_with_phase2_verification",
        "protocol": "DTLS 1.2",
        "standard_reference": "https://www.rfc-editor.org/rfc/rfc6347",
        "target": IMPL,
        "counts": counts,
        "evidence_validation": {
            "checked": len(checks),
            "missing": [c for c in checks if not c["exists"]],
            "out_of_range": [c for c in checks if c["exists"] and not c["line_in_range"]],
        },
    }
    compare = {"meta": meta, "results": results}
    write_json(OUT / "compare_boringssl_001_050.json", compare)

    lines = [
        "# BoringSSL DTLS 1.2 001-050 对比结果",
        "",
        f"- 满足: {counts.get(SAT, 0)}",
        f"- 部分满足: {counts.get(PART, 0)}",
        f"- 不满足: {counts.get(UNSAT, 0)}",
        f"- 不适用: {counts.get(NA, 0)}",
        "",
        "| ID | variable | action | 状态 | 说明 |",
        "|---:|---|---|---|---|",
    ]
    simple = []
    for r in results:
        lines.append(f"| {r['id']:03d} | {r['variable_name']} | {r['change_action']} | {r['status']} | {r['comment']} |")
        simple.append(f"{r['id']:03d}\t{r['status']}\t{r['variable_name']}\t{r['comment']}")
    (OUT / "compare_boringssl_001_050.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "compare_boringssl_001_050_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")

    findings = [r for r in results if r["status"] in (PART, UNSAT)]
    groups = {}
    for r in findings:
        groups.setdefault(r["category"], []).append(r)
    classification = {
        "meta": {
            "scope": "001-050_rules",
            "target": IMPL,
            "counts": {"total": len(findings), PART: sum(1 for r in findings if r["status"] == PART), UNSAT: sum(1 for r in findings if r["status"] == UNSAT)},
            "risk_counts": {risk: sum(1 for r in findings if r.get("risk") == risk) for risk in sorted({r.get("risk") for r in findings})},
            "phase2_status": "completed",
        },
        "groups": {},
    }
    for cat, items in groups.items():
        classification["groups"][cat] = {
            "count": len(items),
            "items": []
        }
        for r in items:
            v = {
                "id": r["id"],
                "status": r["status"],
                "variable_name": r["variable_name"],
                "change_action": r["change_action"],
                "change_condition": r["change_condition"],
                "category": r["category"],
                "risk": r["risk"],
                "standard_section": r["standard_section"],
                "comment": r["comment"],
                "evidence_in_boringssl": r["evidence_in_boringssl"],
                "standard_check": "",
                "code_check": "",
                "test_check": "",
                "decision_reason": "",
                "phase2_decision": "",
            }
            if r["id"] == 23:
                v.update(
                    standard_check="RFC 6347 raises the HelloVerifyRequest/ClientHello cookie vector to opaque cookie<0..2^8-1>, so a 255-byte cookie is valid in DTLS 1.2.",
                    code_check="libssl client parsing uses CBS_get_u8_length_prefixed and therefore accepts 0..255 bytes; ssl/test/runner/handshake_messages.go still rejects helloVerifyRequestMsg cookieLen > 32.",
                    test_check="verify_dtls12_cookie_paths.py confirmed the libssl u8-length parser and the runner cookieLen > 32 guard. No compiled shim was present, so the runtime check is source-executed and logged.",
                    decision_reason="The production client path satisfies the 255-byte requirement, but the in-repo DTLS peer runner contradicts it. This is a confirmed partial conformance issue for repository test/interoperability behavior, not for the shipped client parser.",
                    phase2_decision="confirmed_partial",
                )
            elif r["id"] in (40, 41):
                v.update(
                    standard_check="RFC 6347 requires old epoch handling during the handshake and warns against reusing epoch values within the old-packet lifetime.",
                    code_check="DTLS 1.2 set_read_state directly replaces read_epoch. Only DTLS 1.3 creates next_read_epoch/prev_read_epoch retention; dtls_record.cc states DTLS 1.2 only considers one epoch.",
                    test_check="verify_dtls12_cookie_paths.py checked the DTLS 1.2 branch and found no prev_read_epoch assignment in that path. No compiled libssl test binary was available.",
                    decision_reason="The implementation has robust newer-epoch retention for DTLS 1.3, but not the DTLS 1.2 previous-epoch retention expected by RFC 6347. This is confirmed partial.",
                    phase2_decision="confirmed_partial",
                )
            else:
                v.update(
                    standard_check="RFC 6347 Section 4.2.1 defines server-side HelloVerifyRequest cookie generation, validation, invalid-cookie handling, and secret rotation guidance.",
                    code_check="Production libssl contains client-side HelloVerifyRequest handling but no server-side DTLSv1_listen/cookie callback, HelloVerifyRequest generation, HMAC-style cookie computation, or cookie verification path. The only server cookie implementation found is in ssl/test/runner.",
                    test_check="verify_dtls12_cookie_paths.py searched product and runner paths and confirmed the absence in ssl/ and include/openssl while finding only runner-side generation/validation.",
                    decision_reason="The RFC requirement is server behavior. BoringSSL's production server path does not implement the HelloVerifyRequest cookie exchange; therefore this item is confirmed unsatisfied.",
                    phase2_decision="confirmed_unsatisfied",
                )
            classification["groups"][cat]["items"].append(v)
    write_json(OUT / "compare_boringssl_001_050_partial_unsat_classification.json", classification)

    md = ["# BoringSSL DTLS 1.2 001-050 部分满足/不满足分类", ""]
    for cat, g in classification["groups"].items():
        md.append(f"## {cat} ({g['count']})")
        md.append("")
        md.append("| ID | 状态 | 风险 | 复核结论 | 说明 |")
        md.append("|---:|---|---|---|---|")
        for it in g["items"]:
            md.append(f"| {it['id']:03d} | {it['status']} | {it['risk']} | {it['phase2_decision']} | {it['decision_reason']} |")
        md.append("")
    (OUT / "compare_boringssl_001_050_partial_unsat_classification.md").write_text("\n".join(md), encoding="utf-8")

    summary = {
        "round": "001-050",
        "output_dir": str(OUT),
        "status_counts": counts,
        "classification_counts": classification["meta"]["counts"],
        "confirmed_reports": [
            "id021_022_024_026_029_030_031_server_hello_verify_cookie_missing_unsatisfied.md",
            "id023_hello_verify_request_cookie_255_runner_limit_partial.md",
            "id040_041_dtls12_previous_epoch_retention_partial.md",
        ],
        "next_round": "051-098 (input JSON has 98 records; requested overall_end_id 050 completes this run, next available range starts at 051 if requested)",
    }
    write_json(OUT / "round_summary_001_050.json", summary)


if __name__ == "__main__":
    main()
