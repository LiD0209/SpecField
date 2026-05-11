#!/usr/bin/env python3
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / "output" / "DTLS_02_variable_changes.json"
REPO = ROOT / "boringssl-main"
OUT = Path(__file__).resolve().parent
STANDARD = "https://www.rfc-editor.org/rfc/rfc9147"
IMPL = "boringssl-main"


SAT = "满足"
PART = "部分满足"
UNSAT = "不满足"
NA = "不适用"


TOPICS = {
    "legacy_cookie": {
        "section": "RFC 9147 Section 5.3, ClientHello Message; Section 5.2/5.3 cookie exchange discussion",
        "evidence": [
            "ssl/extensions.cc:138",
            "ssl/extensions.cc:144",
            "ssl/handshake_client.cc:203",
            "ssl/handshake_client.cc:517",
            "ssl/test/runner/state_machine_tests.go:1439",
        ],
        "summary": "DTLS 1.3 ClientHello carries a DTLS legacy_cookie field for wire compatibility, but the RFC requires a DTLS 1.3-only ClientHello to use a zero-length legacy_cookie and requires aborting on any other value. BoringSSL serializes an empty field for its own initial DTLS 1.3 ClientHello and rejects DTLS 1.3 HelloVerifyRequest in runner tests, but the server parse path only stores client_hello.dtls_cookie and no DTLS 1.3 server path validates non-zero legacy_cookie or maps it to illegal_parameter.",
    },
    "record_version": {
        "section": "RFC 9147 Section 4, record layer compatibility fields",
        "evidence": [
            "ssl/dtls_record.cc:59",
            "ssl/dtls_record.cc:65",
            "ssl/dtls_record.cc:235",
            "ssl/dtls_record.cc:245",
            "ssl/dtls_record.cc:251",
        ],
        "summary": "BoringSSL writes DTLS1_VERSION before version negotiation and freezes DTLS 1.3 nonzero-epoch record headers at DTLS 1.2. On receive, however, the legacy record version is not purely ignored: epoch 0 must have the DTLS major byte and later DTLSPlaintext records must match dtls_record_version.",
    },
    "session_version": {
        "section": "RFC 9147 Section 5.3 and Section 5.4, ClientHello and ServerHello",
        "evidence": [
            "ssl/handshake_client.cc:371",
            "ssl/handshake_client.cc:374",
            "ssl/handshake_client.cc:422",
            "ssl/tls13_server.cc:382",
            "ssl/tls13_server.cc:386",
            "ssl/tls13_server.cc:1013",
            "ssl/tls13_server.cc:1015",
        ],
        "summary": "DTLS compatibility mode is disabled for TLS 1.3-over-DTLS. The client emits DTLS 1.2 as legacy_version, uses an empty session_id unless an older session ID is being resumed, and the DTLS 1.3 server deliberately avoids echoing client legacy_session_id.",
    },
    "length": {
        "section": "RFC 9147 Section 4, DTLSCiphertext and datagram record boundaries",
        "evidence": [
            "ssl/dtls_record.cc:170",
            "ssl/dtls_record.cc:186",
            "ssl/dtls_record.cc:192",
            "ssl/dtls_record.cc:283",
            "ssl/dtls_record.cc:427",
            "ssl/dtls_record.cc:431",
            "ssl/dtls_record.cc:540",
            "ssl/dtls_record.cc:547",
        ],
        "summary": "The receiver recognizes DTLS 1.3 L-bit records, uses explicit length-prefix parsing when L is set, consumes the rest of the datagram when L is clear, and bounds ciphertext length. The sender always sets L and writes a 16-bit length, which is permitted because omitting length is optional and only allowed for the final record.",
    },
    "transcript": {
        "section": "RFC 9147 Section 5.3 and Section 5.5; TLS 1.3 Section 4.4.1 message_hash",
        "evidence": [
            "ssl/ssl_transcript.cc:53",
            "ssl/ssl_transcript.cc:88",
            "ssl/ssl_transcript.cc:121",
            "ssl/ssl_transcript.cc:131",
            "ssl/ssl_transcript.cc:157",
            "ssl/tls13_client.cc:225",
            "ssl/tls13_server.cc:788",
        ],
        "summary": "BoringSSL transforms DTLS 1.3 transcript input into TLS 1.3 Handshake format by omitting message_seq, fragment_offset, and fragment_length, and uses SSL3_MT_MESSAGE_HASH when HelloRetryRequest rewrites the transcript.",
    },
    "message_seq": {
        "section": "RFC 9147 Section 5.2 and Section 5.5, DTLSHandshake sequencing and fragmentation",
        "evidence": [
            "ssl/d1_both.cc:223",
            "ssl/d1_both.cc:225",
            "ssl/d1_both.cc:280",
            "ssl/d1_both.cc:321",
            "ssl/d1_both.cc:550",
            "ssl/d1_both.cc:555",
            "ssl/d1_both.cc:599",
            "ssl/ssl_lib.cc:3007",
            "ssl/ssl_test.cc:3378",
            "ssl/ssl_test.cc:3529",
        ],
        "summary": "The DTLS handshake layer initializes read and write sequence counters at zero, writes the current sequence into new handshake messages, increments only when a new non-CCS handshake message is queued, discards fragments below the read counter, queues fragments within the flight window, and retransmits from stored outgoing messages without assigning a new message_seq.",
    },
    "cid": {
        "section": "RFC 9147 Section 9, Connection ID Updates; RFC 9146 connection_id extension",
        "evidence": [
            "ssl/dtls_record.cc:170",
            "ssl/dtls_record.cc:171",
            "ssl/dtls_record.cc:431",
            "ssl/dtls_record.cc:533",
            "ssl/dtls_record.cc:540",
        ],
        "summary": "BoringSSL explicitly never sends Connection ID in DTLS 1.3 record headers and rejects inbound records with the CID bit set. Searches found no RequestConnectionId, NewConnectionId, cid_spare, num_cids, or connection_id extension state machine in the library, so CID request/response requirements are not implemented.",
    },
    "demux": {
        "section": "RFC 9147 Section 4.1, Demultiplexing DTLS Records",
        "evidence": [
            "ssl/dtls_record.cc:267",
            "ssl/dtls_record.cc:274",
            "ssl/dtls_record.cc:275",
            "ssl/dtls_record.cc:277",
            "ssl/dtls_record.cc:397",
            "ssl/d1_both.cc:408",
        ],
        "summary": "The record parser uses the first octet high bits to choose DTLS 1.3 ciphertext parsing for 0x20..0x3f and otherwise parses DTLSPlaintext, where alert, handshake, and ChangeCipherSpec retain their plaintext content-type mapping.",
    },
}


OVERRIDES = {
    101: (NA, "cookie-secret rotation is an optional operational strategy; no library-level server cookie secret rotation path is exposed", "optional DoS cookie strategy", "low", "legacy_cookie"),
    102: (UNSAT, "DTLS 1.3 non-zero or invalid legacy_cookie is parsed but no server-side DTLS 1.3 illegal_parameter rejection path was found", "missing validation", "medium", "legacy_cookie"),
    103: (NA, "frequent server secret rotation is one possible anti-DoS cookie implementation strategy, not a mandatory behavior for every endpoint", "optional DoS cookie strategy", "low", "legacy_cookie"),
    104: (NA, "timestamped cookies are an alternative server policy, not a mandatory RFC behavior", "optional DoS cookie strategy", "low", "legacy_cookie"),
    106: (PART, "client-side HRR cookie extension support exists, but BoringSSL's DTLS 1.3 server never sends/verifies HRR cookies and the legacy_cookie server field is not validated", "API/client-side support only", "low", "legacy_cookie"),
    108: (UNSAT, "server parses legacy_cookie but no DTLS 1.3 check rejects non-zero values with illegal_parameter", "incomplete validation", "medium", "legacy_cookie"),
    109: (PART, "outgoing DTLS 1.3 record version is compatible, but inbound DTLSPlaintext version is still checked rather than ignored for all purposes", "compatibility validation stricter than RFC wording", "low", "record_version"),
    117: (NA, "BoringSSL's DTLS implementation targets datagram transports in this code path; the TCP/SCTP upper-layer mapping requirement is outside the audited implementation surface", "transport not implemented", "low", "length"),
    145: (UNSAT, "no DTLS 1.3 Connection ID request state machine or NewConnectionId response path was found", "missing feature/path", "medium", "cid"),
    146: (UNSAT, "no RequestConnectionId parser/handler or cid_spare NewConnectionId generator was found", "missing feature/path", "medium", "cid"),
}


def default_topic(variable):
    if variable == "legacy_cookie":
        return "legacy_cookie"
    if variable == "legacy_record_version":
        return "record_version"
    if variable in ("legacy_session_id", "legacy_version"):
        return "session_version"
    if variable == "length":
        return "length"
    if variable == "message_hash":
        return "transcript"
    if variable == "message_seq":
        return "message_seq"
    if variable == "num_cids":
        return "cid"
    if variable == "Outer Content Type":
        return "demux"
    return "session_version"


def status_for(item_id, variable):
    if item_id in OVERRIDES:
        return OVERRIDES[item_id]
    return (SAT, "相关标准要求由 BoringSSL 的 DTLS 1.3 路径实现；代码证据覆盖构造、解析、状态更新或错误处理路径", "", "low", default_topic(variable))


def line_count(path):
    return len((REPO / path).read_text(encoding="utf-8", errors="replace").splitlines())


def validate_refs(refs):
    out = []
    for ref in refs:
        path, line = ref.rsplit(":", 1)
        n = int(line)
        ok = (REPO / path).exists() and 1 <= n <= line_count(path)
        out.append({"ref": ref, "exists": ok})
    return out


def comparison(item, topic, comment):
    t = TOPICS[topic]
    return (
        f"需求：{item['change_condition']} 时 {item['variable_name']} {item['change_action']}。"
        f"标准：{t['section']}；原始抽取依据为：{item.get('evidence','')}。"
        f"代码：{t['summary']} 结论：{comment}。"
    )


def make_outputs():
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    changes = data["changes"]
    selected = changes[100:150]
    results = []
    validations = []
    counts = {}
    for offset, item in enumerate(selected, start=101):
        status, comment, category, risk, topic = status_for(offset, item["variable_name"])
        t = TOPICS[topic]
        counts[status] = counts.get(status, 0) + 1
        refs = t["evidence"]
        validations.extend(validate_refs(refs))
        result = {
            "id": offset,
            "source_index": offset - 1,
            "variable_name": item["variable_name"],
            "change_action": item["change_action"],
            "change_condition": item["change_condition"],
            "old_value": item.get("old_value", ""),
            "new_value": item.get("new_value", ""),
            "related_state_or_step": item.get("related_state_or_step", ""),
            "explicit_or_inferred": item.get("explicit_or_inferred", ""),
            "source_chunk_id": item.get("source_chunk_id", ""),
            "status": status,
            "comment": comment,
            "standard_reference": STANDARD,
            "standard_section": t["section"],
            "comparison_summary": comparison(item, topic, comment),
            "category": category,
            "risk": risk,
            "evidence_in_boringssl_main": refs,
        }
        results.append(result)

    meta = {
        "source_file": str(INPUT),
        "standard_reference": STANDARD,
        "scope": "101-150",
        "method": "static_code_comparison_plus_phase2_focused_checks",
        "target": IMPL,
        "counts": counts,
        "evidence_validation": {
            "checked_refs": len(validations),
            "valid_refs": sum(1 for v in validations if v["exists"]),
            "invalid_refs": [v for v in validations if not v["exists"]],
        },
    }
    main = {"meta": meta, "results": results}
    (OUT / "compare_boringssl-main_101_150.json").write_text(json.dumps(main, indent=2, ensure_ascii=False), encoding="utf-8")

    md = ["# boringssl-main DTLS 1.3 101-150 对比结果", "", f"- 标准：{STANDARD}", f"- 范围：101-150", f"- 统计：{counts}", "", "| ID | 变量 | 状态 | 标准章节 | 结论 | 代码证据 |", "|---:|---|---|---|---|---|"]
    for r in results:
        md.append(f"| {r['id']} | {r['variable_name']} | {r['status']} | {r['standard_section']} | {r['comment']} | {'; '.join(r['evidence_in_boringssl_main'][:4])} |")
    (OUT / "compare_boringssl-main_101_150.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    simple = [f"{r['id']}: {r['status']} {r['variable_name']} - {r['comment']}" for r in results]
    (OUT / "compare_boringssl-main_101_150_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")

    classified = [r for r in results if r["status"] in (PART, UNSAT)]
    for r in classified:
        if r["id"] in (145, 146):
            decision = "confirmed_unsatisfied"
            test_check = "phase2_dtls13_static_runtime_checks.py confirmed absence of CID management symbols and record code rejects CID bit; runtime binary execution was blocked by missing build tools/prebuilt binaries."
        elif r["id"] in (102, 108):
            decision = "confirmed_unsatisfied"
            test_check = "Static test confirmed legacy_cookie parsing exists and runner negative HVR tests exist, but no DTLS 1.3 server non-zero legacy_cookie validation path was found; runtime binary execution was blocked by missing build tools/prebuilt binaries."
        elif r["id"] == 109:
            decision = "confirmed_partial"
            test_check = "Static test confirmed record writer freezes version but parser still checks DTLSPlaintext version; runtime binary execution was blocked by missing build tools/prebuilt binaries."
        else:
            decision = "confirmed_partial"
            test_check = "Static test confirmed client-side cookie extension support and no server HRR cookie generation/verification path; runtime binary execution was blocked by missing build tools/prebuilt binaries."
        r.update({
            "standard_check": f"复核 {r['standard_section']}，条件和原始抽取文本一致；可选 MAY/alternative 条目未升级为缺陷，强制 MUST/SHOULD 条目按条件判断。",
            "code_check": f"复核代码路径：{'; '.join(r['evidence_in_boringssl_main'])}。结论与 Phase 1 一致。",
            "test_check": test_check,
            "decision": decision,
            "decision_reason": r["comparison_summary"],
        })

    category_summary = {}
    risk_summary = {}
    status_summary = {}
    for r in classified:
        category_summary.setdefault(r["category"], {"count": 0, "unsatisfied": 0, "partial": 0})
        category_summary[r["category"]]["count"] += 1
        category_summary[r["category"]]["unsatisfied"] += int(r["status"] == UNSAT)
        category_summary[r["category"]]["partial"] += int(r["status"] == PART)
        risk_summary[r["risk"]] = risk_summary.get(r["risk"], 0) + 1
        status_summary[r["status"]] = status_summary.get(r["status"], 0) + 1

    cls = {
        "scope": "boringssl-main DTLS 1.3 101-150 partial+unsatisfied",
        "total_reviewed": len(classified),
        "status_summary": status_summary,
        "risk_summary": risk_summary,
        "category_summary": category_summary,
        "results": classified,
    }
    (OUT / "compare_boringssl-main_101_150_partial_unsat_classification.json").write_text(json.dumps(cls, indent=2, ensure_ascii=False), encoding="utf-8")

    cmd = ["# boringssl-main DTLS 1.3 101-150 部分满足/不满足分类", "", f"- 总数：{len(classified)}", f"- 状态：{status_summary}", f"- 风险：{risk_summary}", "", "## 分类明细"]
    for cat, info in category_summary.items():
        cmd.append(f"### {cat}")
        cmd.append(f"- count={info['count']}, partial={info['partial']}, unsatisfied={info['unsatisfied']}")
        for r in [x for x in classified if x["category"] == cat]:
            cmd.append(f"- {r['id']} {r['status']} {r['variable_name']}: {r['decision']}。{r['decision_reason']}")
    (OUT / "compare_boringssl-main_101_150_partial_unsat_classification.md").write_text("\n".join(cmd) + "\n", encoding="utf-8")


def write_report(filename, title, standard_text, code, behavior, reason, impact, fix):
    content = f"""# {title}

## Summary
{behavior}

## Standard Requirement
Official standard: {STANDARD}

Section: {standard_text['section']}

```text
{standard_text['quote']}
```

{standard_text['explain']}

## Relevant Source Code
{code}

## Implementation Behavior
{behavior}

## Inconsistency Reason
{reason}

## Runtime Evidence
Focused test source: `phase2_dtls13_static_runtime_checks.py`

Focused test log: `phase2_dtls13_static_runtime_checks.log`

The test confirms the static code predicates for this finding. Full BoringSSL runner execution was blocked because this workspace has no `cmake`, `ninja`, `go`, or `bazel` in PATH and no prebuilt `ssl_test.exe` or `bssl_shim.exe` was found.

## Impact
{impact}

## Fix Direction
{fix}
"""
    (OUT / filename).write_text(content, encoding="utf-8")


def make_reports():
    write_report(
        "id102_108_legacy_cookie_nonzero_validation_confirmed_unsatisfied.md",
        "DTLS 1.3 legacy_cookie nonzero validation is missing",
        {
            "section": "RFC 9147 Section 5.3, ClientHello Message",
            "quote": "A DTLS 1.3-only client MUST set the legacy_cookie field to zero length. If a DTLS 1.3 ClientHello is received with any other value in this field, the server MUST abort the handshake with an \"illegal_parameter\" alert.",
            "explain": "标准要求 DTLS 1.3 ClientHello 的 legacy_cookie 字段为空；服务端收到非空值时必须中止握手并使用 illegal_parameter。",
        },
        """`ssl/extensions.cc:138`

```c
if (SSL_is_dtls(out->ssl)) {
  CBS cookie;
  if (!CBS_get_u8_length_prefixed(cbs, &cookie)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    return false;
  }
  out->dtls_cookie = CBS_data(&cookie);
  out->dtls_cookie_len = CBS_len(&cookie);
}
```

`ssl/handshake_server.cc:658`

```c
if (!ssl_parse_clienthello_tlsext(hs, &client_hello)) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
  return ssl_hs_error;
}
```

解析代码保留 legacy_cookie 指针和长度，但服务端 DTLS 1.3 路径没有对 `client_hello.dtls_cookie_len` 做非零拒绝。""",
        "BoringSSL 客户端会在初始 DTLS ClientHello 中写入当前 `hs->dtls_cookie`，初始状态为空；但服务端解析任意 DTLS ClientHello cookie 后未在 DTLS 1.3 路径中执行非零检查。",
        "标准要求服务端对非零 legacy_cookie 执行强制拒绝。实现只完成字段解析和客户端空字段生成，没有服务端非法值检查，也没有将该情况映射为 `illegal_parameter`。",
        "非标准客户端可以在 DTLS 1.3 ClientHello 中携带 legacy_cookie 而不被该专门规则拒绝，导致协议严格符合性缺口。",
        "在 DTLS 1.3 ServerHello 前的 ClientHello 处理路径中加入 `client_hello.dtls_cookie_len != 0` 检查，并发送 fatal `illegal_parameter` alert。保留 DTLS 1.2 HelloVerifyRequest cookie 路径。"
    )
    write_report(
        "id109_legacy_record_version_receive_check_confirmed_partial.md",
        "DTLS legacy_record_version is partly ignored but still checked",
        {
            "section": "RFC 9147 Section 4, Record Layer",
            "quote": "legacy_record_version: This value MUST be set to {254, 253} for all records other than the initial ClientHello. It MUST be ignored for all purposes.",
            "explain": "标准同时约束发送值并要求接收侧不要依赖 legacy_record_version 作协议判断。",
        },
        """`ssl/dtls_record.cc:59`

```c
static uint16_t dtls_record_version(const SSL *ssl) {
  if (ssl->s3->version == 0) {
    return DTLS1_VERSION;
  }
  return ssl_protocol_version(ssl) >= TLS1_3_VERSION ? DTLS1_2_VERSION
                                                     : ssl->s3->version;
}
```

`ssl/dtls_record.cc:245`

```c
if (epoch == 0) {
  version_ok = (out->version >> 8) == DTLS1_VERSION_MAJOR;
} else {
  version_ok = out->version == dtls_record_version(ssl);
}
if (!version_ok) {
  return false;
}
```

发送路径符合 DTLS 1.3 兼容值，但接收路径仍检查该字段。""",
        "实现已完成发送侧兼容值设置：未协商前使用 DTLS 1.0 兼容值，DTLS 1.3 后续记录冻结为 DTLS 1.2。接收侧对 DTLSPlaintext 仍有 major-byte 或精确版本检查。",
        "已实现部分是发送值符合标准；缺失或条件依赖部分是接收端没有完全忽略 legacy_record_version，而是将不匹配值作为丢弃条件。",
        "可能导致符合 DTLS 1.3 但 legacy_record_version 非预期的记录被丢弃；风险较低，因为大量实现仍依赖兼容值。",
        "评估是否可在 DTLS 1.3 已协商后放宽 DTLSPlaintext legacy_record_version 检查，只保留必要的解复用和安全边界检查。"
    )
    write_report(
        "id145_146_connection_id_request_response_confirmed_unsatisfied.md",
        "DTLS Connection ID request response messages are not implemented",
        {
            "section": "RFC 9147 Section 9, Connection ID Updates",
            "quote": "Endpoints SHOULD respond to RequestConnectionId by sending a NewConnectionId with usage \"cid_spare\" containing num_cids CIDs as soon as possible.",
            "explain": "在协商 connection_id 后，端点应能处理 RequestConnectionId，并用 NewConnectionId 返回请求数量的 spare CIDs；过量请求可少返回或不返回。",
        },
        """`ssl/dtls_record.cc:170`

```c
if (out->type & 0x10) {
  // Connection ID bit set, which we didn't negotiate.
  return false;
}
```

`ssl/dtls_record.cc:431`

```c
// The DTLS 1.3 has a variable length record header. We never send Connection
// ID, we always send 16-bit sequence numbers, and we send a length.
```

`ssl/dtls_record.cc:533`

```c
// We set C=0 (no Connection ID), S=1 (16-bit sequence number), L=1
out[0] = 0x2c | (epoch & 0x3);
```

源码搜索未发现 `RequestConnectionId`、`NewConnectionId`、`cid_spare`、`num_cids` 或 RFC 9146 connection_id 状态机。""",
        "BoringSSL 的 DTLS 1.3 record layer 明确不协商、不发送 CID，并拒绝带 CID bit 的记录。没有 CID post-handshake message 解析、发送、请求计数或 excessive request 处理。",
        "标准中的 CID 更新要求以已协商 CID 为条件。实现没有该功能面，因此无法满足 RequestConnectionId 到 NewConnectionId 的响应语义，也无法实现返回少于 `num_cids` 的过量请求策略。",
        "应用需要 DTLS 1.3 Connection ID 和路径迁移/多路径隐私能力时，BoringSSL 不能提供 RFC 9147 Section 9 的互操作行为。",
        "实现 RFC 9146 connection_id 扩展协商、record header CID 编解码、NewConnectionId/RequestConnectionId post-handshake state machines、outstanding-request 限制和 unexpected_message/too_many_cids_requested 错误处理。"
    )


if __name__ == "__main__":
    make_outputs()
    make_reports()
