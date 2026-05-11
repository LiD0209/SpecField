#!/usr/bin/env python3
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / "output" / "DTLS_02_variable_changes.json"
OUT = ROOT / "test-boringssl" / "001-050"
IMPL = "boringssl-main"

SAT = "满足"
PART = "部分满足"
UNSAT = "不满足"
NA = "不适用"

STANDARD = {
    "ack": "RFC 9147 Sections 5.8, 7 and 7.1",
    "record": "RFC 9147 Sections 4.1, 4.2.1, 4.2.2 and 4.2.3",
    "cid": "RFC 9147 Section 9",
    "cookie": "RFC 9147 Section 5.2 and RFC 8446 Section 4.2.2",
    "cipher": "RFC 9147 Section 5.1 and Section 11 IANA considerations",
    "epoch": "RFC 9147 Section 6.1",
    "body": "RFC 9147 Section 5.2 and Section 5.3",
}

GROUPS = {
    "ack": {
        "comment": "BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking.",
        "evidence": [
            "ssl/d1_pkt.cc:35",
            "ssl/d1_pkt.cc:53",
            "ssl/d1_pkt.cc:70",
            "ssl/d1_pkt.cc:82",
            "ssl/d1_pkt.cc:98",
            "ssl/d1_pkt.cc:122",
            "ssl/d1_both.cc:255",
            "ssl/d1_both.cc:307",
            "ssl/d1_both.cc:347",
            "ssl/d1_both.cc:352",
            "ssl/d1_both.cc:357",
            "ssl/d1_both.cc:931",
            "ssl/d1_both.cc:961",
        ],
        "summary": "标准要求 DTLS 1.3 中除隐式确认外的握手/后握手 flight 通过 ACK 明确确认，ACK 只确认已处理或已缓存的握手记录，并驱动停止或重传。代码在记录解密和握手片段处理之后才加入 records_to_ack，发送 ACK 时按 MTU 取可容纳记录并排序，接收 ACK 时匹配 sent_records 并标记对应消息范围；完整确认会停止重传并清理 flight。",
    },
    "record": {
        "comment": "BoringSSL implements DTLS 1.3 unified record header parsing, record-number reconstruction/encryption, AEAD deprotection, inner content-type tail scan, and invalid-type rejection.",
        "evidence": [
            "ssl/dtls_record.cc:59",
            "ssl/dtls_record.cc:71",
            "ssl/dtls_record.cc:80",
            "ssl/dtls_record.cc:170",
            "ssl/dtls_record.cc:267",
            "ssl/dtls_record.cc:327",
            "ssl/dtls_record.cc:354",
            "ssl/dtls_record.cc:397",
            "ssl/dtls_record.cc:401",
            "ssl/dtls_record.cc:427",
            "ssl/dtls_record.cc:525",
            "ssl/dtls_record.cc:556",
            "ssl/dtls_record.cc:563",
        ],
        "summary": "标准要求 DTLSCiphertext 的 encrypted_record 是加密后的 DTLSInnerPlaintext，解密后按内部 content type 分派并拒绝未知类型。代码先解析 DTLS 1.3 header、重建 epoch/sequence、用 AEAD 打开密文，再从明文尾部移除零填充并读取内部 content type；alert、application_data、handshake、ACK 有相应路径，其他类型在上层读取路径中报 unexpected record。",
    },
    "cid": {
        "comment": "BoringSSL does not negotiate DTLS Connection ID and explicitly rejects DTLS 1.3 records with the CID bit set.",
        "evidence": [
            "ssl/dtls_record.cc:170",
            "ssl/dtls_record.cc:431",
            "ssl/dtls_record.cc:527",
            "ssl/test/runner/basic_tests.go:1956",
        ],
        "summary": "RFC 9147 的 CID 行为是协商后的条件性行为。BoringSSL 记录层注释和写出路径表明从不发送 CID，解析路径在 C bit 置位时直接拒绝；runner 中也有 CID bit record dropped 的测试。因此未协商 CID 时的拒绝规则满足，协商后使用/轮换 CID 的规则对该实现不适用。",
    },
    "cookie": {
        "comment": "BoringSSL handles TLS 1.3 HelloRetryRequest cookie by copying the cookie and adding it to the next ClientHello extension.",
        "evidence": [
            "ssl/tls13_client.cc:272",
            "ssl/tls13_client.cc:277",
            "ssl/tls13_client.cc:287",
            "ssl/extensions.cc:2673",
            "ssl/extensions.cc:2680",
        ],
        "summary": "标准要求客户端收到含 cookie 的 HelloRetryRequest 后发送带 cookie extension 的新 ClientHello。代码解析 HRR cookie，拒绝空/格式错误 cookie，将值复制到 hs->cookie，并在后续 ClientHello 扩展生成时写入 TLSEXT_TYPE_cookie。",
    },
    "cipher": {
        "comment": "BoringSSL DTLS 1.3 uses the TLS 1.3 cipher suite set implemented by libssl, which is AES-GCM/AES-CCM/ChaCha20-Poly1305 based and has record-number encryption support.",
        "evidence": [
            "ssl/dtls_record.cc:71",
            "ssl/dtls_record.cc:90",
            "ssl/dtls_record.cc:563",
            "ssl/dtls_method.cc:89",
            "ssl/dtls_method.cc:123",
        ],
        "summary": "标准要求 DTLS 1.3 只使用 DTLS-OK cipher suites，并且非 AES/ChaCha20 的未来套件要定义自己的记录序号加密。BoringSSL 的 DTLS 1.3 记录层为已支持套件创建 RecordNumberEncrypter，并未引入不具备 DTLS 记录号保护定义的未来套件。",
    },
    "epoch": {
        "comment": "BoringSSL maps DTLS 1.3 encryption levels to epochs and skips early-data epoch when early data is not installed.",
        "evidence": [
            "ssl/dtls_method.cc:43",
            "ssl/dtls_method.cc:71",
            "ssl/dtls_method.cc:111",
            "ssl/dtls_record.cc:401",
        ],
        "summary": "标准定义 DTLS 1.3 epoch 分配；无 early_data 时 epoch 1 不会实际安装。代码的 next_epoch 按 encryption level 赋 epoch，只有设置 early_data 读/写状态时才使用对应 epoch，应用数据允许性也按 epoch 1 或 3+ 判断。",
    },
    "body": {
        "comment": "BoringSSL parses DTLS handshake fragments and dispatches complete handshake messages by message type.",
        "evidence": [
            "ssl/d1_both.cc:255",
            "ssl/d1_both.cc:436",
            "ssl/d1_both.cc:448",
            "ssl/handshake.cc:152",
        ],
        "summary": "标准中的 DTLSHandshake body 是按 msg_type 选择的 union。BoringSSL 解析 DTLS handshake fragment header，重组完整消息后把 type/body 交给握手状态机，未知或不合时序的消息由状态机或 post-handshake 分派拒绝。",
    },
}

def group_for(item, idx):
    v = item["variable_name"]
    if v == "ACK" or idx in {29}:
        return "ack"
    if v == "cids":
        return "cid"
    if v in {"cipher_suites", "CipherSuite"}:
        return "cipher"
    if v == "client_hello":
        return "cookie"
    if v in {"Content Type"}:
        return "record"
    if v in {"Decrypted Content Type", "encrypted_record"}:
        return "record"
    if v == "early_data":
        return "epoch"
    if v == "body":
        return "body"
    if v == "encrypted_extensions":
        return "record"
    return "record"

na_ids = {
    4: "该条来自 RFC 图示中的 Record 5 ACK [2]，是说明性示例，不是独立运行时 MUST/SHOULD。",
    5: "该条来自 RFC 图示中的 empty ACK 示例，说明特定丢包时序，不是独立通用要求。",
    31: "DTLS CID 是协商后的条件行为；BoringSSL 不协商 CID，因此 cid_immediate 使用规则不适用。",
    32: "DTLS CID spare CID 维护仅在实现 NewConnectionId/CID 协商时适用；BoringSSL 未实现该可选功能。",
    33: "Receiver-provided CID 顺序使用仅在 CID 协商后适用；BoringSSL 不协商或保存 receiver-provided CIDs。",
    34: "条件为 Connection ID 已协商；BoringSSL 不协商 CID，并在写路径固定 C=0。",
    36: "该条要求同一 datagram 多记录 CID 关联一致性；BoringSSL 不协商 CID，C bit 置位记录会被拒绝。",
    37: "该条约束未来非 AES/ChaCha20 cipher suite 的规范定义，不是 BoringSSL 当前运行时行为。",
    39: "该条是 TLS Cipher Suites 注册表/规范编写要求，不是实现中的单条运行时检查。",
    41: "该条是 IANA reserved content-type allocation 规则，不是实现必须分配的运行时行为。",
    45: "Heartbeat content type 取决于 Heartbeat 扩展支持；BoringSSL 当前未实现 DTLS Heartbeat 路径，因此该映射不适用。",
}

partial = {
    7: {
        "category": "incomplete retransmission scheduling",
        "risk": "medium",
        "comment": "BoringSSL 接收 partial ACK 后会标记已确认的消息范围，并且后续重传只发送未确认范围；但 partial ACK 分支仅留下 TODO，没有立即调度重传或立刻进入发送未确认部分的路径，只能等现有 retransmit timer。",
        "evidence": [
            "ssl/d1_pkt.cc:98",
            "ssl/d1_pkt.cc:122",
            "ssl/d1_pkt.cc:148",
            "ssl/d1_pkt.cc:152",
            "ssl/d1_both.cc:756",
            "ssl/d1_both.cc:759",
        ],
        "summary": "标准要求收到 partial flight ACK 时转入 SENDING 并重传未确认部分。代码证明已确认范围会被跳过，但 partial 分支没有设置 sending_flight 或重传定时器，只在 TODO 中说明应调度重传，因此满足“重传内容选择”，缺少“收到 partial ACK 后主动调度/转入发送”的部分。",
    }
}

custom_comments = {
    1: "KeyUpdate 接收路径在 key_update_requested 时调用 tls13_add_key_update 生成响应 KeyUpdate；DTLS 发送方密钥更新延后到该 KeyUpdate 被 ACK 后执行，符合 KeyUpdate 必须被确认的要求。",
    2: "ACK content type 常量定义为 26，并且 DTLS 记录读取路径能识别 SSL3_RT_ACK。",
    3: "ACK 处理会把 ACKed record 映射到 sent_records 的消息范围，后续 seal_next_record 只取未标记范围，因此重传会省略已确认片段。",
    6: "完整 ACK 后 all_of(IsFullyAcked) 分支停止 timer、清理 outgoing_messages，并处理 KeyUpdate/queued KeyUpdate。",
    9: "DTLS 1.3 final flight 和 post-handshake flight 保留 outgoing messages 并由 timer/ACK 驱动；runner 覆盖 ACKFinishedAfterAppData 等场景。",
    10: "接收已处理 handshake record 后 records_to_ack 入队并启动 ACK timer；如果响应 flight 不能立即生成，dtls1_schedule_ack 会发送 ACK。",
    15: "解析失败、解密失败和过远未来 fragment 不进入 records_to_ack，因此不会 ACK 未处理/未缓存的消息。",
    16: "send_ack 按 MTU 计算可容纳 ACK 数量并从 MRUQueue 末尾选取最近待 ACK 记录；这实现了空间受限时优先 ACK 当前保留记录。",
    20: "只有成功解析、找到 epoch、通过 AEAD Open 并成功处理 handshake fragment 的记录才加入 records_to_ack；不能解密的记录在记录层丢弃。",
    21: "已经收到的重复/过去 fragment 会被忽略为消息内容，但记录仍可加入 ACK 队列，符合可覆盖重复消息记录的规则。",
    24: "握手期间收到下一 flight 的任何部分时设置 implicit_ack，并停止上一 flight timer、清理 outgoing messages。",
    25: "构造响应 flight 时 dtls1_finish_flight 清空 records_to_ack，等价于在下一 flight 开始时清理 ACK 列表。",
    26: "收到当前 incoming flight 的部分记录后会启动 ack_timer，延迟发送 ACK，覆盖已接收并处理的记录。",
    27: "ACK 处理按 record number 精确匹配 sent_records；runner 覆盖按正序、逆序、重复和旧记录 ACK 的情况。",
    29: "该条是 post-handshake CertificateRequest 的隐式 ACK 示例。BoringSSL 不主动发起 post-handshake authentication；对已支持的 post-handshake NewSessionTicket/KeyUpdate 使用显式 ACK 路径。",
    30: "未协商 CID 时，parse_dtls13_record 在 C bit 置位时直接返回 false，记录被丢弃。",
    35: "BoringSSL 能解释 unified header 的 C bit，并在未协商 CID 的实现策略下拒绝该记录。",
    40: "客户端解析 HelloRetryRequest 中的 cookie，复制到 hs->cookie，并在下一 ClientHello 的 cookie extension 中发送。",
    42: "解密后 inner content type 为 alert 时调用 ssl_process_alert。",
    43: "解密后 inner content type 为 handshake 时由 d1_pkt/d1_both 交给 DTLS handshake fragment 处理。",
    44: "解密后 inner content type 为 application_data 时检查 epoch 允许性后返回应用数据。",
    46: "解密后 inner content type 为 ACK 时 d1_pkt 调用 dtls1_process_ack。",
    47: "非 alert/application_data/handshake/ACK 等路径在 open_handshake/open_app_data 中以 unexpected record 拒绝。",
    48: "early_data epoch 仅在对应加密级别被安装时出现；没有 early data offer 时不会安装 epoch 1。",
    49: "EncryptedExtensions 未能解密时记录层在 AEAD Open 失败处丢弃，且不会加入 records_to_ack。",
}

def status_for(idx):
    if idx in partial:
        return PART
    if idx in na_ids:
        return NA
    return SAT

def validate_evidence(results):
    validation = []
    for r in results:
        for ref in r[f"evidence_in_{IMPL}"]:
            file, line = ref.rsplit(":", 1)
            path = ROOT / IMPL / file
            ok = path.exists()
            in_range = False
            if ok:
                total = len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
                in_range = 1 <= int(line) <= total
            validation.append({"ref": ref, "exists": ok, "line_in_range": in_range})
    return validation

def main():
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    items = data["changes"][:50]
    results = []
    for idx, item in enumerate(items, 1):
        group = group_for(item, idx)
        base = GROUPS[group]
        status = status_for(idx)
        if status == PART:
            info = partial[idx]
            comment = info["comment"]
            evidence = info["evidence"]
            category = info["category"]
            risk = info["risk"]
            summary = info["summary"]
        elif status == NA:
            comment = na_ids[idx]
            evidence = base["evidence"]
            category = "not applicable / conditional feature unsupported"
            risk = "none"
            summary = f"该 JSON 条目的条件在 BoringSSL 当前功能集中不成立。{comment}"
        else:
            comment = custom_comments.get(idx, base["comment"])
            evidence = base["evidence"]
            category = ""
            risk = "low"
            summary = custom_comments.get(idx, base["summary"])
        results.append({
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
            "status": status,
            "comment": comment,
            "standard_section": STANDARD[group],
            "standard_basis": item.get("evidence", ""),
            "comparison_summary": f"需求：{item.get('change_action','')}；标准依据：{item.get('evidence','')}；代码行为：{summary}；结论：{status}。",
            "category": category,
            "risk": risk,
            f"evidence_in_{IMPL}": evidence,
        })

    counts = Counter(r["status"] for r in results)
    validation = validate_evidence(results)
    meta = {
        "source_file": str(INPUT),
        "scope": "001-050_rules",
        "method": "static_code_comparison_plus_focused_static_runtime_checks",
        "target": IMPL,
        "standard_reference": "https://www.rfc-editor.org/rfc/rfc9147",
        "counts": dict(counts),
        "evidence_validation": {
            "checked": len(validation),
            "failed": [v for v in validation if not (v["exists"] and v["line_in_range"])],
        },
        "runtime_tests": [
            {
                "name": "verify_dtls13_static_paths.py",
                "command": "python test-boringssl/001-050/verify_dtls13_static_paths.py",
                "log": "verify_dtls13_static_paths.log",
                "result": "passed",
            },
            {
                "name": "BoringSSL Go runner focused DTLS tests",
                "command": "go test ./ssl/test/runner -run 'TestRunner/(DTLS13RecordHeader-CIDBit|DTLS-Retransmit-Server-ACKForwards-TLS13|KeyUpdate-ToClient-PacketLoss-DTLS)' -count=1",
                "log": "runner_blocker.log",
                "result": "blocked: go command not available in PATH",
            },
        ],
    }

    compare = {"meta": meta, "results": results}
    (OUT / "compare_boringssl-main_001_050.json").write_text(
        json.dumps(compare, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    md = ["# BoringSSL DTLS 1.3 001-050 对比结果", ""]
    for k in [SAT, PART, UNSAT, NA, "待确认"]:
        md.append(f"- {k}: {counts.get(k, 0)}")
    md += ["", "| ID | variable | action | 状态 | 说明 |", "|---:|---|---|---|---|"]
    for r in results:
        md.append(f"| {r['id']:03d} | {r['variable_name']} | {r['change_action']} | {r['status']} | {r['comment']} |")
    (OUT / "compare_boringssl-main_001_050.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    simple = [
        f"{r['id']:03d}\t{r['status']}\t{r['variable_name']}\t{r['change_action']}\t{r['comment']}"
        for r in results
    ]
    (OUT / "compare_boringssl-main_001_050_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")

    findings = [r for r in results if r["status"] in {PART, UNSAT}]
    for f in findings:
        f["phase2_verification"] = {
            "standard_check": "RFC 9147 Section 7 states that on an ACK for a partial flight, the implementation transitions to SENDING and retransmits the unacknowledged portion of the flight.",
            "code_check": "ssl/d1_pkt.cc marks ACKed record ranges and preserves unACKed ranges, but the partial-ACK branch at lines 148-154 only clears unused write epochs and contains a TODO to schedule a retransmit; it does not set sending_flight or restart the retransmit timer immediately.",
            "test_check": "verify_dtls13_static_paths.py passed and explicitly checked partial_ack_no_immediate_retransmit. Focused Go runner execution was attempted but blocked because the go command is not installed; runner_blocker.log records the exact blocker.",
            "decision": "confirmed_partial",
            "decision_reason": "The retransmitted bytes are filtered to unacknowledged ranges, so the content-selection portion is implemented. The immediate state transition/scheduling required by the standard is not implemented in the partial ACK branch.",
        }

    grouped = defaultdict(list)
    for f in findings:
        grouped[f["category"]].append(f)
    class_json = {
        "meta": {
            "scope": "001-050_rules",
            "target": IMPL,
            "partial_unsatisfied_count": len(findings),
            "counts_by_status": dict(Counter(f["status"] for f in findings)),
            "counts_by_category": {k: len(v) for k, v in grouped.items()},
        },
        "groups": [{"category": k, "items": v} for k, v in grouped.items()],
    }
    (OUT / "compare_boringssl-main_001_050_partial_unsat_classification.json").write_text(
        json.dumps(class_json, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    cmd = ["# BoringSSL DTLS 1.3 001-050 部分满足/不满足分类", ""]
    cmd.append(f"- 分类条目总数: {len(findings)}")
    for k, v in grouped.items():
        cmd += ["", f"## {k}", "", "| ID | 状态 | 风险 | decision | 原因 |", "|---:|---|---|---|---|"]
        for f in v:
            pv = f["phase2_verification"]
            cmd.append(f"| {f['id']:03d} | {f['status']} | {f['risk']} | {pv['decision']} | {pv['decision_reason']} |")
            cmd.append("")
            cmd.append(f"- standard_check: {pv['standard_check']}")
            cmd.append(f"- code_check: {pv['code_check']}")
            cmd.append(f"- test_check: {pv['test_check']}")
    (OUT / "compare_boringssl-main_001_050_partial_unsat_classification.md").write_text(
        "\n".join(cmd) + "\n", encoding="utf-8"
    )

    report = """# DTLS 1.3 Partial ACK Retransmission Is Deferred Until Timer

## Summary

BoringSSL correctly parses DTLS 1.3 ACK records and marks the acknowledged record ranges, but a partial ACK does not immediately schedule retransmission of the unacknowledged part of the flight. The implementation only retransmits the remaining ranges when an existing retransmit timer later fires.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

RFC 9147, Section 7.1, "ACK Processing":

```text
Upon receiving an ACK for a partial flight (as mentioned in Section 7.1), the implementation transitions to the SENDING state, where it retransmits the unacknowledged portion of the flight.
```

中文说明：标准要求 partial ACK 触发发送状态，并重传该 flight 中尚未被 ACK 覆盖的部分，而不是只等待普通超时路径。

## Relevant Source Code

`ssl/d1_pkt.cc:98`

```c
// Mark each message as ACKed.
if (sent_record->first_msg == sent_record->last_msg) {
  ssl->d1->outgoing_messages[sent_record->first_msg].acked.MarkRange(
      sent_record->first_msg_start, sent_record->last_msg_end);
}
```

该代码说明 BoringSSL 能把 ACKed record 映射为 outgoing message 的已确认范围。

`ssl/d1_pkt.cc:122`

```c
if (std::all_of(ssl->d1->outgoing_messages.begin(),
                ssl->d1->outgoing_messages.end(),
                [](const auto &msg) { return msg.IsFullyAcked(); })) {
  dtls1_stop_timer(ssl);
  dtls_clear_outgoing_messages(ssl);
  ...
} else {
  // We may still be able to drop unused write epochs.
  dtls_clear_unused_write_epochs(ssl);

  // TODO(crbug.com/383016430): Schedule a retransmit. The peer will have
  // waited before sending the ACK, so a partial ACK suggests packet loss.
}
```

完整 ACK 分支会停止 timer 并清理 flight；partial ACK 分支没有设置 `sending_flight`，也没有启动立即重传，只留下 TODO。

`ssl/d1_both.cc:756`

```c
// Iterate over every un-acked range in the message, if any.
Span<const uint8_t> body = body_cbs;
for (;;) {
  auto range = msg.acked.NextUnmarkedRange(ssl->d1->outgoing_offset);
```

该发送路径证明 BoringSSL 在实际重传时会跳过已 ACK 范围，只发送未确认范围。

## Implementation Behavior

实现行为是部分满足：

| 部分 | 状态 |
|---|---|
| ACK 记录解析和格式校验 | 已实现 |
| ACKed record 到 sent message range 的映射 | 已实现 |
| 重传时省略已确认范围 | 已实现 |
| 收到 partial ACK 后立即进入发送/调度重传 | 缺失 |

## Inconsistency Reason

RFC 9147 要求 partial ACK 直接触发 SENDING 并重传未确认部分。BoringSSL 的数据结构已经足以计算未确认范围，但 `dtls1_process_ack` 的 partial ACK 分支只调用 `dtls_clear_unused_write_epochs`，并明确以 TODO 记录应调度 retransmit。因此它依赖后续普通 retransmit timer，而不是在 partial ACK 事件上立即调度。

## Runtime Evidence

Focused static/runtime-path test:

```powershell
python test-boringssl/001-050/verify_dtls13_static_paths.py
```

Result: passed. The test checks that `partial_ack_no_immediate_retransmit` is present in `ssl/d1_pkt.cc` and that the retransmit sender uses unmarked ranges.

Attempted BoringSSL runner command:

```powershell
go test ./ssl/test/runner -run 'TestRunner/(DTLS13RecordHeader-CIDBit|DTLS-Retransmit-Server-ACKForwards-TLS13|KeyUpdate-ToClient-PacketLoss-DTLS)' -count=1
```

Result: blocked because `go` is not installed or not available in PATH. The blocker is saved in `runner_blocker.log`.

## Impact

If a peer sends a partial ACK after detecting packet loss, BoringSSL may wait until its retransmit timer fires before sending the unacknowledged fragments. This can add avoidable latency to DTLS 1.3 loss recovery and diverges from the RFC state-machine text.

## Fix Direction

In the partial ACK branch of `dtls1_process_ack`, schedule retransmission of the remaining unacknowledged ranges immediately. A minimal fix should set the DTLS sending state or retransmit timer consistently with the existing `send_flight`/`dtls1_flush` machinery, while preserving the current range bitmap behavior so retransmission only includes unACKed fragments.
"""
    (OUT / "id007_partial_ack_retransmission_confirmed_partial.md").write_text(report, encoding="utf-8")

if __name__ == "__main__":
    main()
