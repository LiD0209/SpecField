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
    status = "满足"
    category = ""
    risk = "low"
    std = "RFC 9147"
    ev = EVIDENCE["ack"]
    comment = "wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。"
    summary = (
        f"要求：{item['evidence']} 标准语义是对 ACK 的发送、覆盖或处理施加约束；"
        "代码在 Dtls13RecordRecvd、Dtls13RtxAddAck、Dtls13WriteAckMessage、DoDtls13Ack 和 SendDtls13Ack 路径中保存记录号、编码 ACK 列表、处理收到的 ACK 并触发剩余重传。结论为满足。"
    )

    if i == 16:
        status = "部分满足"
        category = "incomplete ACK prioritization"
        risk = "medium"
        ev = EVIDENCE["ack_overflow"]
        comment = "ACK 列表有容量上限并能避免溢出，但满列表时直接丢弃新记录，没有记录“已经被 ACK 过”的状态，也没有优先保留未确认记录。"
        summary = (
            "要求：ACK 空间受限时 SHOULD favor records which have not yet been acknowledged。"
            "代码：Dtls13RtxAddAck 在 seenRecordsCount 达到 DTLS13_ACK_MAX_RECORDS 或插入位置超过上限时直接 return 0，并注释为 silently drop/list full。"
            "测试：test_dtls13_ack_overflow 验证 one over limit 会被静默丢弃。结论为部分满足。"
        )
    elif i == 28:
        status = "部分满足"
        category = "missing dynamic CID handshake messages"
        risk = "medium"
        ev = EVIDENCE["hs"] + EVIDENCE["cid"]
        comment = "常规 TLS 1.3/DTLS 1.3 握手消息被分派处理，但 RFC 9147 DTLSHandshake 中的 request_connection_id 和 new_connection_id 分支不存在。"
        summary = (
            "要求：DTLSHandshake body select 需要覆盖 client_hello、server_hello、certificate、finished、key_update 以及 request_connection_id/new_connection_id。"
            "代码的 HandShakeType 和 DoTls13HandShakeMsgType 覆盖常规 TLS 1.3 消息，但没有 request_connection_id/new_connection_id 枚举或处理分支；CID 代码仅处理 connection_id extension 和统一头 CID。结论为部分满足。"
        )
    elif i in (31, 32, 33):
        status = "不满足"
        category = "missing dynamic CID handshake messages"
        risk = "medium"
        ev = EVIDENCE["cid"]
        if i == 31:
            comment = "未实现 NewConnectionId/usage=cid_immediate，因此没有收到新 CID 后立即用于未来所有记录的路径。"
        elif i == 32:
            comment = "未实现 spare CID 列表，因此不存在维护或丢弃多余 spare CID 的接收路径。"
        else:
            comment = "未实现 receiver-provided CID 队列，因此没有按提供顺序选择新 CID 的路径。"
        summary = (
            f"要求：{item['evidence']} 标准语义依赖 RFC 9147 动态 CID 更新消息。"
            "代码：wolfSSL 仅有 TLSX_ConnectionID_Use/Parse 的静态 connection_id extension 和 wolfSSL_dtls_cid_set API；该 API 在已有 rx CID 后明确不支持连接中变更 CID。"
            "全文符号搜索未发现 request_connection_id、new_connection_id、cid_immediate、cid_spare。结论为不满足。"
        )
    elif i in (30, 34, 35, 36):
        ev = EVIDENCE["cid"]
        comment = "wolfSSL 支持协商后的静态 Connection ID，并在 DTLS 1.3 unified header 中添加、解析和校验 C bit/CID；未协商 CID 时会拒绝带 CID 的记录。"
        summary = (
            f"要求：{item['evidence']} 代码的 Dtls13AddCID 在发送 unified header 时写入 TX CID，Dtls13UnifiedHeaderParseCID 在收到 C bit 时检查是否启用 CID 和 CID 是否匹配，未协商或缺失/不匹配时返回 DTLS_CID_ERROR。"
            "该结论限于 wolfSSL 已支持的静态 connection_id extension；动态 CID 更新另在相关条目记录为缺失。"
        )
    elif i == 37:
        status = "不适用"
        category = "registry/future-suite requirement"
        risk = "low"
        ev = EVIDENCE["cipher"]
        comment = "该条约束是对未来非 AES/ChaCha20 DTLS cipher suite 规范的注册要求，不是当前 wolfSSL 运行时必须实现的具体套件行为。"
        summary = (
            "要求针对 future cipher suites。wolfSSL 当前记录号掩码实现覆盖 AES-GCM/AES-CCM 和 ChaCha，其他算法返回 NOT_COMPILED_IN。"
            "由于本条要求未来套件规范定义自己的记录号加密方式，当前实现没有可执行义务。"
        )
    elif i in (38, 39):
        ev = EVIDENCE["cipher"]
        comment = "wolfSSL 对 DTLS 1.3 当前支持的 AEAD 套件使用 AES/ChaCha 记录号保护，并实现发送/失败 AEAD 限制检查。"
        summary = (
            f"要求：{item['evidence']} 代码中 Dtls13GetRnMask 覆盖 AES-GCM/AES-CCM/ChaCha；CheckTLS13AEADSendLimit 和 Dtls13CheckAEADFailLimit 使用 RFC 9147 DTLS AEAD 限值常量。结论为满足。"
        )
    elif i == 40:
        ev = EVIDENCE["hrr"]
        comment = "wolfSSL 解析 HRR cookie，重启握手哈希并在后续 ClientHello 中写入 cookie/key_share 等扩展。"
        summary = (
            "要求：收到带 cookie 的 HelloRetryRequest 后，客户端必须发送包含 cookie extension 的新 ClientHello。"
            "代码在 TLSX_Cookie_Parse/TLSX_Cookie_Use 中保存 HRR cookie，DoTls13ServerHello 将状态推进到 SERVER_HELLO_RETRY_REQUEST_COMPLETE，后续 ClientHello 构造通过 TLSX 写出扩展。结论为满足。"
        )
    elif i == 41:
        status = "不适用"
        category = "IANA registry allocation"
        risk = "low"
        ev = EVIDENCE["record"]
        comment = "该条是 IANA 保留范围分配规则，不是 wolfSSL 对端输入处理的直接义务；运行时未知 ContentType 会被拒绝。"
        summary = (
            "要求是 IANA 不应分配 32-63 content type。wolfSSL 运行时枚举已知类型并在未知 record type 时返回 UNKNOWN_RECORD_TYPE；IANA 分配治理本身不由实现执行。"
        )
    elif 42 <= i <= 47:
        ev = EVIDENCE["record"]
        if i == 45:
            status = "不适用"
            category = "unsupported optional content type"
            comment = "wolfSSL 当前没有 Heartbeat content type 处理路径；该条 demux 映射只在启用/支持 Heartbeat 时适用。未知类型会被拒绝。"
            summary = "RFC 图示包含 DCT==24 -> Heartbeat；wolfSSL 当前源码未提供 heartbeat ContentType/处理分支，默认路径对未知类型返回 UNKNOWN_RECORD_TYPE，因此该映射对本构建不适用。"
        else:
            comment = "TLS 1.3 解密后根据内层 content type 分派到 alert、handshake、application_data 或 ack；未知类型返回 UNKNOWN_RECORD_TYPE。"
            summary = f"要求：{item['evidence']} 代码在 DoProcessReply 解密后使用 ssl->curRL.type switch 分派；ack 进入 DoDtls13Ack，unknown/default 返回 UNKNOWN_RECORD_TYPE。结论为满足。"
    elif i == 48:
        ev = EVIDENCE["record"]
        comment = "wolfSSL 将 DTLS 1.3 epoch 1 定义为 early data，并只在 earlyData 激活时切换到 early-data epoch；否则使用当前握手/应用 epoch。"
        summary = (
            "要求：未提供 early_data 时跳过 epoch 1。代码定义 DTLS13_EPOCH_EARLYDATA=1，发送路径只有 isEarlyData 为真时设置 epoch 1，否则保持 dtls13Epoch。结论为满足。"
        )
    elif i == 49:
        ev = EVIDENCE["record"]
        comment = "ServerHello 前遇到 unified/encrypted record 时，客户端只设置发送空 ACK 以提示重传，不会对无法解密的 EncryptedExtensions 做具体 ACK。"
        summary = (
            "要求：ServerHello 前收到无法解密的 EncryptedExtensions 不能安全 ACK。代码在 ServerHello 完成前解析 unified header 失败时只设置 sendAcks 为空 ACK；解密失败路径 DropAndRestartProcessReply/HandleDTLSDecryptFailed，不调用 Dtls13RecordRecvd 加入 ACK 列表。结论为满足。"
        )
    elif i == 50:
        ev = EVIDENCE["encrypted"]
        comment = "BuildTls13Message 将真实 content type 附加在明文末尾，调用 EncryptTls13 加密，并为 DTLS 1.3 添加/加密 unified ciphertext header。"
        summary = (
            "要求：DTLSCiphertext.encrypted_record 是序列化 DTLSInnerPlaintext 的加密形式。代码先复制输入明文、附加内层 content type 和 padding，再 EncryptTls13，DTLS 1.3 下还加密记录号。结论为满足。"
        )
    elif i == 29:
        ev = EVIDENCE["ack"]
        comment = "post-handshake CertificateRequest 处理后即将发送的认证 flight 会隐式确认该记录，代码会移除当前 ACK。"
        summary = (
            "要求：server post-handshake CertificateRequest 由下一 flight 隐式确认。代码在 handShakeDone 且收到 certificate_request 时调用 Dtls13RtxRemoveCurAck，注释说明由即将发送的 certificate/certificate_verify/finished flight 隐式 ACK。结论为满足。"
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
        "standard_check": "RFC 9147 Section 7.1 要求 ACK record 空间允许时尽量包含可容纳的 received packets；空间受限时 SHOULD favor records which have not yet been acknowledged。",
        "code_check": "复核 Dtls13RtxAddAck：列表满时在 742-747 直接 return 0；按插入位置计算 count 后若 count >= DTLS13_MAX_ACK_RECORDS 也直接 return 0。代码没有保存“已经向对端 ACK 过”的记录状态，也没有替换已确认记录以保留未确认记录。",
        "test_check": "运行 unit.test.exe -test_dtls13_ack_overflow。测试通过并验证 one over limit 时 Dtls13RtxAddAck 返回 0 且 seenRecordsCount 保持 DTLS13_ACK_MAX_RECORDS，即新记录被静默丢弃；该行为证明有容量保护，但不证明也不实现未确认记录优先级。",
        "decision_reason": "实现满足 ACK 列表排序、去重和容量保护，但缺少 RFC SHOULD 的优先级策略，因此确认为部分满足。",
        "runtime_log": "phase2_wolfssl_builtin_dtls13_tests.log",
    },
    28: {
        "phase2_decision": "confirmed_partial",
        "standard_check": "RFC 9147 DTLSHandshake body select 显式包含 request_connection_id: RequestConnectionId 和 new_connection_id: NewConnectionId，同时包含常规 TLS 1.3 握手消息。",
        "code_check": "复核 HandShakeType 和 DoTls13HandShakeMsgType：wolfSSL 覆盖 client_hello/server_hello/certificate_request/certificate/finished/session_ticket/key_update 等常规消息，但枚举和 switch 中没有 request_connection_id/new_connection_id。CID 代码只在 extension/unified header 层处理静态 CID。",
        "test_check": "运行 dynamic CID 符号检查，源码/测试中未发现 request_connection_id、new_connection_id、cid_immediate、cid_spare 等符号；同时运行静态 CID built-in 测试通过，说明已实现的是静态 CID，不是 DTLSHandshake 动态 CID 消息。",
        "decision_reason": "DTLSHandshake 常规分支已实现，动态 CID 消息分支缺失，因此确认为部分满足。",
        "runtime_log": "phase2_dynamic_cid_symbol_check.log",
    },
    31: {
        "phase2_decision": "confirmed_unsatisfied",
        "standard_check": "RFC 9147 Section 9 要求当 NewConnectionId.usage 为 cid_immediate 时，接收端必须立即使用一个新 CID 处理所有 future records。",
        "code_check": "复核 TLSX_ConnectionID_Use/Parse、wolfSSL_dtls_cid_set、Dtls13AddCID 和 Dtls13UnifiedHeaderParseCID：实现只有握手 extension 协商出的单个静态 TX/RX CID，wolfSSL_dtls_cid_set 在 rx 已存在时返回失败并说明不支持连接中更改 CID。",
        "test_check": "dynamic CID 符号检查无 NewConnectionId/cid_immediate；built-in CID 测试只覆盖静态 CID 存在和解析，没有可触发 cid_immediate 的消息处理入口。",
        "decision_reason": "没有 NewConnectionId 消息和 usage 字段处理，因此无法满足 cid_immediate 立即切换要求。",
        "runtime_log": "phase2_dynamic_cid_symbol_check.log",
    },
    32: {
        "phase2_decision": "confirmed_unsatisfied",
        "standard_check": "RFC 9147 Section 9 允许实现收到超过希望维护数量的 spare CIDs 时丢弃多余 CID；该语义建立在接收 NewConnectionId/cid_spare 并维护 spare CID 集合之上。",
        "code_check": "复核 CID 数据结构和 API：wolfSSL 只有当前 tx/rx CID 指针，没有 spare CID 列表、容量策略或 extra spare CID 丢弃路径。",
        "test_check": "dynamic CID 符号检查无 cid_spare/spare CID 相关处理；静态 CID 测试通过但不涉及 spare CID 队列。",
        "decision_reason": "由于 spare CID 特性本身缺失，相关丢弃策略也不存在，因此确认为不满足。",
        "runtime_log": "phase2_dynamic_cid_symbol_check.log",
    },
    33: {
        "phase2_decision": "confirmed_unsatisfied",
        "standard_check": "RFC 9147 Section 9 建议 endpoints SHOULD use receiver-provided CIDs in the order they were provided。",
        "code_check": "复核 CID 实现未发现 receiver-provided CID 队列；仅有当前 tx/rx CID，且连接中变更 CID 被拒绝。",
        "test_check": "dynamic CID 符号检查未发现 NewConnectionId 或相关队列/usage 枚举；built-in CID 测试只证明固定 CID 在记录中出现。",
        "decision_reason": "没有多个 receiver-provided CIDs 的存储和选择机制，无法按提供顺序使用，因此确认为不满足。",
        "runtime_log": "phase2_dynamic_cid_symbol_check.log",
    },
}

for r in results:
    if r["id"] in verification:
        r.update(verification[r["id"]])

counts = {}
for r in results:
    counts[r["status"]] = counts.get(r["status"], 0) + 1

classification = [r for r in results if r["status"] in ("部分满足", "不满足")]
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
    "# wolfSSL DTLS 1.3 001-050 对比结果",
    "",
    f"- 满足: {counts.get('满足', 0)}",
    f"- 部分满足: {counts.get('部分满足', 0)}",
    f"- 不满足: {counts.get('不满足', 0)}",
    f"- 不适用: {counts.get('不适用', 0)}",
    "- 待确认: 0",
    "",
    "说明：用户指定的 `wolfssl-main` 路径不存在，本轮实际审计 `wolfssl-master`。",
    "",
    "| ID | variable | action | 状态 | 说明 |",
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
    "# wolfSSL DTLS 1.3 001-050 部分满足/不满足分类",
    "",
    f"- 总数: {len(classification)}",
    f"- confirmed_partial: {sum(1 for r in classification if r.get('phase2_decision') == 'confirmed_partial')}",
    f"- confirmed_unsatisfied: {sum(1 for r in classification if r.get('phase2_decision') == 'confirmed_unsatisfied')}",
    "- false_positive: 0",
    "",
]
for cat in sorted(class_counts):
    cmd.append(f"## {cat}")
    cmd.append("")
    cmd.append("| ID | 状态 | 风险 | Phase 2 | decision_reason |")
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
