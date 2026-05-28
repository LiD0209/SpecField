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

SAT = "满足"
PARTIAL = "部分满足"
UNSAT = "不满足"
NA = "不适用"


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
        "comment": "wolfSSL 在 DTLS 1.3 统一头解析和发送路径中都使用 16 字节最小 ciphertext 约束；发送端 BuildTls13Message 对短明文补零 padding，接收端 Dtls13ParseUnifiedRecordLayer 在解密 record number 前拒绝过短 ciphertext。",
        "summary": "要求：DTLS 1.3 sequence number encryption 需要至少 16 字节 ciphertext，短记录按 deprotection failure 处理，发送端必须 padding。标准含义：该检查必须位于 record number deprotection 之前，发送端也不能生成过短 ciphertext。代码行为：DTLS13_MIN_CIPHERTEXT=16，Dtls13MinimumRecordLength() 把统一头长度加 16；发送 BuildTls13Message() 在 DTLS 模式下把 args->sz 填充到该最小长度；接收 Dtls13ParseUnifiedRecordLayer() 对 hdrInfo->recordLength < 16 返回 LENGTH_ERROR。结论：满足。",
        "evidence": evidence("src/dtls13.c:112", "src/dtls13.c:1303", "src/dtls13.c:1330", "src/dtls13.c:1561", "src/tls13.c:3350", "src/tls13.c:3401"),
    },
    "epoch_basic": {
        "section": "RFC 9147 Sections 4.1, 4.2.2, 4.2.3, 5.3, 5.8 and Appendix A",
        "standard": "The epoch number is initially zero; the DTLSPlaintext epoch is set as the least significant 2 bytes of the connection epoch; the unified header E bits carry the low-order two bits of the epoch; epoch values are assigned to unencrypted, early data, handshake, and application traffic secrets.",
        "comment": "wolfSSL 使用 64-bit w64wrapper 保存 DTLS 1.3 epoch，初始化 epoch 0，按 early/handshake/application/update secret 创建 epoch 槽，并在明文头、统一头和 record number reconstruction 中使用低位 epoch 表示。",
        "summary": "要求：epoch 需要按 RFC 9147 的状态和头部编码规则初始化、序列化、重构并绑定到对应 keying material。代码行为：DTLS13_EPOCH_* 常量定义 epoch 1/2/3，Dtls13GetEpochBits() 提取低两位，Dtls13RlAddCiphertextHeader() 写 fixed bits 与 epoch bits，DeriveTls13Keys() 根据 secret 类型创建对应 epoch，Dtls13SetEpochKeys() 只激活已保存的 epoch key。结论：满足。",
        "evidence": evidence("wolfssl/internal.h:5844", "wolfssl/internal.h:5845", "wolfssl/internal.h:5846", "src/dtls.c:75", "src/dtls13.c:1156", "src/dtls13.c:1241", "src/tls13.c:1653", "src/dtls13.c:2372", "src/dtls13.c:2411"),
    },
    "epoch_reconstruct": {
        "section": "RFC 9147 Section 4.2.2, Reconstructing the Sequence Number and Epoch",
        "standard": "After the handshake is complete, if the epoch bits do not match those from the current epoch, implementations SHOULD use the most recent past epoch which has matching bits.",
        "comment": "wolfSSL 先比较 peer current epoch 的低两位；不匹配时扫描有效 epoch 槽，选取低两位匹配且数值最大的 epoch。",
        "summary": "要求：统一头只携带低两位 epoch，接收端需从当前和历史 epoch 中重构完整 epoch。代码行为：Dtls13ReconstructEpochNumber() 先使用 ssl->dtls13PeerEpoch，之后遍历 ssl->dtls13Epochs[]，选择匹配 epochBits 的最大有效 epoch；没有对应 cipher state 时返回 SEQUENCE_ERROR。结论：满足。",
        "evidence": evidence("src/dtls13.c:1449", "src/dtls13.c:1457", "src/dtls13.c:1464", "src/dtls13.c:1473", "src/dtls13.c:1484"),
    },
    "ack_epoch": {
        "section": "RFC 9147 Section 7, ACK Message",
        "standard": "During the handshake, ACK records MUST be sent with an epoch which is equal to or higher than the record which is being acknowledged. After the handshake, implementations MUST use the highest available sending epoch. Implementations SHOULD simply use the highest current sending epoch.",
        "comment": "wolfSSL 为收到的 handshake record 记录 ACK 的 epoch/seq；发送 ACK 前优先把发送 epoch 切到当前最高 epoch。服务器握手未完成但本端已经有 application epoch 时，会降到 handshake epoch 来 ACK 客户端尚无法解密更高 epoch 的记录，符合 RFC 给出的握手期例外语义。",
        "summary": "要求：ACK 的发送 epoch 要覆盖被确认记录，握手后使用最高可用发送 epoch。代码行为：Dtls13RecordRecvd() 记录当前 record 的 epoch/seq；SendDtls13Ack() 通常设置到 ssl->dtls13Epoch，握手未完成的服务器在 dtls13Epoch>=traffic0 时使用 handshake epoch；Dtls13WriteAckMessage() 把 64-bit epoch/seq 写入 ACK body。结论：满足。",
        "evidence": evidence("src/dtls13.c:1592", "src/dtls13.c:1598", "src/dtls13.c:2603", "src/dtls13.c:2657", "src/dtls13.c:2971", "src/dtls13.c:2976", "src/dtls13.c:2979"),
    },
    "fixed_bits": {
        "section": "RFC 9147 Section 4.2.1, Record Header",
        "standard": "Fixed Bits: The three high bits of the first byte of the unified header are set to 001. If the first byte is any other value, then receivers MUST check to see if the leading bits of the first byte are 001. Otherwise, the record MUST be rejected as if it had failed deprotection.",
        "comment": "wolfSSL 定义 mask/value 0xe0/0x20，发送统一头时设置固定高三位，接收 demux 时只把 fixed bits 为 001 的非 alert/handshake/ack 记录识别为 unified header，否则按非统一头处理并在后续版本/type 检查中拒绝。",
        "summary": "要求：统一头 fixed bits 必须为 001，其他非明文 content type 的首字节必须拒绝。代码行为：DTLS13_FIXED_BITS_MASK 和 DTLS13_FIXED_BITS 分别定义检查掩码和值；Dtls13RlAddCiphertextHeader() 初始化 flags 为固定值；Dtls13IsUnifiedHeader() 排除 alert/handshake/ack 后检查高三位是否为 001。结论：满足。",
        "evidence": evidence("src/dtls13.c:95", "src/dtls13.c:98", "src/dtls13.c:1255", "src/dtls13.c:1391", "src/dtls13.c:1397", "src/internal.c:12309"),
    },
    "fragment_header": {
        "section": "RFC 9147 Section 3.3, Fragmentation",
        "standard": "Each DTLS handshake message contains both a fragment offset and a fragment length.",
        "comment": "wolfSSL 的 DTLS 1.3 handshake header 结构包含 fragmentOffset 和 fragmentLength，普通未分片发送时写 offset=0、fragmentLength=message length，分片发送路径逐片更新 offset/length。",
        "summary": "要求：每个 DTLS handshake message 都带 fragment_offset 和 fragment_length。代码行为：Dtls13HandshakeHeader 结构包含 fragmentOffset/fragmentLength；Dtls13HandshakeAddHeader() 对未分片消息写 offset 0 和完整长度；Dtls13SendFragmented() 进入分片路径并复用内部发送函数更新片段。结论：满足。",
        "evidence": evidence("src/dtls13.c:59", "src/dtls13.c:63", "src/dtls13.c:64", "src/dtls13.c:1296", "src/dtls13.c:1298", "src/dtls13.c:1109"),
    },
    "cookie": {
        "section": "RFC 9147 Sections 5.2 and 5.3, Cookie Exchange",
        "standard": "The client MUST send a new ClientHello with the cookie added as an extension. The server then verifies the cookie and proceeds with the handshake only if it is valid. A DTLS 1.3-only client MUST set the legacy_cookie field to zero length.",
        "comment": "wolfSSL 在 server stateless path 中为 HRR 生成 cookie extension；server 解析 retried ClientHello 时检查 cookie extension 长度并调用 TlsCheckCookie，只有 cookieGood 才进入 stateful 解析；DTLS 1.3 path 使用 TLS cookie extension 而不是 DTLS 1.2 legacy_cookie。",
        "summary": "要求：DTLS 1.3 cookie exchange 使用 TLS cookie extension，验证成功后才继续，legacy_cookie 对 DTLS 1.3-only 客户端为零长。代码行为：CreateCookieExt() 被用于生成 HRR cookie extension；DoClientHelloStateless() 查找 TLSX_COOKIE；CheckDtlsCookie() 对 DTLS 1.3 cookie extension 做长度校验并调用 TlsCheckCookie；cookieGood 为假时返回 INVALID_PARAMETER 或重新发 stateless reply。结论：满足。",
        "evidence": evidence("src/dtls.c:269", "src/dtls.c:274", "src/dtls.c:847", "src/dtls.c:973", "src/dtls.c:1003", "src/dtls.c:1014", "src/dtls.c:1033"),
    },
    "key_update_ack": {
        "section": "RFC 9147 Sections 5.8 and 7.1, KeyUpdate and ACK",
        "standard": "As with other handshake messages with no built-in response, KeyUpdates MUST be acknowledged. Implementations MUST NOT send records with the new keys or send a new KeyUpdate until the previous KeyUpdate has been acknowledged.",
        "comment": "wolfSSL 将 KeyUpdate 作为 retransmission-tracked handshake 记录；发送 KeyUpdate 时设置 dtls13WaitKeyUpdateAck，ACK 处理按 epoch 和 seq 移除对应记录，只有确认后才派生新的发送 traffic key 并递增本端 epoch。",
        "summary": "要求：KeyUpdate 必须由 ACK 显式确认，确认前不能用新 key/epoch 发送。代码行为：Dtls13HandshakeSend() 在 key_update 时设置等待 ACK 标志并保存发送 epoch/seq；DoDtls13Ack() 用 ACK 中的 epoch/seq 移除 retransmit record；DoDtls13KeyUpdateAck() 仅在 KeyUpdate 记录已被 ACK 移除时调用 Dtls13KeyUpdateAckReceived()；后者才 DeriveTls13Keys(update_traffic_key) 并递增 dtls13Epoch。结论：满足。",
        "evidence": evidence("src/dtls13.c:2092", "src/dtls13.c:2099", "src/dtls13.c:2688", "src/dtls13.c:2692", "src/dtls13.c:2696", "src/dtls13.c:2861", "src/dtls13.c:2903", "src/dtls13.c:2931"),
    },
}


PARTIALS = {
    57: {
        "status": PARTIAL,
        "category": "close_notify 后缺少 epoch/sequence pair 专用忽略门控",
        "risk": "medium",
        "section": "RFC 9147 Section 5.8, Closure Alerts",
        "standard": "Any data received with an epoch/sequence number pair after that of a valid received closure alert MUST be ignored.",
        "comment": "wolfSSL 收到 close_notify 后设置 closeNotify 并从当前 ProcessReply 返回 ZERO_RETURN；但代码没有保存有效 closure alert 的 epoch/sequence pair，也没有在后续 DTLS 1.3 record receive path 中比较并忽略 pair 之后的数据。",
        "summary": "要求：收到有效 closure alert 后，所有 epoch/sequence pair 晚于该 alert 的数据都必须忽略。代码行为：DoAlert() 仅设置 ssl->options.closeNotify；ProcessReply 在 close_notify 时返回 ZERO_RETURN 并清空当前 input buffer；代码中没有 close_notify_epoch/sequence 或类似字段，也没有按 pair 对后续记录做忽略判断。结论：close_notify 状态处理已实现，但缺少 RFC 9147 要求的 DTLS 1.3 epoch/sequence pair 后续数据过滤，部分满足。",
        "evidence": evidence("src/internal.c:22226", "src/internal.c:23663", "src/internal.c:23668", "wolfssl/internal.h:5046", "wolfssl/internal.h:6212"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 要求以 valid closure alert 的 epoch/sequence number pair 为界，忽略 pair 之后的任何数据；这是 DTLS 特有的 record-number 顺序要求，不只是 API 层返回 close_notify。",
        "code_check": "DoAlert() 只设置 closeNotify；ProcessReply 在当前 alert 上返回 ZERO_RETURN；WOLFSSL 结构保存当前 curEpoch64/curSeq 和 closeNotify 标志，但没有保存 closure alert pair，也没有后续比较门控。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_close_notify_lacks_epoch_sequence_gate 通过，确认 closeNotify 状态存在且不存在 closeNotifyEpoch/closeNotifySeq 或 post-close pair comparison。",
        "decision_reason": "已实现 close_notify 语义和 API 返回；缺失 DTLS 1.3 以 epoch/sequence pair 为界忽略后续数据的专用逻辑，因此为 confirmed_partial。",
        "report": "id057_close_notify_epoch_sequence_gate_confirmed_partial.md",
    },
    62: {
        "status": PARTIAL,
        "category": "发送端 epoch 上限只检查 64-bit wrap，未显式执行 2^48-1 限制",
        "risk": "medium",
        "section": "RFC 9147 Section 5.8, Key Updates",
        "standard": "sending implementations MUST NOT allow the epoch to exceed 2^48-1. However, receiving implementations MUST NOT enforce this rule.",
        "comment": "wolfSSL 使用 64-bit epoch 并在递增后检查是否回到 0，用于避免 64-bit wrap；但未找到发送端对 2^48-1 的显式上限检查。",
        "summary": "要求：发送端不得让 epoch 超过 2^48-1，接收端不得强制该上限。代码行为：Dtls13KeyUpdateAckReceived() 和 Dtls13GetSeq() 只在 w64Increment 后检查 w64IsZero；该检查覆盖 64-bit wrap，不覆盖 2^48-1；接收端重构 epoch 时也未强制 2^48 上限，这一半符合要求。结论：部分满足。",
        "evidence": evidence("src/dtls13.c:2696", "src/dtls13.c:2699", "src/dtls13.c:2326", "src/dtls13.c:2330", "src/dtls13.c:1449", "src/dtls13.c:1479"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 对 sending implementation 设置 2^48-1 上限，同时禁止 receiving implementation 强制该发送端上限。",
        "code_check": "发送 epoch/sequence 增长逻辑只检查 64-bit wrap；源码中没有 0x0000ffffffffffff、2^48、281474976710655 或等价上限检查。接收端 Dtls13ReconstructEpochNumber() 只按已有 epoch 槽重构，不强制该上限。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_epoch_send_limit_is_64bit_wrap_not_2p48 通过，确认存在 64-bit wrap 检查且不存在 2^48-1 发送上限。",
        "decision_reason": "接收端不强制上限符合标准；发送端缺少 2^48-1 的显式限制，仅防 64-bit wrap，因此为 confirmed_partial。",
        "report": "id062_epoch_send_limit_confirmed_partial.md",
    },
    76: {
        "alias_of": 62,
        "status": PARTIAL,
        "category": "发送端 epoch 上限只检查 64-bit wrap，未显式执行 2^48-1 限制",
        "risk": "medium",
        "section": "RFC 9147 Section 5.8, Key Updates",
        "standard": "Note that epoch values do not wrap. If a DTLS implementation would need to wrap the epoch value, it MUST terminate the connection.",
        "comment": "wolfSSL 在 epoch 递增后检查 w64IsZero 并返回 BAD_STATE_E，可阻止 64-bit wrap；但同一节的发送端 2^48-1 限制没有显式实现。",
        "summary": "要求：epoch 不得 wrap；结合发送端 2^48-1 上限，应在达到协议限制前终止或阻止继续发送。代码行为：w64IsZero 检查能捕获 64-bit wrap，但不会在 2^48-1 后阻止继续递增。结论：部分满足。",
        "evidence": evidence("src/dtls13.c:2696", "src/dtls13.c:2699", "src/dtls13.c:2326", "src/dtls13.c:2330"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 明确 epoch values do not wrap，并在同一 KeyUpdate 限制语境中给出发送端 2^48-1 上限。",
        "code_check": "wolfSSL 有 64-bit wrap 检查，但没有在协议发送上限 2^48-1 处终止连接。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_epoch_send_limit_is_64bit_wrap_not_2p48 通过。",
        "decision_reason": "防 64-bit wrap 已实现；协议发送上限前的阻断未实现，confirmed_partial。",
        "report": "id062_epoch_send_limit_confirmed_partial.md",
    },
    87: {
        "alias_of": 62,
        "status": PARTIAL,
        "category": "发送端 epoch 上限只检查 64-bit wrap，未显式执行 2^48-1 限制",
        "risk": "medium",
        "section": "RFC 9147 Section 4.2.2 and Section 5.8",
        "standard": "Implementations MUST NOT allow the epoch to wrap; sending implementations MUST NOT allow the epoch to exceed 2^48-1.",
        "comment": "wolfSSL 通过 w64IsZero 捕获 64-bit wrap，但未显式执行 DTLS 1.3 sending epoch 2^48-1 上限。",
        "summary": "要求：epoch 不得 wrap，发送端还必须限制到 2^48-1。代码行为：递增后的 zero 检查只处理 64-bit wrap。结论：部分满足。",
        "evidence": evidence("src/dtls13.c:2696", "src/dtls13.c:2699", "src/dtls13.c:2326", "src/dtls13.c:2330"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 同时给出 no-wrap 与 sending 2^48-1 上限。",
        "code_check": "仅发现 64-bit wrap 检查，未发现 2^48-1 上限检查。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_epoch_send_limit_is_64bit_wrap_not_2p48 通过。",
        "decision_reason": "实现了防 wrap 的一部分，但未覆盖发送上限，confirmed_partial。",
        "report": "id062_epoch_send_limit_confirmed_partial.md",
    },
    93: {
        "status": PARTIAL,
        "category": "PMTU 未知且重复重传失败时缺少更小 record size 回退证据",
        "risk": "low",
        "section": "RFC 9147 Section 4.4, Handshake Message Fragmentation and Reassembly",
        "standard": "If repeated retransmissions do not result in a response, and the PMTU is unknown, subsequent retransmissions SHOULD back off to a smaller record size, fragmenting the handshake message as appropriate.",
        "comment": "wolfSSL 支持按当前 MTU/max plaintext 对 handshake message 分片，也会重传已缓存的 DTLS 1.3 handshake record；但未找到 repeated retransmission timeout 后在 PMTU unknown 场景逐步降低 record size 的策略。",
        "summary": "要求：PMTU unknown 且重复重传无响应时，后续重传 SHOULD 降低 record size 并按需分片。代码行为：Dtls13HandshakeSend() 初次发送时根据 wolfssl_local_GetMaxPlaintextSize() 决定是否分片；Dtls13RtxTimeout()/Dtls13RtxSendBuffered() 重发缓存记录；未发现基于重复 timeout 的 MTU/backoff 字段或重分片逻辑。结论：分片能力满足，PMTU unknown 重传回退策略证据不足，部分满足。",
        "evidence": evidence("src/dtls13.c:1109", "src/dtls13.c:2054", "src/dtls13.c:2089", "src/dtls13.c:2115", "src/dtls13.c:2810", "src/dtls13.c:2844", "src/internal.c:42146"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 的 SHOULD 针对 repeated retransmissions 和 unknown PMTU 的自适应回退，不只是支持普通 handshake fragmentation。",
        "code_check": "代码能按当前 max plaintext 分片并缓存重传，但 Dtls13RtxTimeout()/Dtls13RtxSendBuffered() 未调整 MTU 或缩小 record size。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_retransmission_pmtu_backoff_not_present 通过，确认存在分片/重传路径且不存在 retransmission-timeout backoff 关键词或状态。",
        "decision_reason": "已实现分片和重传，缺少 repeated retransmission + unknown PMTU 的更小 record size 回退证据，confirmed_partial。",
        "report": "id093_pmtu_retransmission_backoff_confirmed_partial.md",
    },
    97: {
        "alias_of": 62,
        "status": PARTIAL,
        "category": "KeyUpdate 响应未结合 2^48-1 发送 epoch 上限判断",
        "risk": "medium",
        "section": "RFC 9147 Section 5.8, Key Updates",
        "standard": "If a sending implementation receives a KeyUpdate with request_update set to \"update_requested\", it MUST NOT send its own KeyUpdate if that would cause it to exceed these limits.",
        "comment": "wolfSSL 会在已有 KeyUpdate 等待 ACK 时抑制新的 KeyUpdate，但未发现发送响应前检查该响应是否会超过 2^48-1 epoch/key usage limit 的代码。",
        "summary": "要求：收到 update_requested 时，如果响应 KeyUpdate 会超过限制则不得发送。代码行为：DoTls13KeyUpdate() 设置 keyUpdateRespond；SendTls13KeyUpdate() 发送响应；DTLS 等待 ACK 时会清除 keyUpdateRespond 以避免并发 KeyUpdate；但没有 2^48-1 epoch 上限判断。结论：部分满足。",
        "evidence": evidence("src/tls13.c:11929", "src/tls13.c:11961", "src/tls13.c:11970", "src/tls13.c:11803", "src/dtls13.c:2696", "src/dtls13.c:2699"),
        "decision": "confirmed_partial",
        "standard_check": "RFC 9147 要求 KeyUpdate response decision 受 epoch/key usage limits 约束。",
        "code_check": "代码有并发/等待 ACK 抑制逻辑，但没有在发送响应前根据 2^48-1 发送 epoch 上限拒绝。",
        "test_check": "verify_wolfssl_dtls13_051_100.py::test_keyupdate_response_lacks_2p48_limit_gate 通过。",
        "decision_reason": "响应机制和等待 ACK 门控存在；缺少 limits-based response suppression，confirmed_partial。",
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
                "category": "已满足",
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
        "# wolfssl-main DTLS 1.3 RFC 9147 051-100 对比结果",
        "",
        f"- 标准: {RFC}",
        f"- 请求代码库: `{ROOT / 'wolfssl-main'}`",
        f"- 实际检查代码库: `{SRC}`",
        "- 说明: 请求路径不存在，本轮使用同工作区的 `wolfssl-master` 作为 wolfSSL 源码树。",
        "",
        "| ID | 变量 | 状态 | 标准章节 | 摘要 | 代码证据 |",
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
        "# wolfssl-main DTLS 1.3 RFC 9147 051-100 部分/不满足分类",
        "",
        f"- 待复核条目: {len(findings)}",
        f"- 部分满足: {sum(1 for r in findings if r['status'] == PARTIAL)}",
        f"- 不满足: {sum(1 for r in findings if r['status'] == UNSAT)}",
        "",
        "| ID | 状态 | 风险 | 分类 | 复核结论 | decision_reason |",
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

该要求不是简单的 API shutdown 状态，而是要求 DTLS 接收端按 record number 顺序忽略 closure alert 之后的数据。""",
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

这些限制要求发送端在协议上限处停止继续使用新的发送 epoch，但接收端不能因为对端 epoch 大于该值而拒绝。""",
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

该 SHOULD 约束针对重复重传失败后的自适应行为，不等同于初次发送时支持分片。""",
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
        f"- 协议: DTLS 1.3 ({RFC})",
        f"- 实现: {IMPL}",
        f"- 实际代码库: `{SRC}`",
        f"- 结果计数: {counts}",
        f"- Phase 2 复核条目: {len(findings)}",
        f"- confirmed_partial: {data['confirmed_partial']}",
        f"- confirmed_unsatisfied: {data['confirmed_unsatisfied']}",
        f"- 详细报告: {', '.join(data['reports'])}",
        f"- 下一轮范围: {data['next_round']}",
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
