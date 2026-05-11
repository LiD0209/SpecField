# BoringSSL DTLS 1.3 001-050 对比结果

- 满足: 38
- 部分满足: 1
- 不满足: 0
- 不适用: 11
- 待确认: 0

| ID | variable | action | 状态 | 说明 |
|---:|---|---|---|---|
| 001 | ACK | must be present / must be sent as acknowledgement | 满足 | KeyUpdate 接收路径在 key_update_requested 时调用 tls13_add_key_update 生成响应 KeyUpdate；DTLS 发送方密钥更新延后到该 KeyUpdate 被 ACK 后执行，符合 KeyUpdate 必须被确认的要求。 |
| 002 | ACK | set to constant | 满足 | ACK content type 常量定义为 26，并且 DTLS 记录读取路径能识别 SSL3_RT_ACK。 |
| 003 | ACK | must be used to judge acknowledged messages or message fragments; acknowledged ones SHOULD be omitted from transmission | 满足 | ACK 处理会把 ACKed record 映射到 sent_records 的消息范围，后续 seal_next_record 只取未标记范围，因此重传会省略已确认片段。 |
| 004 | ACK | set to acknowledge record 2 | 不适用 | 该条来自 RFC 图示中的 Record 5 ACK [2]，是说明性示例，不是独立运行时 MUST/SHOULD。 |
| 005 | ACK | set to empty | 不适用 | 该条来自 RFC 图示中的 empty ACK 示例，说明特定丢包时序，不是独立通用要求。 |
| 006 | ACK | validated value check: ACK must indicate a complete flight; cancels all retransmissions and either remains in WAITING, or, if the ACK was for the final flight, transitions to FINISHED | 满足 | 完整 ACK 后 all_of(IsFullyAcked) 分支停止 timer、清理 outgoing_messages，并处理 KeyUpdate/queued KeyUpdate。 |
| 007 | ACK | validated value check: ACK must indicate a partial flight; retransmit the unacknowledged portion of the flight | 部分满足 | BoringSSL 接收 partial ACK 后会标记已确认的消息范围，并且后续重传只发送未确认范围；但 partial ACK 分支仅留下 TODO，没有立即调度重传或立刻进入发送未确认部分的路径，只能等现有 retransmit timer。 |
| 008 | ACK | must be treated as acknowledging records that appear in it | 满足 | BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking. |
| 009 | ACK | set to retransmit of its ACK | 满足 | DTLS 1.3 final flight 和 post-handshake flight 保留 outgoing messages 并由 timer/ACK 驱动；runner 覆盖 ACKFinishedAfterAppData 等场景。 |
| 010 | ACK | must be sent | 满足 | 接收已处理 handshake record 后 records_to_ack 入队并启动 ACK timer；如果响应 flight 不能立即生成，dtls1_schedule_ack 会发送 ACK。 |
| 011 | ACK | must only cover the current outstanding flight | 满足 | BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking. |
| 012 | ACK | must be ACKed | 满足 | BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking. |
| 013 | ACK | should not be sent unless the responding flight cannot be generated immediately | 满足 | BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking. |
| 014 | ACK | should be sent once | 满足 | BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking. |
| 015 | ACK | must not be sent | 满足 | 解析失败、解密失败和过远未来 fragment 不进入 records_to_ack，因此不会 ACK 未处理/未缓存的消息。 |
| 016 | ACK | should favor including records which have not yet been acknowledged | 满足 | send_ack 按 MTU 计算可容纳 ACK 数量并从 MRUQueue 末尾选取最近待 ACK 记录；这实现了空间受限时优先 ACK 当前保留记录。 |
| 017 | ACK | must equal | 满足 | BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking. |
| 018 | ACK | should ACK as many received packets as can fit into the ACK record | 满足 | BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking. |
| 019 | ACK | may cover more than one flight | 满足 | BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking. |
| 020 | ACK | must not be sent for that record | 满足 | 只有成功解析、找到 epoch、通过 AEAD Open 并成功处理 handshake fragment 的记录才加入 records_to_ack；不能解密的记录在记录层丢弃。 |
| 021 | ACK | may still be covered | 满足 | 已经收到的重复/过去 fragment 会被忽略为消息内容，但记录仍可加入 ACK 队列，符合可覆盖重复消息记录的规则。 |
| 022 | ACK | must not be present | 满足 | BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking. |
| 023 | ACK | must not cover both because they are in different flights | 满足 | BoringSSL implements DTLS 1.3 ACK parsing, ACK record construction, ACK-driven sent-record range marking, implicit ACK handling, delayed ACK scheduling, and final-flight/post-handshake retransmission tracking. |
| 024 | ACK | previous flight(s) are implicitly acknowledged | 满足 | 握手期间收到下一 flight 的任何部分时设置 implicit_ack，并停止上一 flight timer、清理 outgoing messages。 |
| 025 | ACK | clear covered ACK list | 满足 | 构造响应 flight 时 dtls1_finish_flight 清空 records_to_ack，等价于在下一 flight 开始时清理 ACK 列表。 |
| 026 | ACK | should generate an ACK covering the messages from that flight which it has received and processed so far | 满足 | 收到当前 incoming flight 的部分记录后会启动 ack_timer，延迟发送 ACK，覆盖已接收并处理的记录。 |
| 027 | ACK | may acknowledge the records corresponding to each transmission of each flight or simply acknowledge the most recent one | 满足 | ACK 处理按 record number 精确匹配 sent_records；runner 覆盖按正序、逆序、重复和旧记录 ACK 的情况。 |
| 028 | body | selected from offered list | 满足 | BoringSSL parses DTLS handshake fragments and dispatches complete handshake messages by message type. |
| 029 | certificate_request | implicitly acknowledged by receipt of the next flight | 满足 | 该条是 post-handshake CertificateRequest 的隐式 ACK 示例。BoringSSL 不主动发起 post-handshake authentication；对已支持的 post-handshake NewSessionTicket/KeyUpdate 使用显式 ACK 路径。 |
| 030 | cids | invalid if value check fails | 满足 | 未协商 CID 时，parse_dtls13_record 在 C bit 置位时直接返回 false，记录被丢弃。 |
| 031 | cids | must be used immediately | 不适用 | DTLS CID 是协商后的条件行为；BoringSSL 不协商 CID，因此 cid_immediate 使用规则不适用。 |
| 032 | cids | may discard extra CIDs | 不适用 | DTLS CID spare CID 维护仅在实现 NewConnectionId/CID 协商时适用；BoringSSL 未实现该可选功能。 |
| 033 | cids | selected in provided order | 不适用 | Receiver-provided CID 顺序使用仅在 CID 协商后适用；BoringSSL 不协商或保存 receiver-provided CIDs。 |
| 034 | cids | must be present | 不适用 | 条件为 Connection ID 已协商；BoringSSL 不协商 CID，并在写路径固定 C=0。 |
| 035 | cids | must be present | 满足 | BoringSSL 能解释 unified header 的 C bit，并在未协商 CID 的实现策略下拒绝该记录。 |
| 036 | cids | invalid if value check fails | 不适用 | 该条要求同一 datagram 多记录 CID 关联一致性；BoringSSL 不协商 CID，C bit 置位记录会被拒绝。 |
| 037 | cipher_suites | must be present / must be absent | 不适用 | 该条约束未来非 AES/ChaCha20 cipher suite 的规范定义，不是 BoringSSL 当前运行时行为。 |
| 038 | cipher_suites | must be selected from allowed set | 满足 | BoringSSL DTLS 1.3 uses the TLS 1.3 cipher suite set implemented by libssl, which is AES-GCM/AES-CCM/ChaCha20-Poly1305 based and has record-number encryption support. |
| 039 | CipherSuite | must define limits on use | 不适用 | 该条是 TLS Cipher Suites 注册表/规范编写要求，不是实现中的单条运行时检查。 |
| 040 | client_hello | must send a new message with cookie added as an extension | 满足 | 客户端解析 HelloRetryRequest 中的 cookie，复制到 hs->cookie，并在下一 ClientHello 的 cookie extension 中发送。 |
| 041 | Content Type | validated range check | 不适用 | 该条是 IANA reserved content-type allocation 规则，不是实现必须分配的运行时行为。 |
| 042 | Decrypted Content Type | must equal mapped constant for Alert demultiplexing after decryption | 满足 | 解密后 inner content type 为 alert 时调用 ssl_process_alert。 |
| 043 | Decrypted Content Type | must equal mapped constant for DTLSHandshake demultiplexing after decryption | 满足 | 解密后 inner content type 为 handshake 时由 d1_pkt/d1_both 交给 DTLS handshake fragment 处理。 |
| 044 | Decrypted Content Type | must equal mapped constant for Application Data demultiplexing after decryption | 满足 | 解密后 inner content type 为 application_data 时检查 epoch 允许性后返回应用数据。 |
| 045 | Decrypted Content Type | must equal mapped constant for Heartbeat demultiplexing after decryption | 不适用 | Heartbeat content type 取决于 Heartbeat 扩展支持；BoringSSL 当前未实现 DTLS Heartbeat 路径，因此该映射不适用。 |
| 046 | Decrypted Content Type | must equal mapped constant for ACK demultiplexing after decryption | 满足 | 解密后 inner content type 为 ACK 时 d1_pkt 调用 dtls1_process_ack。 |
| 047 | Decrypted Content Type | invalid if value check fails; error | 满足 | 非 alert/application_data/handshake/ACK 等路径在 open_handshake/open_app_data 中以 unexpected record 拒绝。 |
| 048 | early_data | must be absent / skipped | 满足 | early_data epoch 仅在对应加密级别被安装时出现；没有 early data offer 时不会安装 epoch 1。 |
| 049 | encrypted_extensions | cannot safely be acknowledged because it cannot be decrypted | 满足 | EncryptedExtensions 未能解密时记录层在 AEAD Open 失败处丢弃，且不会加入 records_to_ack。 |
| 050 | encrypted_record | derived/computed from another field | 满足 | BoringSSL implements DTLS 1.3 unified record header parsing, record-number reconstruction/encryption, AEAD deprotection, inner content-type tail scan, and invalid-type rejection. |
