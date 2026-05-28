# wolfSSL DTLS 1.3 001-050 对比结果

- 满足: 42
- 部分满足: 2
- 不满足: 3
- 不适用: 3
- 待确认: 0

说明：用户指定的 `wolfssl-main` 路径不存在，本轮实际审计 `wolfssl-master`。

| ID | variable | action | 状态 | 说明 |
|---:|---|---|---|---|
| 001 | ACK | must be present / must be sent as acknowledgement | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 002 | ACK | set to constant | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 003 | ACK | must be used to judge acknowledged messages or message fragments; acknowledged ones SHOULD be omitted from transmission | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 004 | ACK | set to acknowledge record 2 | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 005 | ACK | set to empty | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 006 | ACK | validated value check: ACK must indicate a complete flight; cancels all retransmissions and either remains in WAITING, or, if the ACK was for the final flight, transitions to FINISHED | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 007 | ACK | validated value check: ACK must indicate a partial flight; retransmit the unacknowledged portion of the flight | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 008 | ACK | must be treated as acknowledging records that appear in it | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 009 | ACK | set to retransmit of its ACK | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 010 | ACK | must be sent | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 011 | ACK | must only cover the current outstanding flight | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 012 | ACK | must be ACKed | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 013 | ACK | should not be sent unless the responding flight cannot be generated immediately | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 014 | ACK | should be sent once | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 015 | ACK | must not be sent | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 016 | ACK | should favor including records which have not yet been acknowledged | 部分满足 | ACK 列表有容量上限并能避免溢出，但满列表时直接丢弃新记录，没有记录“已经被 ACK 过”的状态，也没有优先保留未确认记录。 |
| 017 | ACK | must equal | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 018 | ACK | should ACK as many received packets as can fit into the ACK record | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 019 | ACK | may cover more than one flight | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 020 | ACK | must not be sent for that record | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 021 | ACK | may still be covered | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 022 | ACK | must not be present | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 023 | ACK | must not cover both because they are in different flights | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 024 | ACK | previous flight(s) are implicitly acknowledged | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 025 | ACK | clear covered ACK list | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 026 | ACK | should generate an ACK covering the messages from that flight which it has received and processed so far | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 027 | ACK | may acknowledge the records corresponding to each transmission of each flight or simply acknowledge the most recent one | 满足 | wolfSSL 的 DTLS 1.3 ACK 发送、解析、重传队列和记录号编码路径覆盖该要求。 |
| 028 | body | selected from offered list | 部分满足 | 常规 TLS 1.3/DTLS 1.3 握手消息被分派处理，但 RFC 9147 DTLSHandshake 中的 request_connection_id 和 new_connection_id 分支不存在。 |
| 029 | certificate_request | implicitly acknowledged by receipt of the next flight | 满足 | post-handshake CertificateRequest 处理后即将发送的认证 flight 会隐式确认该记录，代码会移除当前 ACK。 |
| 030 | cids | invalid if value check fails | 满足 | wolfSSL 支持协商后的静态 Connection ID，并在 DTLS 1.3 unified header 中添加、解析和校验 C bit/CID；未协商 CID 时会拒绝带 CID 的记录。 |
| 031 | cids | must be used immediately | 不满足 | 未实现 NewConnectionId/usage=cid_immediate，因此没有收到新 CID 后立即用于未来所有记录的路径。 |
| 032 | cids | may discard extra CIDs | 不满足 | 未实现 spare CID 列表，因此不存在维护或丢弃多余 spare CID 的接收路径。 |
| 033 | cids | selected in provided order | 不满足 | 未实现 receiver-provided CID 队列，因此没有按提供顺序选择新 CID 的路径。 |
| 034 | cids | must be present | 满足 | wolfSSL 支持协商后的静态 Connection ID，并在 DTLS 1.3 unified header 中添加、解析和校验 C bit/CID；未协商 CID 时会拒绝带 CID 的记录。 |
| 035 | cids | must be present | 满足 | wolfSSL 支持协商后的静态 Connection ID，并在 DTLS 1.3 unified header 中添加、解析和校验 C bit/CID；未协商 CID 时会拒绝带 CID 的记录。 |
| 036 | cids | invalid if value check fails | 满足 | wolfSSL 支持协商后的静态 Connection ID，并在 DTLS 1.3 unified header 中添加、解析和校验 C bit/CID；未协商 CID 时会拒绝带 CID 的记录。 |
| 037 | cipher_suites | must be present / must be absent | 不适用 | 该条约束是对未来非 AES/ChaCha20 DTLS cipher suite 规范的注册要求，不是当前 wolfSSL 运行时必须实现的具体套件行为。 |
| 038 | cipher_suites | must be selected from allowed set | 满足 | wolfSSL 对 DTLS 1.3 当前支持的 AEAD 套件使用 AES/ChaCha 记录号保护，并实现发送/失败 AEAD 限制检查。 |
| 039 | CipherSuite | must define limits on use | 满足 | wolfSSL 对 DTLS 1.3 当前支持的 AEAD 套件使用 AES/ChaCha 记录号保护，并实现发送/失败 AEAD 限制检查。 |
| 040 | client_hello | must send a new message with cookie added as an extension | 满足 | wolfSSL 解析 HRR cookie，重启握手哈希并在后续 ClientHello 中写入 cookie/key_share 等扩展。 |
| 041 | Content Type | validated range check | 不适用 | 该条是 IANA 保留范围分配规则，不是 wolfSSL 对端输入处理的直接义务；运行时未知 ContentType 会被拒绝。 |
| 042 | Decrypted Content Type | must equal mapped constant for Alert demultiplexing after decryption | 满足 | TLS 1.3 解密后根据内层 content type 分派到 alert、handshake、application_data 或 ack；未知类型返回 UNKNOWN_RECORD_TYPE。 |
| 043 | Decrypted Content Type | must equal mapped constant for DTLSHandshake demultiplexing after decryption | 满足 | TLS 1.3 解密后根据内层 content type 分派到 alert、handshake、application_data 或 ack；未知类型返回 UNKNOWN_RECORD_TYPE。 |
| 044 | Decrypted Content Type | must equal mapped constant for Application Data demultiplexing after decryption | 满足 | TLS 1.3 解密后根据内层 content type 分派到 alert、handshake、application_data 或 ack；未知类型返回 UNKNOWN_RECORD_TYPE。 |
| 045 | Decrypted Content Type | must equal mapped constant for Heartbeat demultiplexing after decryption | 不适用 | wolfSSL 当前没有 Heartbeat content type 处理路径；该条 demux 映射只在启用/支持 Heartbeat 时适用。未知类型会被拒绝。 |
| 046 | Decrypted Content Type | must equal mapped constant for ACK demultiplexing after decryption | 满足 | TLS 1.3 解密后根据内层 content type 分派到 alert、handshake、application_data 或 ack；未知类型返回 UNKNOWN_RECORD_TYPE。 |
| 047 | Decrypted Content Type | invalid if value check fails; error | 满足 | TLS 1.3 解密后根据内层 content type 分派到 alert、handshake、application_data 或 ack；未知类型返回 UNKNOWN_RECORD_TYPE。 |
| 048 | early_data | must be absent / skipped | 满足 | wolfSSL 将 DTLS 1.3 epoch 1 定义为 early data，并只在 earlyData 激活时切换到 early-data epoch；否则使用当前握手/应用 epoch。 |
| 049 | encrypted_extensions | cannot safely be acknowledged because it cannot be decrypted | 满足 | ServerHello 前遇到 unified/encrypted record 时，客户端只设置发送空 ACK 以提示重传，不会对无法解密的 EncryptedExtensions 做具体 ACK。 |
| 050 | encrypted_record | derived/computed from another field | 满足 | BuildTls13Message 将真实 content type 附加在明文末尾，调用 EncryptTls13 加密，并为 DTLS 1.3 添加/加密 unified ciphertext header。 |
