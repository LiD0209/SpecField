# wolfSSL DTLS 1.2 001-050 对比结果

- 满足: 43
- 部分满足: 6
- 不满足: 0
- 不适用: 1

| ID | variable | action | 状态 | 说明 |
|---:|---|---|---|---|
| 001 | body | selected from enumerated cases based on HandshakeType | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 002 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 003 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 004 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 005 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 006 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 007 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 008 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 009 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 010 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 011 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 012 | body | selected from offered list | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 013 | cipher_suites | must equal original ClientHello value | 满足 | 客户端收到 HelloVerifyRequest 后仅保存 cookie 并重发 ClientHello；version/random/session_id/cipher_suites/compression_methods 仍由同一连接状态和 suites 配置生成，random 被复用。 |
| 014 | cipher_suites | validated range check | 满足 | ClientHello 解析使用 16-bit vector 读取 cipher_suites，并通过边界检查保证不会越过消息长度；DTLS 1.3 stateless 辅助路径额外检查偶数字节和最大 suite 缓冲。 |
| 015 | client_hello | must be absent | 满足 | 发送 HelloVerifyRequest 前重置握手哈希；客户端处理 HelloVerifyRequest 后重发 ClientHello，后续 CertificateVerify/Finished transcript 不包含初始 ClientHello 和 HelloVerifyRequest。 |
| 016 | compression_methods | must equal original ClientHello value | 满足 | 客户端收到 HelloVerifyRequest 后仅保存 cookie 并重发 ClientHello；version/random/session_id/cipher_suites/compression_methods 仍由同一连接状态和 suites 配置生成，random 被复用。 |
| 017 | compression_methods | validated range check | 满足 | ClientHello 解析读取 u8 compression_methods vector 并校验边界；发送端固定写入长度 1 和 NO_COMPRESSION 或启用压缩时的配置值。 |
| 018 | cookie | set/added to retransmitted ClientHello | 满足 | ClientHello cookie 使用 u8 长度前缀；初始 cookieSz 为 0，DoHelloVerifyRequest 解析 HelloVerifyRequest 后保存 cookie，后续 SendClientHello 将 cookie 写入重发 ClientHello。 |
| 019 | cookie | set to constant | 满足 | ClientHello cookie 使用 u8 长度前缀；初始 cookieSz 为 0，DoHelloVerifyRequest 解析 HelloVerifyRequest 后保存 cookie，后续 SendClientHello 将 cookie 写入重发 ClientHello。 |
| 020 | cookie | validated range check | 满足 | ClientHello cookie 使用 u8 长度前缀；初始 cookieSz 为 0，DoHelloVerifyRequest 解析 HelloVerifyRequest 后保存 cookie，后续 SendClientHello 将 cookie 写入重发 ClientHello。 |
| 021 | cookie | invalid if value check fails | 满足 | 服务端 stateless ClientHello 路径在收到非空 cookie 后调用 CheckDtlsCookie；长度必须等于内部 HMAC cookie 长度，ConstantCompare 失败时不进入 dtlsStateful，而是重新发送 HelloVerifyRequest。 |
| 022 | cookie | must be present | 满足 | 服务端在无 cookie 的 ClientHello 上生成 HMAC cookie 并发送 HelloVerifyRequest；生成输入包括 peer 地址和 ClientHello 参数。SendHelloVerifyRequest 拒绝空 cookie。 |
| 023 | cookie | validated range check | 部分满足 | 语法层的 opaque cookie<0..2^8-1> 可由 u8 长度表达，但 wolfSSL 服务端接受的 DTLS 1.2 cookie 必须等于 DTLS_COOKIE_SZ，客户端保存 HelloVerifyRequest cookie 时还受 MAX_COOKIE_LEN=32 约束。 |
| 024 | cookie | membership check | 部分满足 | wolfSSL 提供 wolfSSL_DTLS_SetCookieSecret 设置或随机生成当前 secret；CreateDtls12Cookie 和 CheckDtlsCookie 只使用 ssl->buffers.dtlsCookieSecret 当前值，没有 previous secret 列表或有限过渡窗口。 |
| 025 | cookie | must be present as part of cookie exchange support | 满足 | 服务端在无 cookie 的 ClientHello 上生成 HMAC cookie 并发送 HelloVerifyRequest；生成输入包括 peer 地址和 ClientHello 参数。SendHelloVerifyRequest 拒绝空 cookie。 |
| 026 | cookie | invalid if value check fails | 满足 | 服务端 stateless ClientHello 路径在收到非空 cookie 后调用 CheckDtlsCookie；长度必须等于内部 HMAC cookie 长度，ConstantCompare 失败时不进入 dtlsStateful，而是重新发送 HelloVerifyRequest。 |
| 027 | cookie | validated range check | 满足 | ClientHello cookie 使用 u8 长度前缀；初始 cookieSz 为 0，DoHelloVerifyRequest 解析 HelloVerifyRequest 后保存 cookie，后续 SendClientHello 将 cookie 写入重发 ClientHello。 |
| 028 | cookie | validated range check | 满足 | ClientHello cookie 使用 u8 长度前缀；初始 cookieSz 为 0，DoHelloVerifyRequest 解析 HelloVerifyRequest 后保存 cookie，后续 SendClientHello 将 cookie 写入重发 ClientHello。 |
| 029 | cookie | derived/computed from another field | 满足 | 服务端在无 cookie 的 ClientHello 上生成 HMAC cookie 并发送 HelloVerifyRequest；生成输入包括 peer 地址和 ClientHello 参数。SendHelloVerifyRequest 拒绝空 cookie。 |
| 030 | cookie | validity check | 满足 | 服务端 stateless ClientHello 路径在收到非空 cookie 后调用 CheckDtlsCookie；长度必须等于内部 HMAC cookie 长度，ConstantCompare 失败时不进入 dtlsStateful，而是重新发送 HelloVerifyRequest。 |
| 031 | cookie | invalid if value check fails | 部分满足 | wolfSSL 提供 wolfSSL_DTLS_SetCookieSecret 设置或随机生成当前 secret；CreateDtls12Cookie 和 CheckDtlsCookie 只使用 ssl->buffers.dtlsCookieSecret 当前值，没有 previous secret 列表或有限过渡窗口。 |
| 032 | epoch | increment | 满足 | DTLS 初始 epoch 为 0；发送 ChangeCipherSpec/切换写密钥后 dtls_epoch 自增并重置当前 epoch sequence；WriteSEQ 将 epoch 与 48-bit sequence 写入记录头/MAC 序列值。 |
| 033 | epoch | must not wrap | 满足 | wolfSSL 使用 16-bit dtls_epoch 字段并在记录头中按 2 字节编码；序列号也有高低字递增逻辑。未发现允许 epoch 编码越界的路径。 |
| 034 | epoch | set to constant | 满足 | DTLS 初始 epoch 为 0；发送 ChangeCipherSpec/切换写密钥后 dtls_epoch 自增并重置当前 epoch sequence；WriteSEQ 将 epoch 与 48-bit sequence 写入记录头/MAC 序列值。 |
| 035 | epoch | increment | 满足 | DTLS 初始 epoch 为 0；发送 ChangeCipherSpec/切换写密钥后 dtls_epoch 自增并重置当前 epoch sequence；WriteSEQ 将 epoch 与 48-bit sequence 写入记录头/MAC 序列值。 |
| 036 | epoch | invalid if value check fails | 满足 | GetRecordHeader 对 DTLS 1.2 检查 replay window、application_data 不允许 epoch 0；Finished 必须来自非零 epoch 且在 ChangeCipherSpec 后。未知/未来 epoch 记录无法匹配当前解密状态而被丢弃或报序列错误。 |
| 037 | epoch | must equal / must not equal | 满足 | GetRecordHeader 对 DTLS 1.2 检查 replay window、application_data 不允许 epoch 0；Finished 必须来自非零 epoch 且在 ChangeCipherSpec 后。未知/未来 epoch 记录无法匹配当前解密状态而被丢弃或报序列错误。 |
| 038 | epoch | must equal | 不适用 | 该条涉及同一 host/port quartet 上收到 epoch 0 ClientHello 时是否建立新 association。wolfSSL record layer 可解析 epoch 0 并重置 DTLS 状态，但 UDP socket/peer 关联由应用和 BIO 回调管理。 |
| 039 | epoch | derived/computed with sequence_number by concatenation | 满足 | DTLS 初始 epoch 为 0；发送 ChangeCipherSpec/切换写密钥后 dtls_epoch 自增并重置当前 epoch sequence；WriteSEQ 将 epoch 与 48-bit sequence 写入记录头/MAC 序列值。 |
| 040 | epoch | must accept old epoch packets until handshake completes | 满足 | wolfSSL 保存当前和上一 epoch 的发送 flight；DtlsMsgPoolSend 对 pool->epoch==0 且当前 epoch 非 0 时按 PREV_ORDER 重写 sequence，VerifyForTxDtlsMsgDelete 只删除早于 current-1 的消息。 |
| 041 | epoch | must not equal previously used epoch value | 部分满足 | wolfSSL 在单个 WOLFSSL 对象内递增 dtls_epoch 并重置 sequence，但没有发现跨 association 的 2*MSL epoch reuse 计时器或持久 epoch 禁用窗口。 |
| 042 | fragment | must be fragmented | 部分满足 | SendHandshakeMsg 根据 wolfssl_local_GetMaxPlaintextSize 和当前 MTU 分片；wolfSSL_dtls_set_mtu 可设置 MTU。但 repeated retransmissions no response 且 PMTU unknown 时自动降低片长/探测黑洞的状态机未在 DTLS 1.2 timeout 路径中出现。 |
| 043 | fragment | must be fragmented | 部分满足 | SendHandshakeMsg 根据 wolfssl_local_GetMaxPlaintextSize 和当前 MTU 分片；wolfSSL_dtls_set_mtu 可设置 MTU。但 repeated retransmissions no response 且 PMTU unknown 时自动降低片长/探测黑洞的状态机未在 DTLS 1.2 timeout 路径中出现。 |
| 044 | fragment_length | must be present | 满足 | AddHandShakeHeader 为每个 DTLS fragment 写入 message_seq、fragment_offset、fragment_length；接收端 GetDtlsHandShakeHeader 读取这些字段，重组完成后构造 offset=0、fragment_length=total length 的完整 header 供 transcript hash 使用。 |
| 045 | fragment_offset | must be present | 满足 | AddHandShakeHeader 为每个 DTLS fragment 写入 message_seq、fragment_offset、fragment_length；接收端 GetDtlsHandShakeHeader 读取这些字段，重组完成后构造 offset=0、fragment_length=total length 的完整 header 供 transcript hash 使用。 |
| 046 | hello_verify_request | set to constant | 满足 | wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。 |
| 047 | hello_verify_request | must be absent | 满足 | 发送 HelloVerifyRequest 前重置握手哈希；客户端处理 HelloVerifyRequest 后重发 ClientHello，后续 CertificateVerify/Finished transcript 不包含初始 ClientHello 和 HelloVerifyRequest。 |
| 048 | length | validated range check | 满足 | GetDtlsRecordHeader 读取 DTLSPlaintext.length，GetRecordHeader 对最大记录大小和非应用数据零长度做检查。 |
| 049 | level | set to constant | 满足 | wolfSSL 对无效 DTLS 记录多数情况下静默丢弃；如果选择发送 fatal alert，则 SendAlert 使用 alert_fatal，bad MAC 路径发送 bad_record_mac 或按 DTLS 静默丢弃。 |
| 050 | level | set to constant | 满足 | wolfSSL 对无效 DTLS 记录多数情况下静默丢弃；如果选择发送 fatal alert，则 SendAlert 使用 alert_fatal，bad MAC 路径发送 bad_record_mac 或按 DTLS 静默丢弃。 |
