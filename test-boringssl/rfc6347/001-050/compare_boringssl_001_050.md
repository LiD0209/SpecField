# BoringSSL DTLS 1.2 001-050 对比结果

- 满足: 39
- 部分满足: 3
- 不满足: 7
- 不适用: 1

| ID | variable | action | 状态 | 说明 |
|---:|---|---|---|---|
| 001 | body | selected from enumerated cases based on HandshakeType | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 002 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 003 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 004 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 005 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 006 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 007 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 008 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 009 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 010 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 011 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 012 | body | selected from offered list | 满足 | BoringSSL defines the DTLS/TLS handshake type constants and constructs/parses the message body through type-specific handshake state functions; unknown or unexpected message types are rejected by the state machine. |
| 013 | cipher_suites | must equal original ClientHello value | 满足 | 客户端收到 HelloVerifyRequest 后只把 cookie 写入 hs->dtls_cookie 并重发 ClientHello；cipher_suites 与 compression_methods 仍由同一配置和固定 null compression 生成。 |
| 014 | cipher_suites | validated range check | 满足 | SSL_parse_client_hello requires a u16-length-prefixed cipher_suites vector with length at least 2 and an even number of bytes. |
| 015 | client_hello | must be absent | 满足 | BoringSSL resets the handshake transcript after processing HelloVerifyRequest, so the initial ClientHello and HelloVerifyRequest are excluded from later Finished/CertificateVerify transcript hashes. |
| 016 | compression_methods | must equal original ClientHello value | 满足 | 客户端收到 HelloVerifyRequest 后只把 cookie 写入 hs->dtls_cookie 并重发 ClientHello；cipher_suites 与 compression_methods 仍由同一配置和固定 null compression 生成。 |
| 017 | compression_methods | validated range check | 满足 | 解析端要求 compression_methods 为 u8-length-prefixed 且至少 1 字节；发送端固定发送一个 null compression method。 |
| 018 | cookie | set/added to retransmitted ClientHello | 满足 | 客户端 ClientHello 的 DTLS cookie 是 u8-length-prefixed；初次握手 hs->dtls_cookie 为空，收到 HelloVerifyRequest 后复制 cookie 并重发。 |
| 019 | cookie | set to constant | 满足 | 客户端 ClientHello 的 DTLS cookie 是 u8-length-prefixed；初次握手 hs->dtls_cookie 为空，收到 HelloVerifyRequest 后复制 cookie 并重发。 |
| 020 | cookie | validated range check | 满足 | 客户端 ClientHello 的 DTLS cookie 是 u8-length-prefixed；初次握手 hs->dtls_cookie 为空，收到 HelloVerifyRequest 后复制 cookie 并重发。 |
| 021 | cookie | invalid if value check fails | 不满足 | libssl 产品代码中未发现 DTLS 1.2 服务端生成 HelloVerifyRequest、计算/验证 stateless cookie、无效 cookie 当作无 cookie 重新挑战、或 secret 轮换接受窗口的实现路径；这些逻辑只在 runner 测试服务端中出现。 |
| 022 | cookie | must be present | 不满足 | libssl 产品代码中未发现 DTLS 1.2 服务端生成 HelloVerifyRequest、计算/验证 stateless cookie、无效 cookie 当作无 cookie 重新挑战、或 secret 轮换接受窗口的实现路径；这些逻辑只在 runner 测试服务端中出现。 |
| 023 | cookie | validated range check | 部分满足 | libssl 客户端解析 HelloVerifyRequest 使用 u8-length-prefixed，可接受 255 字节；但 BoringSSL runner 的 helloVerifyRequestMsg.unmarshal 仍拒绝 cookieLen > 32，与 DTLS 1.2 的 255 字节上限不一致。 |
| 024 | cookie | membership check | 不满足 | libssl 产品代码中未发现 DTLS 1.2 服务端生成 HelloVerifyRequest、计算/验证 stateless cookie、无效 cookie 当作无 cookie 重新挑战、或 secret 轮换接受窗口的实现路径；这些逻辑只在 runner 测试服务端中出现。 |
| 025 | cookie | must be present as part of cookie exchange support | 满足 | 客户端 ClientHello 的 DTLS cookie 是 u8-length-prefixed；初次握手 hs->dtls_cookie 为空，收到 HelloVerifyRequest 后复制 cookie 并重发。 |
| 026 | cookie | invalid if value check fails | 不满足 | libssl 产品代码中未发现 DTLS 1.2 服务端生成 HelloVerifyRequest、计算/验证 stateless cookie、无效 cookie 当作无 cookie 重新挑战、或 secret 轮换接受窗口的实现路径；这些逻辑只在 runner 测试服务端中出现。 |
| 027 | cookie | validated range check | 满足 | 客户端 ClientHello 的 DTLS cookie 是 u8-length-prefixed；初次握手 hs->dtls_cookie 为空，收到 HelloVerifyRequest 后复制 cookie 并重发。 |
| 028 | cookie | validated range check | 满足 | 客户端 ClientHello 的 DTLS cookie 是 u8-length-prefixed；初次握手 hs->dtls_cookie 为空，收到 HelloVerifyRequest 后复制 cookie 并重发。 |
| 029 | cookie | derived/computed from another field | 不满足 | libssl 产品代码中未发现 DTLS 1.2 服务端生成 HelloVerifyRequest、计算/验证 stateless cookie、无效 cookie 当作无 cookie 重新挑战、或 secret 轮换接受窗口的实现路径；这些逻辑只在 runner 测试服务端中出现。 |
| 030 | cookie | validity check | 不满足 | libssl 产品代码中未发现 DTLS 1.2 服务端生成 HelloVerifyRequest、计算/验证 stateless cookie、无效 cookie 当作无 cookie 重新挑战、或 secret 轮换接受窗口的实现路径；这些逻辑只在 runner 测试服务端中出现。 |
| 031 | cookie | invalid if value check fails | 不满足 | libssl 产品代码中未发现 DTLS 1.2 服务端生成 HelloVerifyRequest、计算/验证 stateless cookie、无效 cookie 当作无 cookie 重新挑战、或 secret 轮换接受窗口的实现路径；这些逻辑只在 runner 测试服务端中出现。 |
| 032 | epoch | increment | 满足 | DTLS 初始读写 epoch 使用 null cipher；cipher state 更新时 next_epoch 递增或映射 DTLS 1.3 固定 epoch；记录 MAC/AEAD 序列使用 epoch 与 sequence 的组合值。 |
| 033 | epoch | must not wrap | 满足 | next_epoch refuses to advance beyond 0xffff and dtls_seal_record checks record sequence overflow before sending. |
| 034 | epoch | set to constant | 满足 | DTLS 初始读写 epoch 使用 null cipher；cipher state 更新时 next_epoch 递增或映射 DTLS 1.3 固定 epoch；记录 MAC/AEAD 序列使用 epoch 与 sequence 的组合值。 |
| 035 | epoch | increment | 满足 | DTLS 初始读写 epoch 使用 null cipher；cipher state 更新时 next_epoch 递增或映射 DTLS 1.3 固定 epoch；记录 MAC/AEAD 序列使用 epoch 与 sequence 的组合值。 |
| 036 | epoch | invalid if value check fails | 满足 | DTLS 1.2 只查找当前 read_epoch；未知或未来 epoch 的记录被丢弃。应用数据只允许 epoch >= 1，握手完成前的新 epoch 数据无法匹配当前 read_epoch 时会被丢弃。 |
| 037 | epoch | must equal / must not equal | 满足 | 该条是 MAY 语义；BoringSSL 丢弃未知 epoch 记录并依赖 DTLS 丢包/重传处理，符合允许的处理范围。 |
| 038 | epoch | must equal | 不适用 | 该条涉及 UDP 5-tuple/association 调度策略；BoringSSL record layer 可解析 epoch 0，但是否把同一地址上的 epoch 0 ClientHello 视为新关联由应用的 BIO/连接管理决定。 |
| 039 | epoch | derived/computed with sequence_number by concatenation | 满足 | DTLS 初始读写 epoch 使用 null cipher；cipher state 更新时 next_epoch 递增或映射 DTLS 1.3 固定 epoch；记录 MAC/AEAD 序列使用 epoch 与 sequence 的组合值。 |
| 040 | epoch | must accept old epoch packets until handshake completes | 部分满足 | BoringSSL 为 DTLS 1.3 保留 prev_read_epoch，但 DTLS 1.2 set_read_state 直接替换 read_epoch；代码注释说明 DTLS 1.2 会忽略旧 epoch 记录。 |
| 041 | epoch | must not equal previously used epoch value | 部分满足 | BoringSSL 为 DTLS 1.3 保留 prev_read_epoch，但 DTLS 1.2 set_read_state 直接替换 read_epoch；代码注释说明 DTLS 1.2 会忽略旧 epoch 记录。 |
| 042 | fragment | must be fragmented | 满足 | 发送端根据当前 MTU 和 dtls_seal_max_input_len 将握手消息切分为 DTLS fragments；测试 runner 包含 ChangeMTU/retransmit 场景。 |
| 043 | fragment | must be fragmented | 满足 | 发送端根据当前 MTU 和 dtls_seal_max_input_len 将握手消息切分为 DTLS fragments；测试 runner 包含 ChangeMTU/retransmit 场景。 |
| 044 | fragment_length | must be present | 满足 | 发送端把完整 DTLS handshake header 写入消息数组后更新 transcript；接收端重组后保留 offset=0 和完整 fragment_length 的 header。 |
| 045 | fragment_offset | must be present | 满足 | 发送端把完整 DTLS handshake header 写入消息数组后更新 transcript；接收端重组后保留 offset=0 和完整 fragment_length 的 header。 |
| 046 | hello_verify_request | set to constant | 满足 | BoringSSL defines DTLS1_MT_HELLO_VERIFY_REQUEST as 3 and uses it in client state handling. |
| 047 | hello_verify_request | must be absent | 满足 | 处理 HelloVerifyRequest 后重置 transcript，因此该消息不进入后续 Finished/CertificateVerify MAC。 |
| 048 | length | validated range check | 满足 | 输入记录长度受 SSL3_RT_MAX_ENCRYPTED_LENGTH 限制；输出密文长度计算失败会返回 RECORD_TOO_LARGE。 |
| 049 | level | set to constant | 满足 | BoringSSL 多数 DTLS 无效记录选择静默丢弃；当选择发送 alert 时，调用 ssl_send_alert 的路径使用 SSL3_AL_FATAL。 |
| 050 | level | set to constant | 满足 | BoringSSL 多数 DTLS 无效记录选择静默丢弃；当选择发送 alert 时，调用 ssl_send_alert 的路径使用 SSL3_AL_FATAL。 |
