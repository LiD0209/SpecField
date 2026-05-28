# wolfSSL DTLS 1.2 001-050 部分满足/不满足分类

## DTLS 1.2 cookie 长度实现固定为哈希长度

- 023 部分满足 cookie: 语法层的 opaque cookie<0..2^8-1> 可由 u8 长度表达，但 wolfSSL 服务端接受的 DTLS 1.2 cookie 必须等于 DTLS_COOKIE_SZ，客户端保存 HelloVerifyRequest cookie 时还受 MAX_COOKIE_LEN=32 约束。

## cookie secret 轮换只保留当前 secret

- 024 部分满足 cookie: wolfSSL 提供 wolfSSL_DTLS_SetCookieSecret 设置或随机生成当前 secret；CreateDtls12Cookie 和 CheckDtlsCookie 只使用 ssl->buffers.dtlsCookieSecret 当前值，没有 previous secret 列表或有限过渡窗口。
- 031 部分满足 cookie: wolfSSL 提供 wolfSSL_DTLS_SetCookieSecret 设置或随机生成当前 secret；CreateDtls12Cookie 和 CheckDtlsCookie 只使用 ssl->buffers.dtlsCookieSecret 当前值，没有 previous secret 列表或有限过渡窗口。

## epoch 不复用依赖会话生命周期而非 MSL 计时

- 041 部分满足 epoch: wolfSSL 在单个 WOLFSSL 对象内递增 dtls_epoch 并重置 sequence，但没有发现跨 association 的 2*MSL epoch reuse 计时器或持久 epoch 禁用窗口。

## PMTU 黑洞探测依赖显式 MTU/配置

- 042 部分满足 fragment: SendHandshakeMsg 根据 wolfssl_local_GetMaxPlaintextSize 和当前 MTU 分片；wolfSSL_dtls_set_mtu 可设置 MTU。但 repeated retransmissions no response 且 PMTU unknown 时自动降低片长/探测黑洞的状态机未在 DTLS 1.2 timeout 路径中出现。
- 043 部分满足 fragment: SendHandshakeMsg 根据 wolfssl_local_GetMaxPlaintextSize 和当前 MTU 分片；wolfSSL_dtls_set_mtu 可设置 MTU。但 repeated retransmissions no response 且 PMTU unknown 时自动降低片长/探测黑洞的状态机未在 DTLS 1.2 timeout 路径中出现。
