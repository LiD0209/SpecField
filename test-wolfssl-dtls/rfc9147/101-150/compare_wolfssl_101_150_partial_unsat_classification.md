# wolfSSL DTLS 1.3 101-150 部分/不满足分类

## API-side support only (3)

| ID | 状态 | 风险 | Phase2 | 说明 |
|---:|---|---|---|---|
| 101 | 部分满足 | medium | confirmed_partial | 当前实现支持应用设置/轮换单个 secret 和完整性验证，不提供内建过渡窗口或时间戳过期策略。 |
| 103 | 部分满足 | medium | confirmed_partial | 当前实现支持应用设置/轮换单个 secret 和完整性验证，不提供内建过渡窗口或时间戳过期策略。 |
| 104 | 部分满足 | medium | confirmed_partial | 当前实现支持应用设置/轮换单个 secret 和完整性验证，不提供内建过渡窗口或时间戳过期策略。 |

## behavior exists but strict proof is missing (2)

| ID | 状态 | 风险 | Phase2 | 说明 |
|---:|---|---|---|---|
| 114 | 部分满足 | low | confirmed_partial | 通用 helper 可写 session ID，但 DTLS 1.3 特定条件策略证据不足。 |
| 139 | 部分满足 | medium | confirmed_partial | 同一序列状态贯穿 DTLS 1.3 路径，但缺少完整 post-handshake 覆盖测试。 |

## transport mode not implemented (1)

| ID | 状态 | 风险 | Phase2 | 说明 |
|---:|---|---|---|---|
| 117 | 部分满足 | low | not_testable | 要求限定 DTLS over TCP/SCTP，当前目标代码和构建环境以 UDP datagram DTLS 为主，不能形成可靠运行结论。 |

## incomplete validation (2)

| ID | 状态 | 风险 | Phase2 | 说明 |
|---:|---|---|---|---|
| 123 | 部分满足 | medium | confirmed_partial | 实现不会发送违规中间无长度记录，接收端语义上把无 length 解释为最后记录，但缺少显式错误路径。 |
| 125 | 部分满足 | medium | confirmed_partial | 代码能读显式 length 并进行最小密文长度检查，但没有直接证明显式 length 被限制在 datagram 内。 |

## missing feature/path (2)

| ID | 状态 | 风险 | Phase2 | 说明 |
|---:|---|---|---|---|
| 145 | 不满足 | high | confirmed_unsatisfied | 标准要求动态 CID 请求/响应 handshake 消息，源码只有 CID extension/API 和 unified header CID bit，没有对应 post-handshake 消息处理。 |
| 146 | 不满足 | high | confirmed_unsatisfied | 标准要求动态 CID 请求/响应 handshake 消息，源码只有 CID extension/API 和 unified header CID bit，没有对应 post-handshake 消息处理。 |
