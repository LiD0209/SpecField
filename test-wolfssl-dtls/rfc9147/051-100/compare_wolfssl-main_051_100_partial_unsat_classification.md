# wolfssl-main DTLS 1.3 RFC 9147 051-100 部分/不满足分类

- 待复核条目: 6
- 部分满足: 6
- 不满足: 0

| ID | 状态 | 风险 | 分类 | 复核结论 | decision_reason |
|---:|---|---|---|---|---|
| 57 | 部分满足 | medium | close_notify 后缺少 epoch/sequence pair 专用忽略门控 | confirmed_partial | 已实现 close_notify 语义和 API 返回；缺失 DTLS 1.3 以 epoch/sequence pair 为界忽略后续数据的专用逻辑，因此为 confirmed_partial。 |
| 62 | 部分满足 | medium | 发送端 epoch 上限只检查 64-bit wrap，未显式执行 2^48-1 限制 | confirmed_partial | 接收端不强制上限符合标准；发送端缺少 2^48-1 的显式限制，仅防 64-bit wrap，因此为 confirmed_partial。 |
| 76 | 部分满足 | medium | 发送端 epoch 上限只检查 64-bit wrap，未显式执行 2^48-1 限制 | confirmed_partial | 防 64-bit wrap 已实现；协议发送上限前的阻断未实现，confirmed_partial。 |
| 87 | 部分满足 | medium | 发送端 epoch 上限只检查 64-bit wrap，未显式执行 2^48-1 限制 | confirmed_partial | 实现了防 wrap 的一部分，但未覆盖发送上限，confirmed_partial。 |
| 93 | 部分满足 | low | PMTU 未知且重复重传失败时缺少更小 record size 回退证据 | confirmed_partial | 已实现分片和重传，缺少 repeated retransmission + unknown PMTU 的更小 record size 回退证据，confirmed_partial。 |
| 97 | 部分满足 | medium | KeyUpdate 响应未结合 2^48-1 发送 epoch 上限判断 | confirmed_partial | 响应机制和等待 ACK 门控存在；缺少 limits-based response suppression，confirmed_partial。 |
