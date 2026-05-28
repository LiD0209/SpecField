# wolfSSL DTLS 1.3 001-050 部分满足/不满足分类

- 总数: 5
- confirmed_partial: 2
- confirmed_unsatisfied: 3
- false_positive: 0

## incomplete ACK prioritization

| ID | 状态 | 风险 | Phase 2 | decision_reason |
|---:|---|---|---|---|
| 016 | 部分满足 | medium | confirmed_partial | 实现满足 ACK 列表排序、去重和容量保护，但缺少 RFC SHOULD 的优先级策略，因此确认为部分满足。 |

## missing dynamic CID handshake messages

| ID | 状态 | 风险 | Phase 2 | decision_reason |
|---:|---|---|---|---|
| 028 | 部分满足 | medium | confirmed_partial | DTLSHandshake 常规分支已实现，动态 CID 消息分支缺失，因此确认为部分满足。 |
| 031 | 不满足 | medium | confirmed_unsatisfied | 没有 NewConnectionId 消息和 usage 字段处理，因此无法满足 cid_immediate 立即切换要求。 |
| 032 | 不满足 | medium | confirmed_unsatisfied | 由于 spare CID 特性本身缺失，相关丢弃策略也不存在，因此确认为不满足。 |
| 033 | 不满足 | medium | confirmed_unsatisfied | 没有多个 receiver-provided CIDs 的存储和选择机制，无法按提供顺序使用，因此确认为不满足。 |
