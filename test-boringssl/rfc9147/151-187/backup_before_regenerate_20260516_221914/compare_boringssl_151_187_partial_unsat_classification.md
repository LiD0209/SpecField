# BoringSSL 151-187 部分满足/不满足分类

- 分类条目: 6

## missing optional feature/path

- 数量: 1
- 风险分布: {"medium": 1}

| ID | 状态 | 风险 | 变量 | 验证结论 | 原因 |
|---:|---|---|---|---|---|
| 152 | 部分满足 | medium | Outer Content Type | confirmed_partial | Confirmed partial: unsupported Heartbeat is safely rejected/not dispatched, but the implementation cannot process Heartbeat records if that feature were required by the deployment. |

## missing feature/path

- 数量: 1
- 风险分布: {"high": 1}

| ID | 状态 | 风险 | 变量 | 验证结论 | 原因 |
|---:|---|---|---|---|---|
| 153 | 不满足 | high | Outer Content Type | confirmed_unsatisfied | Confirmed unsatisfied for CID-capable operation: the record layer has no DTLS 1.2 CID demux path and rejects DTLS 1.3 CID headers. |

## incomplete ACK behavior

- 数量: 1
- 风险分布: {"medium": 1}

| ID | 状态 | 风险 | 变量 | 验证结论 | 原因 |
|---:|---|---|---|---|---|
| 157 | 部分满足 | medium | record_numbers | confirmed_partial | Confirmed partial: regular ACK generation works, but the special empty ACK shortcut is not implemented. |

## missing CID update feature/path

- 数量: 3
- 风险分布: {"high": 3}

| ID | 状态 | 风险 | 变量 | 验证结论 | 原因 |
|---:|---|---|---|---|---|
| 185 | 不满足 | high | usage | confirmed_unsatisfied | Confirmed unsatisfied: BoringSSL cannot process cid_spare because DTLS CID update support is absent. |
| 186 | 不满足 | high | usage | confirmed_unsatisfied | Confirmed unsatisfied: there is no mechanism to switch future records to a new CID immediately. |
| 187 | 不满足 | high | usage | confirmed_unsatisfied | Confirmed unsatisfied: RequestConnectionId cannot trigger a cid_spare NewConnectionId response. |

