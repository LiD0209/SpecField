# wolfMQTT-master 101-150 未满足/部分满足分类

- total_reviewed: 23
- 部分满足: 17
- 不满足: 6
- 风险分布: low=0, medium=7, high=16

## 分类汇总

| 分类 | 数量 | 部分满足 | 不满足 |
|---|---:|---:|---:|
| CONNECT Flags 交叉约束接收校验不足 | 1 | 1 | 0 |
| CleanSession=0 重连重传机制缺失 | 2 | 0 | 2 |
| Packet Identifier 唯一值分配校验不足 | 5 | 5 | 0 |
| Packet Identifier 释放后复用策略不完整 | 1 | 1 | 0 |
| Packet Identifier 重传同值约束覆盖不完整 | 1 | 1 | 0 |
| Packet Identifier 非零约束接收校验不足 | 2 | 2 | 0 |
| Password Flag=0 负载一致性校验不足 | 3 | 3 | 0 |
| Password/Username Flag 联动校验不足 | 2 | 2 | 0 |
| QoS2 Method B 存储/丢弃流程缺失 | 3 | 0 | 3 |
| QoS2 去重状态机覆盖不完整 | 2 | 2 | 0 |
| SUBSCRIBE Payload 最小元素约束缺失 | 1 | 0 | 1 |

## 明细

| ID | source_idx | 状态 | 风险 | 分类 | 说明 |
|---:|---:|---|---|---|---|

| 101 | 100 | 部分满足 | high | QoS2 去重状态机覆盖不完整 | 实现按当前包直接处理并回包，缺少完整 QoS2 入站去重状态管理。 |
| 116 | 115 | 不满足 | high | QoS2 Method B 存储/丢弃流程缺失 | Broker 客户端状态结构中无对应 Method B 去重/丢弃状态存储。 |
| 117 | 116 | 不满足 | high | QoS2 Method B 存储/丢弃流程缺失 | 接收 QoS2 PUBLISH 后无对应 packet id 去重缓存。 |
| 118 | 117 | 不满足 | high | QoS2 Method B 存储/丢弃流程缺失 | 流程仅做即时应答，缺少 Method B 语义化状态机。 |
| 121 | 120 | 部分满足 | high | Packet Identifier 非零约束接收校验不足 | 发送端严格，接收端对非零约束未完全落地。 |
| 123 | 122 | 部分满足 | high | QoS2 去重状态机覆盖不完整 | 缺少“等待 PUBREL 期间”去重状态，可能重复分发。 |
| 124 | 123 | 不满足 | high | CleanSession=0 重连重传机制缺失 | 重连语义缺失 inflight 重放，无法满足该规则要求。 |
| 125 | 124 | 不满足 | high | CleanSession=0 重连重传机制缺失 | 实现重点在订阅会话延续，不包含未确认消息重放队列。 |

| 96 | 95 | 部分满足 | medium | Packet Identifier重发语义不完整 | 可保持同 ID，但缺少内建“重发必须复用”策略层。 |
| 102 | 101 | 部分满足 | high | Packet Identifier 唯一值分配校验不足 | 缺少 in-use 集合冲突检测，无法强保证“从未使用值集合选择”。 |
| 107 | 106 | 部分满足 | high | Packet Identifier 唯一值分配校验不足 | 仅递增与回绕，未做在用冲突检查。 |
| 111 | 110 | 部分满足 | high | Packet Identifier 唯一值分配校验不足 | QoS2 分配路径同样缺少在用冲突检测。 |
| 129 | 128 | 部分满足 | medium | Packet Identifier 释放后复用策略不完整 | 有“处理后可继续使用”的效果，但缺少统一复用分配约束。 |
| 130 | 129 | 部分满足 | high | Packet Identifier 唯一值分配校验不足 | 缺少端到端“发送前未占用校验”。 |
| 133 | 132 | 部分满足 | high | Packet Identifier 非零约束接收校验不足 | 编码侧强约束与解码侧弱约束不一致。 |
| 134 | 133 | 部分满足 | medium | Packet Identifier 重传同值约束覆盖不完整 | 行为可实现但依赖调用方策略，缺少内建保障。 |
| 138 | 137 | 部分满足 | high | Packet Identifier 唯一值分配校验不足 | 服务端侧同样缺少“当前未使用值”校验闭环。 |

| 139 | 138 | 部分满足 | medium | Password Flag=0 负载一致性校验不足 | 发送端约束存在，接收端一致性校验不足。 |
| 140 | 139 | 部分满足 | medium | Password Flag=0 负载一致性校验不足 | 缺少对“Flag=0 但携带密码载荷”场景的显式协议拒绝。 |
| 143 | 142 | 部分满足 | medium | Password/Username Flag 联动校验不足 | 发送端做了强约束，接收端未完整实现同等级协议校验。 |
| 146 | 145 | 部分满足 | medium | Password Flag=0 负载一致性校验不足 | 以“是否读取字段”替代了“协议一致性强校验”。 |
| 149 | 148 | 部分满足 | medium | Password/Username Flag 联动校验不足 | 顺序正确但联动约束在接收端并未完整硬化。 |

| 148 | 147 | 部分满足 | high | CONNECT Flags 交叉约束接收校验不足 | 客户端编码强约束已实现，但 broker 解码路径缺失对违规组合的协议级拒绝。 |
| 150 | 149 | 不满足 | high | SUBSCRIBE Payload 最小元素约束缺失 | 未落实“至少一个 Topic Filter/QoS 对”约束。 |
