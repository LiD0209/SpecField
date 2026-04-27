# wolfMQTT-master 101-150 对比结果

- 对比输入: `output/02_variable_changes.json` 的索引 `100..149`（共 50 条）
- 目标代码: `wolfMQTT-master`
- 满足: 27
- 部分满足: 17
- 不满足: 6
- 不适用: 0
- 待确认: 0
- 证据定位校验: all_locatable=True, references=163

| ID | source_idx | variable | action | 状态 | 说明 | 证据数 |
|---:|---:|---|---|---|---|---:|
| 101 | 100 | Packet Identifier | validity judgment changes; subsequent matching Packet Identifier is treated as a new publication | 部分满足 | PUBCOMP 之后同 packet id 的后续 PUBLISH 会被当作新消息处理；但 QoS2 去重状态机并不完整。 | 4 |
| 102 | 101 | Packet Identifier | selected from unused set | 部分满足 | Broker 端 packet id 为递增分配并跳过 0，但未校验“当前未使用集合”；Client 端由调用方提供 id。 | 4 |
| 103 | 102 | Packet Identifier | must equal / derived from another field | 满足 | UNSUBACK 的 packet id 直接来自对应 UNSUBSCRIBE。 | 2 |
| 104 | 103 | Packet Identifier | must equal | 满足 | 收到 PUBREL 后发送 PUBCOMP，沿用同一个 packet id。 | 3 |
| 105 | 104 | Packet Identifier | must equal | 满足 | 收到 PUBREC 后发送 PUBREL，沿用同一个 packet id。 | 3 |
| 106 | 105 | Packet Identifier | must equal | 满足 | SUBACK 的 packet id 来自已解析的 SUBSCRIBE。 | 2 |
| 107 | 106 | Packet Identifier | must be selected from unused values | 部分满足 | QoS1 新消息会分配 packet id，但分配策略缺少“当前未使用”校验。 | 4 |
| 108 | 107 | Packet Identifier | copy from another field | 满足 | QoS1 入站 PUBLISH 回 PUBACK 时，packet id 复制自入站包。 | 3 |
| 109 | 108 | Packet Identifier | must be present | 满足 | QoS1 发送 PUBLISH 时要求并编码 packet id（非 0）。 | 3 |
| 110 | 109 | Packet Identifier | copy from another field | 满足 | QoS2 入站 PUBLISH 回 PUBREC 时，packet id 复制自入站包。 | 3 |
| 111 | 110 | Packet Identifier | must be selected from unused values | 部分满足 | QoS2 新消息分配 packet id，但未建立“未使用集合”唯一性约束。 | 4 |
| 112 | 111 | Packet Identifier | must be present | 满足 | QoS2 发送 PUBLISH 时要求并编码 packet id（非 0）。 | 3 |
| 113 | 112 | Packet Identifier | must equal | 满足 | 发送 PUBREL（响应 PUBREC）时沿用相同 packet id。 | 2 |
| 114 | 113 | Packet Identifier | derived/copied from another field | 满足 | SUBACK 变量头 packet id 源自对应 SUBSCRIBE。 | 2 |
| 115 | 114 | Packet Identifier | derived/copied from another field | 满足 | UNSUBACK 变量头 packet id 源自对应 UNSUBSCRIBE。 | 2 |
| 116 | 115 | Packet Identifier | clear/discard | 不满足 | 未实现 Method B 的“discard packet identifier”显式状态迁移。 | 4 |
| 117 | 116 | Packet Identifier | store | 不满足 | 未发现 Method B 接收端 packet identifier 持久化存储与比对逻辑。 | 4 |
| 118 | 117 | Packet Identifier | store | 不满足 | 未实现 Method B 流程里与 packet identifier 相关的存储/丢弃闭环。 | 4 |
| 119 | 118 | Packet Identifier | must be absent | 满足 | QoS0 PUBLISH 不编码 packet id，解码也仅在 QoS>0 时读取。 | 3 |
| 120 | 119 | Packet Identifier | must equal | 满足 | SUBACK 使用与 SUBSCRIBE 相同的 packet id。 | 2 |
| 121 | 120 | Packet Identifier | must be present and non-zero 16-bit | 部分满足 | 发送路径对 SUBSCRIBE/UNSUBSCRIBE/PUBLISH(QoS>0) 已做 non-zero 校验；接收解码路径未统一校验 non-zero。 | 6 |
| 122 | 121 | Packet Identifier | must equal | 满足 | UNSUBACK 对应 UNSUBSCRIBE 的 packet id 保持一致。 | 2 |
| 123 | 122 | Packet Identifier | must equal | 部分满足 | 收到同 packet id 的后续 QoS2 PUBLISH 时会按当前包回 PUBREC；但“直到收到对应 PUBREL”的去重状态约束不完整。 | 4 |
| 124 | 123 | Packet Identifier | must equal | 不满足 | clean_session=0 重连后仅保留订阅，不会自动重发未确认 PUBLISH/PUBREL。 | 4 |
| 125 | 124 | Packet Identifier | must equal original value / reuse original | 不满足 | 未实现“重连时未确认 PUBLISH/PUBREL 复用原 packet id 并重发”的自动机制。 | 4 |
| 126 | 125 | Packet Identifier | set to same value as another field | 满足 | 响应 PUBREL 发送 PUBCOMP 时使用同一 packet id。 | 2 |
| 127 | 126 | Packet Identifier | derived/computed from another field | 满足 | 响应入站 PUBLISH 的 PUBACK 使用原 packet id。 | 2 |
| 128 | 127 | Packet Identifier | set to same value as tracked identifier | 满足 | PUBCOMP 发送流程沿用已跟踪的 packet id。 | 2 |
| 129 | 128 | Packet Identifier | becomes available for reuse | 部分满足 | ACK 处理后会移除等待响应记录，但 packet id 复用策略依赖调用方/递增器，非显式 in-use 集合管理。 | 4 |
| 130 | 129 | Packet Identifier | set to a currently unused value | 部分满足 | 发送新包时未统一保证“当前未使用值”；仅有 non-zero 或递增分配。 | 4 |
| 131 | 130 | Packet Identifier | must equal original PUBLISH Packet Identifier | 满足 | PUBACK/PUBREC/PUBREL 路径中 packet id 与对应 PUBLISH 保持一致。 | 4 |
| 132 | 131 | Packet Identifier | must equal Packet Identifier used in corresponding request | 满足 | SUBACK/UNSUBACK 与请求包 packet id 一一对应。 | 3 |
| 133 | 132 | Packet Identifier | must be present and must not equal zero | 部分满足 | 字段存在性满足；但接收端对 non-zero 的协议约束校验不完整。 | 5 |
| 134 | 133 | Packet Identifier | must equal prior Packet Identifier used for that packet | 部分满足 | 重发时可由调用方复用同 packet id，但库内未形成通用自动重发同 id 的强约束机制。 | 4 |
| 135 | 134 | Packet Identifier | must be present | 满足 | QoS1/2 PUBLISH 均要求并携带 packet id。 | 3 |
| 136 | 135 | Packet Identifier | derived/computed from another field | 满足 | PUBACK 的 packet id 来源于已确认的 PUBLISH。 | 2 |
| 137 | 136 | Packet Identifier | derived/computed from another field | 满足 | PUBREC 的 packet id 来源于已确认的 PUBLISH。 | 2 |
| 138 | 137 | Packet Identifier | same requirements apply as for Client assignment and reuse | 部分满足 | Server 发送 QoS>0 PUBLISH 时会分配 packet id，但未做 in-use 冲突检查。 | 4 |
| 139 | 138 | Password | must be absent | 部分满足 | 编码路径可保证 Password Flag=0 时不发送密码字段；但解码后未校验 payload 消费完毕，异常组合可能未被显式拒绝。 | 4 |
| 140 | 139 | Password | must be absent | 部分满足 | 同 ID139：Password Flag=0 的异常负载一致性校验未完全闭环。 | 4 |
| 141 | 140 | Password | must be present | 满足 | Password Flag=1 时会按协议解析密码字段；缺失时解码失败。 | 2 |
| 142 | 141 | Password | must be present | 满足 | 同 ID141：Password Flag=1 对应密码字段读取路径存在且有边界检查。 | 2 |
| 143 | 142 | Password | must be present as next field | 部分满足 | 编码路径保证 Password 与 Username 联动；接收端未显式校验全部联动约束。 | 4 |
| 144 | 143 | Password | validated range check | 满足 | Password 字段长度使用 16-bit 并进行边界校验（0..65535）。 | 4 |
| 145 | 144 | Password | invalid if value check fails | 满足 | 实现使用 CONNACK 0x04 表示用户名/密码相关校验失败（长度/认证失败）。 | 4 |
| 146 | 145 | Password Flag | must equal | 部分满足 | Password Flag=0 的主要语义路径成立，但接收端对异常负载一致性的显式拒绝不足。 | 2 |
| 147 | 146 | Password Flag | must equal | 满足 | Password Flag=1 时会进入密码字段解析，字段缺失会触发解码错误。 | 2 |
| 148 | 147 | Password Flag | set to constant | 部分满足 | 编码端已实现 User Name Flag=0 时 Password 不允许存在；接收端未显式拒绝所有违规 flag 组合。 | 4 |
| 149 | 148 | Password Flag | must equal | 部分满足 | Password Flag=1 的字段顺序处理存在，但与 Username/Password 联动一致性校验不完全。 | 4 |
| 150 | 149 | Payload | must be present | 不满足 | SUBSCRIBE 解码允许空 payload（topic_count=0），且该异常处理未形成规范化拒绝闭环。 | 5 |
