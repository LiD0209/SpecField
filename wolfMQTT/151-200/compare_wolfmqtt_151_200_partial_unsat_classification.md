# wolfMQTT-master 151-200 未满足/部分满足分类

- total_reviewed: 34
- 部分满足: 16
- 不满足: 18
- 风险分布: low=0, medium=13, high=21

## 分类汇总

| 分类 | 数量 | 部分满足 | 不满足 |
|---|---:|---:|---:|
| ACK 报文长度严格校验不足 | 4 | 4 | 0 |
| CleanSession=0 重连重传机制缺失 | 2 | 0 | 2 |
| Fixed Header Reserved bits 校验缺失 | 3 | 0 | 3 |
| PINGREQ/DISCONNECT 空 payload 校验缺失 | 2 | 0 | 2 |
| PUBLISH QoS bits 非法值校验缺失 | 4 | 0 | 4 |
| QoS 与 DUP 约束实现不完整 | 1 | 1 | 0 |
| QoS 与 Packet Identifier 联动校验不完整 | 3 | 3 | 0 |
| QoS 固定值与边界校验不完整 | 3 | 3 | 0 |
| Remaining Length 一致性校验不完整 | 1 | 1 | 0 |
| SUBSCRIBE Requested QoS/保留位校验缺失 | 5 | 0 | 5 |
| SUBSCRIBE/UNSUBSCRIBE 最小 payload 约束缺失 | 2 | 0 | 2 |
| 控制报文空 payload 接收校验不足 | 1 | 1 | 0 |
| 订阅 QoS 协商语义不完整 | 1 | 1 | 0 |
| 重叠订阅 QoS 汇总语义不完整 | 2 | 2 | 0 |

## 明细

| ID | source_idx | 状态 | 风险 | 分类 | 说明 |
|---:|---:|---|---|---|---|
| 151 | 150 | 不满足 | high | SUBSCRIBE/UNSUBSCRIBE 最小 payload 约束缺失 | 协议要求最小元素时，当前实现可接受空载荷。 |
| 152 | 151 | 不满足 | high | PINGREQ/DISCONNECT 空 payload 校验缺失 | 接收路径缺少协议格式校验。 |
| 153 | 152 | 不满足 | high | PINGREQ/DISCONNECT 空 payload 校验缺失 | 没有“非法长度即协议错误”的分支。 |
| 154 | 153 | 部分满足 | medium | 控制报文空 payload 接收校验不足 | 编码符合，解码校验偏宽松。 |
| 155 | 154 | 部分满足 | medium | ACK 报文长度严格校验不足 | 存在“至少 2 字节”校验，但无 MQTT3 严格等值校验。 |
| 156 | 155 | 部分满足 | medium | ACK 报文长度严格校验不足 | 接收端未对 MQTT3 场景做固定长度强校验。 |
| 158 | 157 | 不满足 | high | SUBSCRIBE/UNSUBSCRIBE 最小 payload 约束缺失 | 最小元素约束未在协议接收面落实。 |
| 162 | 161 | 部分满足 | medium | ACK 报文长度严格校验不足 | 接收容忍更长报文，严格性不足。 |
| 163 | 162 | 部分满足 | medium | ACK 报文长度严格校验不足 | 缺少“长度必须等于 2”的约束。 |
| 165 | 164 | 部分满足 | high | QoS 与 Packet Identifier 联动校验不完整 | 发送端约束强，接收端 non-zero 缺失。 |
| 167 | 166 | 不满足 | high | CleanSession=0 重连重传机制缺失 | 会话保持主要是订阅层，不含 inflight 消息重传。 |
| 169 | 168 | 部分满足 | medium | QoS 固定值与边界校验不完整 | 主要流程可达成，协议级硬约束不足。 |
| 170 | 169 | 部分满足 | medium | QoS 固定值与边界校验不完整 | 依赖调用路径与上层输入，缺少全面限制。 |
| 171 | 170 | 部分满足 | high | QoS 与 Packet Identifier 联动校验不完整 | 解码侧未拒绝 QoS>0 + packet_id=0。 |
| 172 | 171 | 部分满足 | high | QoS 与 Packet Identifier 联动校验不完整 | 发送侧有校验，接收侧无等价校验。 |
| 175 | 174 | 部分满足 | medium | 重叠订阅 QoS 汇总语义不完整 | 按匹配项逐条转发，缺少统一“最大 QoS 汇总后单发”机制。 |
| 176 | 175 | 不满足 | high | CleanSession=0 重连重传机制缺失 | 无内建重发通道。 |
| 177 | 176 | 部分满足 | medium | QoS 与 DUP 约束实现不完整 | 缺少统一禁止非法组合的入口校验。 |
| 178 | 177 | 部分满足 | medium | QoS 固定值与边界校验不完整 | 更偏路径性满足，而非协议级强制。 |
| 179 | 178 | 不满足 | high | SUBSCRIBE Requested QoS/保留位校验缺失 | 应在接收面拒绝非法 Requested QoS，而非静默裁剪。 |
| 180 | 179 | 不满足 | high | SUBSCRIBE Requested QoS/保留位校验缺失 | 缺少 invalid->disconnect 的强处理分支。 |
| 182 | 181 | 部分满足 | medium | 重叠订阅 QoS 汇总语义不完整 | 多匹配订阅缺少统一汇总决策。 |

| 183 | 182 | 不满足 | high | PUBLISH QoS bits 非法值校验缺失 | QoS=3 可进入处理路径。 |
| 184 | 183 | 不满足 | high | PUBLISH QoS bits 非法值校验缺失 | 固定头解析不校验 qos bits 合法性。 |
| 185 | 184 | 不满足 | high | PUBLISH QoS bits 非法值校验缺失 | 缺少协议违规断开分支。 |
| 186 | 185 | 不满足 | high | PUBLISH QoS bits 非法值校验缺失 | 缺少 QoS bits=3 的接收拒绝逻辑。 |  （已在前面调查）

| 188 | 187 | 部分满足 | medium | Remaining Length 一致性校验不完整 | 存在分段/截断场景，未统一在此层强制“全部剩余字节都在当前包”。 |
| 194 | 193 | 不满足 | high | SUBSCRIBE Requested QoS/保留位校验缺失 | 未实现集合成员校验。 |
| 195 | 194 | 不满足 | high | SUBSCRIBE Requested QoS/保留位校验缺失 | invalid 值被容忍并继续处理。 |
| 196 | 195 | 部分满足 | medium | 订阅 QoS 协商语义不完整 | 缺少更细粒度授权/拒绝策略。 |
| 197 | 196 | 不满足 | high | Fixed Header Reserved bits 校验缺失 | 仅校验 packet type，未校验 flags 合法性。 |
| 198 | 197 | 不满足 | high | Fixed Header Reserved bits 校验缺失 | 接收侧未对 DISCONNECT flags 做合法性验证。 |
| 199 | 198 | 不满足 | high | SUBSCRIBE Requested QoS/保留位校验缺失 | 当前仅提取低 2 位 QoS。 |
| 200 | 199 | 不满足 | high | Fixed Header Reserved bits 校验缺失 | 协议违规标志位未触发统一拒绝断链。 |
