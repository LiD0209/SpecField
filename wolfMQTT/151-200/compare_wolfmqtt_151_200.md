# wolfMQTT-master 151-200 对比结果

- 对比输入: `output/02_variable_changes.json` 的索引 `150..199`（共 50 条）
- 目标代码: `wolfMQTT-master`
- 满足: 16
- 部分满足: 16
- 不满足: 18
- 不适用: 0
- 待确认: 0
- 证据定位校验: all_locatable=True, references=153

| ID | source_idx | variable | action | 状态 | 说明 | 证据数 |
|---:|---:|---|---|---|---|---:|
| 151 | 150 | Payload | must be present and contain at least one Topic Filter; invalid if absent | 不满足 | UNSUBSCRIBE 解码允许空 payload（topic_count=0），未落实“至少一个 Topic Filter”约束。 | 4 |
| 152 | 151 | Payload | must be absent | 不满足 | Broker 接收 DISCONNECT 时按包类型直接处理，未校验 Remaining Length/payload 是否为 0。 | 3 |
| 153 | 152 | Payload | must be absent | 不满足 | Broker 接收 PINGREQ 时未验证 Remaining Length 是否为 0，直接回复 PINGRESP。 | 3 |
| 154 | 153 | Payload | must be absent | 部分满足 | 发送侧 PINGRESP 为固定头+0 长度；接收侧 PINGRESP 解码未强制 remain_len=0。 | 4 |
| 155 | 154 | Payload | must be absent | 部分满足 | PUBCOMP 编码在 MQTT 3.x 下仅 packet id（remain_len=2）；解码未严格限制为恰好 2。 | 4 |
| 156 | 155 | Payload | must be absent | 部分满足 | PUBREL 编码在 MQTT 3.x 下仅 packet id（remain_len=2）；解码未严格限制为恰好 2。 | 4 |
| 157 | 156 | Payload | must be absent | 满足 | UNSUBACK 在 MQTT 3.x 编码仅包含 packet id，不包含 payload。 | 3 |
| 158 | 157 | Payload | invalid if value check fails | 不满足 | SUBSCRIBE 解码允许 topic_count=0，空 payload 未在解码层判为非法。 | 4 |
| 159 | 158 | Payload | derived/computed from another field | 满足 | PUBLISH payload 长度按 Remaining Length 减去 variable header 长度计算。 | 3 |
| 160 | 159 | Payload | must not be present / must not be stored | 满足 | RETAIN=1 且 payload 长度为 0 时执行删除，不会存储零字节 retained 消息。 | 3 |
| 161 | 160 | Payload | must equal | 满足 | 实现了“retained + payload=0 => 删除 retained message”的行为。 | 3 |
| 162 | 161 | Payload | must be absent | 部分满足 | PUBACK 编码无 payload；解码侧仅校验 remain_len>=2，未做 MQTT3 固定长度严格校验。 | 3 |
| 163 | 162 | Payload | must be absent | 部分满足 | PUBREC 编码无 payload；解码侧同样未做 MQTT3 固定长度严格校验。 | 3 |
| 164 | 163 | Payload | validated range check | 满足 | PUBLISH payload 支持 0 长度并有边界处理。 | 3 |
| 165 | 164 | QoS | must not equal 0 when Packet Identifier is required; if QoS is set to 0 then Packet Identifier must be absent | 部分满足 | 编码侧满足 QoS>0 才携带 packet id 且非 0；解码侧未校验 packet id 非 0。 | 5 |
| 166 | 165 | QoS | derived/computed from another field | 满足 | 下行转发 QoS 按 min(发布 QoS, 订阅 QoS) 计算。 | 3 |
| 167 | 166 | QoS | validated range check | 不满足 | 未实现 clean_session=0 重连后未确认 PUBLISH 自动重发路径。 | 4 |
| 168 | 167 | QoS | set to constant | 满足 | QoS0 场景转发时 out_pub.qos 保持为 0。 | 2 |
| 169 | 168 | QoS | set to constant | 部分满足 | QoS1 发送可在路径上实现，但缺少统一强约束防止异常 QoS 值。 | 3 |
| 170 | 169 | QoS | set to constant | 部分满足 | QoS2 发送可在路径上实现，但缺少统一边界与非法值拒绝。 | 3 |
| 171 | 170 | QoS | must not equal 0 when Packet Identifier is required; if equal to 0 then Packet Identifier must be absent | 部分满足 | QoS 与 packet id 存在性关系基本成立，但 packet id 非 0 的接收校验缺失。 | 4 |
| 172 | 171 | QoS | validated range check with comparison > 0 | 部分满足 | QoS>0 与 packet id 关联存在，但缺少完整的 non-zero 校验闭环。 | 3 |
| 173 | 172 | QoS | derived/computed from another field | 满足 | 响应订阅转发消息的 QoS 由发布 QoS 与订阅 QoS 推导（取较小值）。 | 2 |
| 174 | 173 | QoS | set/overwrite/select | 满足 | SUBACK 对每个 topic tuple 返回一个结果码，并对请求 QoS 做上限裁剪。 | 4 |
| 175 | 174 | QoS | derived/computed from another field | 部分满足 | 单订阅/同过滤器更新场景可满足，但重叠订阅“取最大 QoS”语义未形成统一汇总逻辑。 | 4 |
| 176 | 175 | QoS | validated range check | 不满足 | clean_session=0 重连后的未确认 PUBLISH 重发机制缺失，无法验证该路径下 QoS 约束。 | 3 |
| 177 | 176 | QoS | must equal | 部分满足 | QoS0 + DUP 约束未在通用编码接口强校验，主要依赖调用约定。 | 2 |
| 178 | 177 | QoS | set to constant | 部分满足 | 描述场景可实现指定 QoS，但未建立全局强制约束。 | 2 |
| 179 | 178 | QoS | membership check | 不满足 | SUBSCRIBE 请求 QoS 未做集合校验，options 仅取低 2 位，值 3 会被接受并后续裁剪。 | 3 |
| 180 | 179 | QoS | invalid if value check fails | 不满足 | SUBSCRIBE 中非法 Requested QoS 未触发协议错误断链。 | 3 |
| 181 | 180 | QoS | derived/computed from another field | 满足 | 接收 PUBLISH 后的响应类型由 QoS 推导：QoS1->PUBACK，QoS2->PUBREC，QoS0 无应答。 | 3 |
| 182 | 181 | QoS | selected from offered list | 部分满足 | 存在按订阅 QoS 限幅逻辑，但重叠订阅的全局最大 QoS 汇总语义不完整。 | 3 |
| 183 | 182 | QoS bits | invalid if value check fails | 不满足 | 未实现 PUBLISH QoS bits=11 的协议级拒绝与断链。 | 3 |
| 184 | 183 | QoS bits | must not equal | 不满足 | PUBLISH 不允许的 QoS bits 组合（11）未被拒绝。 | 2 |
| 185 | 184 | QoS bits | invalid if value check fails | 不满足 | 同 ID183：收到 QoS bits=11 的 PUBLISH 时未断链。 | 3 |
| 186 | 185 | QoS bits | must not equal forbidden combination | 不满足 | 同 ID184：forbidden QoS bits 组合未在接收侧判为非法。 | 2 |
| 187 | 186 | Remaining Length | validated upper bound check | 满足 | Remaining Length 编解码有上限控制：编码限制最大值，解码限制最多 4 字节。 | 3 |
| 188 | 187 | Remaining Length | must equal number of bytes remaining within the current packet, including data in the variable header and the payload, excluding the bytes used to encode the Remaining Length | 部分满足 | 读取路径按 Remaining Length 驱动，但当报文大于接收缓冲区时会截断读取，严格一致性校验不完整。 | 4 |
| 189 | 188 | Remaining Length | derived/computed from another field | 满足 | CONNECT 的 Remaining Length 由各字段长度累加计算后编码。 | 4 |
| 190 | 189 | Remaining Length | derived/computed from another field | 满足 | PUBLISH payload 长度按 Remaining Length 计算得到。 | 2 |
| 191 | 190 | Remaining Length | set to constant | 满足 | PUBACK 在 MQTT 3.x 发送路径 Remaining Length 为常量 2。 | 2 |
| 192 | 191 | Remaining Length | set to constant | 满足 | PUBREC 在 MQTT 3.x 发送路径 Remaining Length 为常量 2。 | 2 |
| 193 | 192 | Remaining Length | set to decoded value | 满足 | Remaining Length 解码循环结束后返回累计解码值。 | 3 |
| 194 | 193 | Requested QoS | must equal one of allowed values | 不满足 | Requested QoS 未严格限制为 {0,1,2}（值 3 被接受后裁剪）。 | 2 |
| 195 | 194 | Requested QoS | invalid if value check fails | 不满足 | Requested QoS 非法时未作为协议错误断开连接。 | 3 |
| 196 | 195 | Requested QoS | selected from offered list | 部分满足 | 服务端有授权 QoS 选择与失败码路径，但策略以“裁剪/回显”为主，协商语义覆盖不完整。 | 4 |
| 197 | 196 | Reserved bits | set to constant / must equal listed table value | 不满足 | 固定头 reserved bits 未按报文类型表做合法值校验。 | 3 |
| 198 | 197 | Reserved bits | must equal zero; invalid if not zero | 不满足 | DISCONNECT reserved bits 非 0 场景未实现显式 invalid->disconnect 校验分支。 | 3 |
| 199 | 198 | Reserved bits | must equal | 不满足 | SUBSCRIBE 的 Requested QoS 字节高 6 位保留位未校验为 0。 | 2 |
| 200 | 199 | Reserved bits | invalid if value check fails | 不满足 | reserved bits 非法值缺少统一 invalid->disconnect 处理。 | 3 |
