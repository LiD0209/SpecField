# wolfMQTT-master 301-336 对比结果（存放于 301-350 目录）

- 对比源：`output/02_variable_changes.json` 的 `300..335`（共 36 条）
- 目标代码：`wolfMQTT-master`
- 满足：20
- 部分满足：12
- 不满足：4
- 不适用：0
- 待确认：0
- 证据定位校验：all_locatable=True, references=108

| ID | source_idx | variable | action | 状态 | 结论说明 | 证据数 |
|---:|---:|---|---|---|---|---:|
| 301 | 300 | Will Flag | must equal | 满足 | Will Flag=0 时解码侧 `enable_lwt` 为 0，编码侧也仅在启用时置位该标志。 | 3 |
| 302 | 301 | Will Flag | must equal | 满足 | Will Flag=1 时可正确置位并在解码中读取为启用 LWT。 | 3 |
| 303 | 302 | Will Flag | must equal | 满足 | Will Flag=1 时，CONNECT 载荷解析进入 LWT 字段分支。 | 3 |
| 304 | 303 | Will Flag | must equal 1 | 满足 | 服务端 CONNECT 处理会依据解码得到的 `mc.enable_lwt` 执行 Will 逻辑。 | 3 |
| 305 | 304 | Will Message | must be absent | 部分满足 | Will Flag=0 时不解析 Will 字段，但未做“剩余载荷必须恰好消费完”的强校验。 | 3 |
| 306 | 305 | Will Message | must be absent | 部分满足 | 同 ID305：缺少对 Will Flag=0 且载荷仍含 Will 内容的显式拒绝。 | 3 |
| 307 | 306 | Will Message | must be present | 满足 | Will Flag=1 时必须进入 LWT 字段解析，字段缺失会触发越界/解码错误。 | 3 |
| 308 | 307 | Will Message | must be present / stored | 满足 | CONNECT 被接受后，服务端会存储 Will Topic/Payload/QoS/Retain 并关联到客户端连接。 | 3 |
| 309 | 308 | Will Message | discard / clear without publishing | 满足 | 收到 DISCONNECT 时清除 Will，不触发发布。 | 3 |
| 310 | 309 | Will Message | clear/remove | 满足 | Will 发布后立即清除；正常 DISCONNECT 也清除。 | 3 |
| 311 | 310 | Will Message | removed/cleared from stored Session state | 满足 | 同 ID310，Will 生命周期包含发布后/正常断开后清理。 | 3 |
| 312 | 311 | Will Message | must be present as next field | 满足 | Will Flag=1 时，Will topic 与 Will payload 在 CONNECT 载荷中按顺序作为后续字段解析。 | 3 |
| 313 | 312 | Will Message | must be present / stored | 满足 | 连接接受并启用 LWT 时会将 Will 持久于连接上下文（`bc->has_will=1`）。 | 3 |
| 314 | 313 | Will Message | must be present | 满足 | Will Flag=1 的 CONNECT 解析必须包含 Will 字段路径。 | 3 |
| 315 | 314 | Will QoS | set to constant | 部分满足 | 编码侧仅在 `enable_lwt` 时设置 Will QoS 位；但解码侧未验证 Will Flag=0 时 QoS 位必须为 0。 | 3 |
| 316 | 315 | Will QoS | must equal | 部分满足 | 同 ID315：缺少对 Will Flag=0 下 Will QoS 位非零的协议拒绝。 | 3 |
| 317 | 316 | Will QoS | set to constant | 部分满足 | 同 ID315/316：未做 Will Flag=0 时 Will QoS=0 的强制验证。 | 3 |
| 318 | 317 | Will QoS | validated range check | 不满足 | 未发现对 Will QoS=3（保留值）的拒绝逻辑，解码直接取两位值。 | 3 |
| 319 | 318 | Will QoS | validated membership check | 不满足 | 同 ID318：未限制 Will QoS 仅允许 {0,1,2}。 | 3 |
| 320 | 319 | Will QoS | must not equal | 不满足 | 同 ID318/319：Will QoS=3 未被判定为错误。 | 3 |
| 321 | 320 | Will QoS | used/selected from Connect Flags | 满足 | Will Flag=1 时，Will QoS 从 CONNECT flags 提取并被服务端保存使用。 | 3 |
| 322 | 321 | Will Retain | set to constant | 部分满足 | 编码侧可保证 Will Flag=0 时不会置位 Will Retain；但解码侧未显式拒绝违规置位。 | 3 |
| 323 | 322 | Will Retain | must equal | 部分满足 | 同 ID322：Will Flag=0 时 Will Retain 必为 0 的接收侧强校验不存在。 | 3 |
| 324 | 323 | Will Retain | must equal | 满足 | Will Retain=0 时不会写 retained 存储，Will 普通分发。 | 3 |
| 325 | 324 | Will Retain | must equal | 满足 | Will Retain=1 时进入 retained 处理路径（存储/删除 retained）。 | 3 |
| 326 | 325 | Will Retain | used/selected from Connect Flags | 满足 | Will Retain 从 CONNECT flags 解码并写入连接状态。 | 3 |
| 327 | 326 | Will topic | must be absent | 部分满足 | Will Flag=0 时不解析 Will topic，但未严格拒绝多余 Will topic 载荷。 | 3 |
| 328 | 327 | Will topic | must be absent | 部分满足 | 同 ID327：缺乏对 Flag=0 且出现 Will topic 字段的显式无效判定。 | 3 |
| 329 | 328 | Will topic | must be present | 满足 | Will Flag=1 时 CONNECT 解析会读取 Will topic。 | 3 |
| 330 | 329 | Will topic | must be valid UTF-8; invalid if value check fails | 部分满足 | Will topic 仅做长度前缀字符串解码，无 UTF-8 语义合法性校验。 | 3 |
| 331 | 330 | Will topic | must be present as next field | 满足 | Will Flag=1 时，Will topic 是 CONNECT 中 Will 区段的首字段并先于 Will payload 解析。 | 3 |
| 332 | 331 | Will topic | must be present | 满足 | Will Flag=1 的解析路径会要求并消费 Will topic 字段。 | 3 |
| 333 | 332 | Will topic | must satisfy validity check | 部分满足 | Will topic 采用长度前缀字符串格式，但未校验 UTF-8 码点合法性。 | 3 |
| 334 | 333 | Will topic | must be valid UTF-8; invalid if value check fails | 部分满足 | 同 ID330/333：Will topic 缺失 UTF-8 字符语义校验。 | 3 |
| 335 | 334 | Will topic | must not equal or include U+0000; invalid if value check fails | 不满足 | 未发现对 Will topic 中 U+0000 的显式拒绝。 | 3 |
| 336 | 335 | Will topic | validated range check | 满足 | Will topic 字符串长度采用 2 字节长度字段，范围可覆盖 0..65535 并含边界校验。 | 3 |
