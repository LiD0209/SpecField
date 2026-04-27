# wolfMQTT-master 251-300 对比结果

- 对比源：`output/02_variable_changes.json` 的 `250..299`（共 50 条）
- 目标代码：`wolfMQTT-master`
- 满足：19
- 部分满足：23
- 不满足：8
- 不适用：0
- 待确认：0
- 证据定位校验：all_locatable=True, references=151

| ID | source_idx | variable | action | 状态 | 结论说明 | 证据数 |
|---:|---:|---|---|---|---|---:|
| 251 | 250 | Topic Filter | must not equal / include forbidden character | 不满足 | 未发现对 Topic Filter 中 U+0000 的显式拒绝；仅解码长度和边界，不校验禁用字符。 | 4 |
| 252 | 251 | Topic Filter | validated range check | 满足 | 字符串采用 2 字节长度字段解码，编码侧也限制 >65535 字节，满足长度上限约束。 | 3 |
| 253 | 252 | Topic Filter | must equal corresponding Topic Name level character for character | 满足 | 订阅匹配时，非通配符层级按字符逐个比较实现。 | 3 |
| 254 | 253 | Topic Filter | invalid if value check fails | 部分满足 | 支持通过编译开关禁用通配符匹配，但禁用后并未在 SUBSCRIBE 入站阶段拒绝含通配符的 Topic Filter。 | 3 |
| 255 | 254 | Topic Filter | validity check | 部分满足 | SUBSCRIBE 的 Topic Filter 走长度前缀字符串解码，但无 UTF-8 语义校验。 | 3 |
| 256 | 255 | Topic Filter | validity check | 部分满足 | UNSUBSCRIBE 的 Topic Filter 同样仅做长度解码，无 UTF-8 合法性判断。 | 3 |
| 257 | 256 | Topic Filter | must equal | 满足 | 同一客户端对同一 Topic Filter 重复订阅时执行更新 QoS，而非创建重复订阅。 | 3 |
| 258 | 257 | Topic Filter | must not equal wildcard-start pattern for matching with '$'-prefixed Topic Name | 满足 | 实现了 $ 前缀 Topic Name 与前导通配符过滤器（#/+）不匹配的约束。 | 3 |
| 259 | 258 | Topic Filter | must not be modified or normalized | 满足 | 匹配逻辑基于字符逐位比较与通配符规则分支，未做归一化或字符替换。 | 3 |
| 260 | 259 | Topic Filter | must equal wildcard placement constraint | 部分满足 | 匹配阶段仅当 # 为末尾字符才返回匹配；但未在订阅入站阶段显式判定非法位置。 | 3 |
| 261 | 260 | Topic Filter | must equal whole-level placement constraint | 不满足 | 未实现“+ 必须占据整级”的显式语法校验；匹配器会将 + 作为字符位置通配处理。 | 3 |
| 262 | 261 | Topic Name | validated range check | 不满足 | 未发现 Topic Name 最小长度（>=1）的显式拒绝；空 Topic Name 可进入后续流程。 | 3 |
| 263 | 262 | Topic Name | must not contain | 不满足 | 未对 Topic Name 的 U+0000 做拒绝校验。 | 3 |
| 264 | 263 | Topic Name | must be valid UTF-8; invalid if value check fails | 部分满足 | 接收侧使用长度前缀解码字符串，但未进行 UTF-8 编码合法性检查。 | 3 |
| 265 | 264 | Topic Name | must be valid UTF-8; invalid if value check fails | 部分满足 | Topic Name 解析流程仅完成长度与边界校验，未做 UTF-8 语义验证。 | 3 |
| 266 | 265 | Topic Name | must not equal or include U+0000; invalid if value check fails | 不满足 | Topic Name 未实现 U+0000 特判拒绝。 | 3 |
| 267 | 266 | Topic Name | validated range check | 满足 | Topic Name 使用 2 字节长度字段（0..65535）并带边界检查。 | 3 |
| 268 | 267 | Topic Name | validated range check | 满足 | 编码侧限制 UTF-8 字符串长度不得超过 65535 字节。 | 3 |
| 269 | 268 | Topic Name | must not contain | 部分满足 | Broker 入站 PUBLISH 会拒绝 Topic Name 中的 +/#；但编码 API 未做同等限制。 | 3 |
| 270 | 269 | Topic Name | must not contain | 部分满足 | 与 ID269 一致：仅 Broker 接收路径显式拒绝通配符 Topic Name。 | 3 |
| 271 | 270 | Topic Name | validated range check | 不满足 | 未实现“所有 Topic Name 至少 1 字符”的统一校验。 | 3 |
| 272 | 271 | Topic Name | must not equal / include forbidden character | 不满足 | 未发现 Topic Name 的 NUL 字符全局拒绝。 | 3 |
| 273 | 272 | Topic Name | validated range check | 满足 | Topic Name 长度上限通过编码限制和 2 字节长度字段机制得到保证。 | 3 |
| 274 | 273 | Topic Name | must equal corresponding Topic Filter level character for character | 满足 | 订阅匹配中，非通配符层级按字符精确相等进行比较。 | 3 |
| 275 | 274 | Topic Name | must match | 满足 | Broker 向订阅者转发前通过 BrokerTopicMatch 判定 Topic Name 与 Topic Filter 是否匹配。 | 3 |
| 276 | 275 | Topic Name | must equal required type/format | 部分满足 | PUBLISH 的 Topic Name 以长度前缀字符串编解码，但无 UTF-8 语义校验。 | 3 |
| 277 | 276 | Topic Name | must not contain | 部分满足 | 接收侧 Broker 拒绝 Topic Name 中 +/#，但发送编码路径未统一校验。 | 3 |
| 278 | 277 | Topic Name | validity check | 部分满足 | PUBLISH Topic Name 的 UTF-8 校验仍停留在长度层，缺少编码语义验证。 | 3 |
| 279 | 278 | Topic Name | must be present | 满足 | PUBLISH 可变头首字段按实现先编解码 Topic Name，再处理 Packet Identifier/属性。 | 3 |
| 280 | 279 | Topic Name | invalid if value check fails | 满足 | Topic Name 以 $ 开头时不会与前导 +/# 的 Topic Filter 匹配。 | 3 |
| 281 | 280 | Topic Name | must not be modified or normalized | 满足 | 匹配算法未做归一化或替换，按原始字符流进行判断。 | 3 |
| 282 | 281 | User Name | must be absent | 部分满足 | CONNECT 解码仅在 User Name Flag=1 时解析用户名；但未校验“Flag=0 时剩余载荷必须不含用户名字段”。 | 3 |
| 283 | 282 | User Name | must be absent | 部分满足 | 同 ID282：条件分支存在，但未做“多余用户名字段”一致性拒绝。 | 3 |
| 284 | 283 | User Name | must be present | 满足 | 当 User Name Flag=1 时，解码路径会读取用户名字段；字段缺失将触发边界错误返回。 | 3 |
| 285 | 284 | User Name | must be present | 满足 | 同 ID284：Flag=1 会触发用户名字段读取，满足存在性约束。 | 3 |
| 286 | 285 | User Name | invalid if value check fails | 部分满足 | 实现中确实使用返回码 0x04（v3）表示用户名/密码问题，但覆盖了“认证失败”与“格式错误”两类语义。 | 3 |
| 287 | 286 | User Name | must be valid UTF-8; invalid if value check fails | 部分满足 | User Name 字段接收侧仅做长度解码，无 UTF-8 合法性校验。 | 3 |
| 288 | 287 | User Name | must be present as next field | 满足 | CONNECT 载荷解析顺序中，User Name Flag=1 时用户名字段作为后续字段被读取。 | 3 |
| 289 | 288 | User Name | must be valid UTF-8; invalid if value check fails | 部分满足 | User Name 未做 UTF-8 语义级合法性判断，仅长度边界检查。 | 3 |
| 290 | 289 | User Name | must not equal or include U+0000; invalid if value check fails | 不满足 | 未发现对 User Name 中 U+0000 的显式拒绝。 | 3 |
| 291 | 290 | User Name | validated range check | 满足 | User Name 解析基于 2 字节长度字段并做边界检查，满足 0..65535 字节范围。 | 3 |
| 292 | 291 | User Name | must equal valid UTF-8 encoded string format | 部分满足 | CONNECT 中 User Name 使用长度前缀字符串格式，但未校验 UTF-8 语义合法性。 | 3 |
| 293 | 292 | User Name Flag | must equal | 部分满足 | 发送侧编码已实现“Password 不能在 Username 为空时单独出现”；接收侧 CONNECT 解码未显式验证该约束。 | 3 |
| 294 | 293 | User Name Flag | must equal | 部分满足 | 实现通过 Flag 位驱动字段解析，但未严格拒绝 Flag=0 时附带用户名数据的异常载荷。 | 3 |
| 295 | 294 | User Name Flag | must equal | 满足 | 编码侧当用户名存在时会设置 User Name Flag=1。 | 3 |
| 296 | 295 | User Name Flag | must equal | 满足 | 当 User Name Flag=1 时，CONNECT 解析会读取用户名字段。 | 3 |
| 297 | 296 | Variable header | must be absent | 部分满足 | DISCONNECT 编码在 MQTT3 场景为无可变头；但实现同时支持 MQTT5 可变头，且 broker 收包路径未显式校验 remaining length=0。 | 3 |
| 298 | 297 | Variable header | must be absent | 部分满足 | PINGREQ 发送侧固定 remaining length=0；broker 收到 PINGREQ 后直接回 PINGRESP，未显式拒绝附加可变头/载荷。 | 3 |
| 299 | 298 | Variable header | must be absent | 部分满足 | PINGRESP 编码为无可变头；但 PINGRESP 解码未校验 remaining length 必须为 0。 | 3 |
| 300 | 299 | Will Flag | must equal | 部分满足 | Will 处理逻辑在 Will Flag=1 时会存储并置位 has_will；但条目中的“Connect accepted => Will Flag=1”并非实现的普遍约束。 | 3 |
