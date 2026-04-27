# wolfMQTT-master 051-100 对比结果

- 对比输入: `output/02_variable_changes.json` 的索引 `50..99`（共 50 条）
- 目标代码: `wolfMQTT-master`
- 满足: 26
- 部分满足: 16
- 不满足: 8
- 不适用: 0
- 待确认: 0
- 证据定位校验: all_locatable=True, references=145

| ID | source_idx | variable | action | 状态 | 说明 | 证据数 |
|---:|---:|---|---|---|---|---:|
| 51 | 50 | CONNACK return code | set to constant | 不满足 | 空 ClientId + clean_session=0 未返回 0x02（Identifier rejected）。 | 3 |
| 52 | 51 | CONNACK return code | must not equal zero | 部分满足 | 部分校验失败会返回非零 CONNACK，但并非所有失败路径都发送 CONNACK。 | 4 |
| 53 | 52 | CONNACK return code | set to constant | 满足 | CONNECT 验证成功时，CONNACK 返回码为 0。 | 2 |
| 54 | 53 | CONNACK return code | must not equal | 满足 | 发送非零 CONNACK 后会立即走断链流程。 | 4 |
| 55 | 54 | CONNACK return code | set to constant | 不满足 | 同 ID51：空 ClientId + clean_session=0 未返回 0x02。 | 3 |
| 56 | 55 | CONNACK return code | set to constant | 满足 | 接受 clean_session=0 连接时返回码为 0。 | 3 |
| 57 | 56 | CONNACK return code | set to constant | 满足 | 接受 clean_session=1 连接时返回码为 0。 | 3 |
| 58 | 57 | CONNACK return code | set to constant | 满足 | 无已存会话状态时，接受连接返回码为 0。 | 3 |
| 59 | 58 | CONNACK return code | set to constant | 部分满足 | 存在 ClientId 被拒绝并返回 0x02 的路径（如过长 ID），但覆盖不完整。 | 3 |
| 60 | 59 | CONNACK return code | set to constant | 部分满足 | 同 ID59：0x02 返回码仅在部分 ClientId 拒绝路径生效。 | 3 |
| 61 | 60 | CONNACK return code | set to constant | 满足 | 服务端确认 CONNECT 时使用零返回码。 | 2 |
| 62 | 61 | CONNACK return code | set to constant | 不满足 | 未见对不支持 protocol level 的显式 0x01 响应校验与分支。 | 3 |
| 63 | 62 | Connect Acknowledge Flags | validated value constraint | 部分满足 | 发送侧 CONNACK flags 置 0，但接收侧未显式校验 bits7..1 为 0。 | 3 |
| 64 | 63 | Connect Flags | indicates presence or absence of payload fields | 满足 | Connect Flags 同时用于连接行为参数和 payload 字段存在性判定。 | 4 |
| 65 | 64 | Connect Return code | selected from offered list | 满足 | 对可处理的“well-formed 但无法处理”场景，会给出表内非零返回码。 | 4 |
| 66 | 65 | Connect Return code | invalid if value selection fails | 部分满足 | 存在不发 CONNACK 直接断链路径，但非以“无适用返回码”统一决策实现。 | 4 |
| 67 | 66 | continuation bit | set to 1 | 满足 | Remaining Length 编码时，有后续字节会置 continuation bit。 | 3 |
| 68 | 67 | continuation bit | must not equal 0 to continue decoding | 满足 | Remaining Length 解码循环条件为 `(encodedByte & 128) != 0`。 | 2 |
| 69 | 68 | DUP | value ignored for judgment | 满足 | 接收侧未基于 DUP 位做重复抑制判定，同包标识重来仍按发布流程处理。 | 3 |
| 70 | 69 | DUP | set to constant | 部分满足 | broker 转发 QoS0 时固定 DUP=0，但通用编码接口未硬性禁止 QoS0+dup=1。 | 2 |
| 71 | 70 | DUP | set to constant | 部分满足 | QoS1 首发在 broker 流程为 DUP=0；通用客户端编码由调用方提供 duplicate。 | 3 |
| 72 | 71 | DUP | set to constant | 部分满足 | QoS2 首发同样依赖调用侧 duplicate 输入，未统一强制。 | 3 |
| 73 | 72 | DUP | set to constant | 部分满足 | QoS0 发送常见路径 DUP=0，但非所有调用路径都强制该常量。 | 2 |
| 74 | 73 | DUP | set to constant | 部分满足 | “所有 QoS0 消息 DUP=0”未在通用编码层做强制校验。 | 3 |
| 75 | 74 | DUP | must not be derived/computed from another field | 部分满足 | broker 转发不会传播 incoming DUP，但也未实现“重传时按状态置位”的完整机制。 | 3 |
| 76 | 75 | DUP | set to constant | 不满足 | 未发现重投递时自动将 DUP 置 1 的实现路径。 | 3 |
| 77 | 76 | DUP flag | set to constant | 部分满足 | 同 ID74：QoS0 DUP=0 在主要路径满足，但通用层不强制。 | 3 |
| 78 | 77 | DUP flag | set to constant | 不满足 | 同 ID76：Client/Server 重投递场景未见 DUP=1 自动置位。 | 3 |
| 79 | 78 | DUP flag | derived/computed from another condition | 部分满足 | 转发 DUP 不继承入站值（固定 0），但“仅按是否重传决定”仍未完整实现。 | 2 |
| 80 | 79 | encodedByte | set to X MOD 128 | 满足 | Variable Byte Integer 编码实现了 `encodedByte = X MOD 128`。 | 1 |
| 81 | 80 | encodedByte | set from next byte in stream | 满足 | 解码时 `encodedByte` 从后续字节流读取。 | 1 |
| 82 | 81 | encodedByte | set to encodedByte OR 128 | 满足 | 存在后续编码数据时执行 `encodedByte \|= 128`。 | 2 |
| 83 | 82 | flags | must equal value listed in that table | 不满足 | 接收侧固定报头 flags 未按包类型做保留位合法性校验。 | 3 |
| 84 | 83 | flags | invalid if value check fails | 不满足 | 未实现通用“invalid flags -> close connection”处理。 | 3 |
| 85 | 84 | flags | invalid if value check fails | 不满足 | 同 ID84：非法 flags 场景未覆盖到协议级断链处理。 | 3 |
| 86 | 85 | Keep Alive | validated upper bound check | 部分满足 | 客户端携带 Keep Alive 并提供 PING API，但未自动调度保证发送间隔不超时。 | 3 |
| 87 | 86 | Keep Alive | upper bound check | 部分满足 | 同 ID86：发送间隔控制主要由应用层负责。 | 3 |
| 88 | 87 | Keep Alive | validated timeout check | 满足 | 服务端实现了 1.5 倍 Keep Alive 超时断链。 | 3 |
| 89 | 88 | Keep Alive | must equal zero to turn off keep alive mechanism | 满足 | Keep Alive 为 0 时不会进入超时断链逻辑（机制关闭）。 | 1 |
| 90 | 89 | Keep Alive | must not exceed inactivity limit; invalid if value check fails | 满足 | 超过 1.5 倍 Keep Alive 无控制报文时会判定超时并断开。 | 3 |
| 91 | 90 | Keep Alive | validated range check | 满足 | Keep Alive 使用 16 位字段（最大 65535 秒）。 | 3 |
| 92 | 91 | length | must equal byte count of the UTF-8 encoded string itself | 满足 | UTF-8 字符串编码使用 2 字节长度前缀，长度为字符串字节数。 | 3 |
| 93 | 92 | length | derived/computed from another field | 满足 | Password 存在时通过长度前缀编码，长度来自实际字节数。 | 3 |
| 94 | 93 | length | validated range check | 满足 | UTF-8 字符串长度有 65535 上限且解码时做边界验证。 | 3 |
| 95 | 94 | length | derived/computed from another field | 满足 | Will Message 长度前缀来自数据长度，且不包含前缀自身长度。 | 3 |
| 96 | 95 | Packet Identifier | must equal previous value / reuse same value | 部分满足 | packet_id 在发送过程中保持调用方提供值，但未实现统一自动重发管理策略。 | 4 |
| 97 | 96 | Packet Identifier | must equal corresponding PUBLISH Packet value | 满足 | PUBACK/PUBREC/PUBREL 响应路径都复用原始 PUBLISH 的 packet_id。 | 4 |
| 98 | 97 | Packet Identifier | must be absent | 满足 | QoS0 的 PUBLISH 不编码 packet_id，解码也仅在 QoS>0 时读取。 | 3 |
| 99 | 98 | Packet Identifier | must equal corresponding SUBSCRIBE or UNSUBSCRIBE Packet value | 满足 | SUBACK/UNSUBACK 都使用对应 SUBSCRIBE/UNSUBSCRIBE 的 packet_id。 | 4 |
| 100 | 99 | Packet Identifier | must equal | 满足 | 接收端对同 packet_id 的后续 PUBLISH 仍按新发布流程处理，不依赖 DUP 位判断。 | 3 |
