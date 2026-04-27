# wolfMQTT-master 051-100 未满足/部分满足分类

- total_reviewed: 24
- 部分满足: 16
- 不满足: 8
- 风险分布: low=0, medium=16, high=8

## 分类汇总

| 分类 | 数量 | 部分满足 | 不满足 |
|---|---:|---:|---:|
| CONNACK Flags接收校验不足 | 1 | 1 | 0 |
| CONNECT失败响应覆盖不完整 | 2 | 2 | 0 |
| ClientId拒绝返回码不符合规范 | 4 | 2 | 2 |
| DUP重传置位缺失 | 2 | 0 | 2 |
| DUP重传语义实现不完整 | 2 | 2 | 0 |
| DUP首发语义约束不完整 | 6 | 6 | 0 |
| Fixed Header Flags校验缺失 | 3 | 0 | 3 |
| KeepAlive客户端责任未自动保障 | 2 | 2 | 0 |
| Packet Identifier重发语义不完整 | 1 | 1 | 0 |
| Protocol Level校验缺失 | 1 | 0 | 1 |

## 明细

| ID | source_idx | 状态 | 风险 | 分类 | 说明 |
|---:|---:|---|---|---|---|
| 51 | 50 | 不满足 | high | ClientId拒绝返回码不符合规范 | 规范要求该场景返回 0x02 并断链，当前实现会进入接受/分配路径。 |
| 55 | 54 | 不满足 | high | ClientId拒绝返回码不符合规范 | Identifier rejected 约束未命中该条件分支。 |  ( 0x02，也就是 Identifier rejected)
| 59 | 58 | 部分满足 | medium | ClientId拒绝返回码不符合规范 | 并非所有应拒绝 ClientId 的场景都会回 0x02。 |
| 60 | 59 | 部分满足 | medium | ClientId拒绝返回码不符合规范 | 拒绝码语义落地存在条件差异。 |  （前面已经写过相关的内容了）


| 52 | 51 | 部分满足 | medium | CONNECT失败响应覆盖不完整 | decode 失败等路径会直接断开，未总是“发送非零返回码”。 |  （判断错误，这条满足）
| 62 | 61 | 不满足 | high | Protocol Level校验缺失 | 缺少“unsupported level -> 0x01 + disconnect”的明确实现。 |  （有问题）
| 63 | 62 | 部分满足 | medium | CONNACK Flags接收校验不足 | 编码满足约束，解码未验证保留位合法性。 |   （client没有校验CONNACK flags）
| 66 | 65 | 部分满足 | medium | CONNECT失败响应覆盖不完整 | 效果上有 close-no-CONNACK，但缺少显式 rule-level 分支。 |  （满足）

| 70 | 69 | 部分满足 | medium | DUP首发语义约束不完整 | 核心路径符合，但库 API 级约束不严格。 |
| 71 | 70 | 部分满足 | medium | DUP首发语义约束不完整 | 缺少全局“首发必为 0”的硬约束。 |
| 72 | 71 | 部分满足 | medium | DUP首发语义约束不完整 | 通用编码路径未封死异常取值。 |
| 73 | 72 | 部分满足 | medium | DUP首发语义约束不完整 | 依赖调用约定而非统一约束。 |
| 74 | 73 | 部分满足 | medium | DUP首发语义约束不完整 | 库允许调用方构造不规范组合。 |
| 77 | 76 | 部分满足 | medium | DUP首发语义约束不完整 | 缺少库级硬性约束。 |  （属于一组）



| 76 | 75 | 不满足 | high | DUP重传置位缺失 | 规范要求重投递必须 DUP=1，代码无对应自动机制。 |
| 78 | 77 | 不满足 | high | DUP重传置位缺失 | 无显式重投递 DUP 置位策略。 |  （确定是不一致，标准要求重投递 PUBLISH 时 DUP=1，但 wolfMQTT 没有自动重投递并自动置位 DUP 的机制。）

| 75 | 74 | 部分满足 | medium | DUP重传语义实现不完整 | 做到了“独立于入站 DUP”，但“仅重传置 1”未形成闭环。 |
| 79 | 78 | 部分满足 | medium | DUP重传语义实现不完整 | 独立性满足，重传状态机不足。 | （简单issue，部分满足） 

| 83 | 82 | 不满足 | high | Fixed Header Flags校验缺失 | 仅校验 packet type，缺少 flags 合法值约束。 |
| 84 | 83 | 不满足 | high | Fixed Header Flags校验缺失 | 缺少对非法 flags 的统一拒绝断链。 |
| 85 | 84 | 不满足 | high | Fixed Header Flags校验缺失 | 保留位/非法位值缺少接收端严格校验。 |  （前面已经描述，id4，5，8，9，11等）

| 183 | 182 | 不满足 | high | PUBLISH QoS bits 非法值校验缺失 | QoS=3 可进入处理路径。 |
| 184 | 183 | 不满足 | high | PUBLISH QoS bits 非法值校验缺失 | 固定头解析不校验 qos bits 合法性。 |
| 185 | 184 | 不满足 | high | PUBLISH QoS bits 非法值校验缺失 | 缺少协议违规断开分支。 |
| 186 | 185 | 不满足 | high | PUBLISH QoS bits 非法值校验缺失 | 缺少 QoS bits=3 的接收拒绝逻辑。 | （不满足）


| 86 | 85 | 部分满足 | medium | KeepAlive客户端责任未自动保障 | 能力存在，依赖上层应用主动调用与调度。 |
| 87 | 86 | 部分满足 | medium | KeepAlive客户端责任未自动保障 | 库未内建 keepalive 定时发送策略。 |   (不满足)


