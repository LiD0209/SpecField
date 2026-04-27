# wolfMQTT-master 301-336 未满足/部分满足分类

- total_reviewed: 16
- 部分满足: 12
- 不满足: 4
- 风险分布: low=0, medium=0, high=16

## 分类汇总

| 分类 | 数量 | 部分满足 | 不满足 |
|---|---:|---:|---:|
| Will Flag=0 的载荷一致性校验不足 | 4 | 4 | 0 |
| Will QoS 合法取值校验缺失 | 3 | 0 | 3 |
| Will QoS/Retain 与 Will Flag 的联动校验不足 | 5 | 5 | 0 |
| Will topic UTF-8 语义校验缺失 | 3 | 3 | 0 |
| Will topic 禁用字符校验缺失（U+0000） | 1 | 0 | 1 |

## 明细

| ID | source_idx | 状态 | 风险 | 分类 | 原因 |
|---:|---:|---|---|---|---|
| 305 | 304 | 部分满足 | high | Will Flag=0 的载荷一致性校验不足 | 可能放行 Flag 与载荷不一致的 CONNECT 报文。 |
| 306 | 305 | 部分满足 | high | Will Flag=0 的载荷一致性校验不足 | 协议一致性约束不完整。 |
| 315 | 314 | 部分满足 | high | Will QoS/Retain 与 Will Flag 的联动校验不足 | 入站 CONNECT 可能携带规范外标志位组合。 |
| 316 | 315 | 部分满足 | high | Will QoS/Retain 与 Will Flag 的联动校验不足 | 标志位一致性校验不完整。 |
| 317 | 316 | 部分满足 | high | Will QoS/Retain 与 Will Flag 的联动校验不足 | 协议位约束未被严格执行。 |
| 318 | 317 | 不满足 | high | Will QoS 合法取值校验缺失 | Will QoS 保留值可能进入后续处理路径。 |
| 319 | 318 | 不满足 | high | Will QoS 合法取值校验缺失 | 协议保留值未被拦截。 |
| 320 | 319 | 不满足 | high | Will QoS 合法取值校验缺失 | 可能导致非标准 QoS 分发行为。 |
| 322 | 321 | 部分满足 | high | Will QoS/Retain 与 Will Flag 的联动校验不足 | 入站 CONNECT 位组合校验缺失。 |
| 323 | 322 | 部分满足 | high | Will QoS/Retain 与 Will Flag 的联动校验不足 | 协议一致性约束不完整。 |
| 327 | 326 | 部分满足 | high | Will Flag=0 的载荷一致性校验不足 | 可兼容接受不符合字段出现规则的报文。 |
| 328 | 327 | 部分满足 | high | Will Flag=0 的载荷一致性校验不足 | 与协议字段出现条件存在偏差。 |
| 330 | 329 | 部分满足 | high | Will topic UTF-8 语义校验缺失 | 无法拦截 malformed UTF-8 Will topic。 |
| 333 | 332 | 部分满足 | high | Will topic UTF-8 语义校验缺失 | 仅完成长度层校验。 |
| 334 | 333 | 部分满足 | high | Will topic UTF-8 语义校验缺失 | 不能保证 UTF-8 数据严格合规。 |
| 335 | 334 | 不满足 | high | Will topic 禁用字符校验缺失（U+0000） | NUL 会破坏字符串一致性并影响后续匹配/日志。 |
