# wolfSSL DTLS 1.2 Partial/Unsatisfied Classification 051-098

- 总数: 2
- 部分满足: 2
- 不满足: 0
- Phase 2 confirmed_partial: 0
- Phase 2 confirmed_unsatisfied: 0
- Phase 2 false_positive: 2

## RFC6347 HelloVerifyRequest server_version equality text conflicts with DTLS 1.2 guidance

- 76: 部分满足 -> false_positive。如果按 page 16 孤立句子判断，wolfSSL 不执行 HVR/ServerHello version equality；但 RFC 6347 同节对 DTLS 1.2 的实际要求是 HVR version 仅表示包格式且不参与版本协商，errata 也说明相等性文本应删除。因此该项不升级为 confirmed_partial/confirmed_unsatisfied。
- 80: 部分满足 -> false_positive。如果按 page 16 孤立句子判断，wolfSSL 不执行 HVR/ServerHello version equality；但 RFC 6347 同节对 DTLS 1.2 的实际要求是 HVR version 仅表示包格式且不参与版本协商，errata 也说明相等性文本应删除。因此该项不升级为 confirmed_partial/confirmed_unsatisfied。
