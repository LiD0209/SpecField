# BoringSSL DTLS 1.2 001-050 部分满足/不满足分类

## missing server HelloVerifyRequest cookie generation/validation path (7)

| ID | 状态 | 风险 | 复核结论 | 说明 |
|---:|---|---|---|---|
| 021 | 不满足 | medium | confirmed_unsatisfied | The RFC requirement is server behavior. BoringSSL's production server path does not implement the HelloVerifyRequest cookie exchange; therefore this item is confirmed unsatisfied. |
| 022 | 不满足 | medium | confirmed_unsatisfied | The RFC requirement is server behavior. BoringSSL's production server path does not implement the HelloVerifyRequest cookie exchange; therefore this item is confirmed unsatisfied. |
| 024 | 不满足 | medium | confirmed_unsatisfied | The RFC requirement is server behavior. BoringSSL's production server path does not implement the HelloVerifyRequest cookie exchange; therefore this item is confirmed unsatisfied. |
| 026 | 不满足 | medium | confirmed_unsatisfied | The RFC requirement is server behavior. BoringSSL's production server path does not implement the HelloVerifyRequest cookie exchange; therefore this item is confirmed unsatisfied. |
| 029 | 不满足 | medium | confirmed_unsatisfied | The RFC requirement is server behavior. BoringSSL's production server path does not implement the HelloVerifyRequest cookie exchange; therefore this item is confirmed unsatisfied. |
| 030 | 不满足 | medium | confirmed_unsatisfied | The RFC requirement is server behavior. BoringSSL's production server path does not implement the HelloVerifyRequest cookie exchange; therefore this item is confirmed unsatisfied. |
| 031 | 不满足 | medium | confirmed_unsatisfied | The RFC requirement is server behavior. BoringSSL's production server path does not implement the HelloVerifyRequest cookie exchange; therefore this item is confirmed unsatisfied. |

## test runner parser keeps obsolete 32-byte HelloVerifyRequest limit (1)

| ID | 状态 | 风险 | 复核结论 | 说明 |
|---:|---|---|---|---|
| 023 | 部分满足 | low | confirmed_partial | The production client path satisfies the 255-byte requirement, but the in-repo DTLS peer runner contradicts it. This is a confirmed partial conformance issue for repository test/interoperability behavior, not for the shipped client parser. |

## DTLS 1.2 old epoch retention not implemented (2)

| ID | 状态 | 风险 | 复核结论 | 说明 |
|---:|---|---|---|---|
| 040 | 部分满足 | medium | confirmed_partial | The implementation has robust newer-epoch retention for DTLS 1.3, but not the DTLS 1.2 previous-epoch retention expected by RFC 6347. This is confirmed partial. |
| 041 | 部分满足 | medium | confirmed_partial | The implementation has robust newer-epoch retention for DTLS 1.3, but not the DTLS 1.2 previous-epoch retention expected by RFC 6347. This is confirmed partial. |
