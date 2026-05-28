# DTLS 1.3 RFC9147 wolfSSL 151-187 部分/不满足分类

- 总数：4
- 状态：{'部分满足': 1, '不满足': 3}
- 风险：{'medium': 4}

| ID | Variable | Status | Standard | Comment | Evidence |
|---:|---|---|---|---|---|
| 164 | sequence_number | 部分满足 | RFC 9147 Section 5.10 Closure Alerts | wolfSSL 处理 close_notify 并终止读取，但未记录有效关闭告警的 epoch/sequence pair 来按 RFC 9147 忽略之后的更晚数据。 | wolfssl-master/src/internal.c:22186<br>wolfssl-master/src/internal.c:22226<br>wolfssl-master/src/internal.c:23654<br>wolfssl-master/src/internal.c:23664 |
| 185 | usage | 不满足 | RFC 9147 Section 9 Connection IDs | wolfSSL 仅支持协商期 Connection ID 扩展和统一头 CID 位，未实现 RFC 9147 NewConnectionId/RequestConnectionId 的 usage=cid_spare/cid_immediate 语义。 | wolfssl-master/wolfssl/ssl.h:6150<br>wolfssl-master/wolfssl/internal.h:3793<br>wolfssl-master/src/dtls13.c:1163<br>wolfssl-master/src/dtls13.c:1185<br>wolfssl-master/src/internal.c:38422 |
| 186 | usage | 不满足 | RFC 9147 Section 9 Connection IDs | wolfSSL 仅支持协商期 Connection ID 扩展和统一头 CID 位，未实现 RFC 9147 NewConnectionId/RequestConnectionId 的 usage=cid_spare/cid_immediate 语义。 | wolfssl-master/wolfssl/ssl.h:6150<br>wolfssl-master/wolfssl/internal.h:3793<br>wolfssl-master/src/dtls13.c:1163<br>wolfssl-master/src/dtls13.c:1185<br>wolfssl-master/src/internal.c:38422 |
| 187 | usage | 不满足 | RFC 9147 Section 9 Connection IDs | wolfSSL 仅支持协商期 Connection ID 扩展和统一头 CID 位，未实现 RFC 9147 NewConnectionId/RequestConnectionId 的 usage=cid_spare/cid_immediate 语义。 | wolfssl-master/wolfssl/ssl.h:6150<br>wolfssl-master/wolfssl/internal.h:3793<br>wolfssl-master/src/dtls13.c:1163<br>wolfssl-master/src/dtls13.c:1185<br>wolfssl-master/src/internal.c:38422 |

## Phase 2 复核

### 164 sequence_number
- standard_check: RFC 9147 Section 5.10 requires implementations to remember the epoch/sequence number pair of a valid received closure alert and ignore later data whose pair is after that alert.
- code_check: DoAlert records alert_history and sets closeNotify, and ProcessReply returns ZERO_RETURN on close_notify, but no source path stores close_notify curEpoch64/curSeq or compares later records against that saved pair.
- test_check: verify_wolfssl_dtls13_151_187.ps1 confirms positive DTLS 1.3 record/ACK paths and the current build flags. A packet-level post-close pair test is blocked because the local CMake build has WOLFSSL_DTLS13=no and WOLFSSL_DTLS_CID=no, but static symbol/path review confirms the missing pair gate.
- decision: confirmed_partial
- decision_reason: Generic closure handling exists, but the DTLS 1.3 pair-based ignore requirement is not implemented or exposed in the inspected paths.

### 185 usage
- standard_check: RFC 9147 Section 9 defines NewConnectionId and RequestConnectionId messages and the usage values cid_spare and cid_immediate for dynamic CID rotation.
- code_check: wolfSSL exposes RFC 9146-style Connection ID APIs and unified-header CID parsing, but repository-wide scans find no NewConnectionId, RequestConnectionId, cid_spare, or cid_immediate implementation.
- test_check: verify_wolfssl_dtls13_151_187.ps1 scanned source paths and logged ABSENT for NewConnectionId, RequestConnectionId, cid_spare, and cid_immediate. The local build has WOLFSSL_DTLS13=no and WOLFSSL_DTLS_CID=no, so no executable dynamic-CID packet test is available.
- decision: confirmed_unsatisfied
- decision_reason: The required protocol messages and usage semantics are absent; existing CID support only covers negotiated CID extension/header processing.

### 186 usage
- standard_check: RFC 9147 Section 9 defines NewConnectionId and RequestConnectionId messages and the usage values cid_spare and cid_immediate for dynamic CID rotation.
- code_check: wolfSSL exposes RFC 9146-style Connection ID APIs and unified-header CID parsing, but repository-wide scans find no NewConnectionId, RequestConnectionId, cid_spare, or cid_immediate implementation.
- test_check: verify_wolfssl_dtls13_151_187.ps1 scanned source paths and logged ABSENT for NewConnectionId, RequestConnectionId, cid_spare, and cid_immediate. The local build has WOLFSSL_DTLS13=no and WOLFSSL_DTLS_CID=no, so no executable dynamic-CID packet test is available.
- decision: confirmed_unsatisfied
- decision_reason: The required protocol messages and usage semantics are absent; existing CID support only covers negotiated CID extension/header processing.

### 187 usage
- standard_check: RFC 9147 Section 9 defines NewConnectionId and RequestConnectionId messages and the usage values cid_spare and cid_immediate for dynamic CID rotation.
- code_check: wolfSSL exposes RFC 9146-style Connection ID APIs and unified-header CID parsing, but repository-wide scans find no NewConnectionId, RequestConnectionId, cid_spare, or cid_immediate implementation.
- test_check: verify_wolfssl_dtls13_151_187.ps1 scanned source paths and logged ABSENT for NewConnectionId, RequestConnectionId, cid_spare, and cid_immediate. The local build has WOLFSSL_DTLS13=no and WOLFSSL_DTLS_CID=no, so no executable dynamic-CID packet test is available.
- decision: confirmed_unsatisfied
- decision_reason: The required protocol messages and usage semantics are absent; existing CID support only covers negotiated CID extension/header processing.