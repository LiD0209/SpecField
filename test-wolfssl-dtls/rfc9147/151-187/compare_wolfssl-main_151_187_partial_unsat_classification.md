# DTLS 1.3 RFC9147 wolfSSL 151-187 partial/[non-English text removed]satisfiedcategory

- [non-English text removed]：4
- status：{'partialsatisfied': 1, '[non-English text removed]satisfied': 3}
- risk：{'medium': 4}

| ID | Variable | Status | Standard | Comment | Evidence |
|---:|---|---|---|---|---|
| 164 | sequence_number | partialsatisfied | RFC 9147 Section 5.10 Closure Alerts | wolfSSL processing close_notify [non-English text removed] epoch/sequence pair [non-English text removed]。 | wolfssl-master/src/internal.c:22186<br>wolfssl-master/src/internal.c:22226<br>wolfssl-master/src/internal.c:23654<br>wolfssl-master/src/internal.c:23664 |
| 185 | usage | [non-English text removed]satisfied | RFC 9147 Section 9 Connection IDs | wolfSSL [non-English text removed] RFC 9147 NewConnectionId/RequestConnectionId [non-English text removed] usage=cid_spare/cid_immediate semantic。 | wolfssl-master/wolfssl/ssl.h:6150<br>wolfssl-master/wolfssl/internal.h:3793<br>wolfssl-master/src/dtls13.c:1163<br>wolfssl-master/src/dtls13.c:1185<br>wolfssl-master/src/internal.c:38422 |
| 186 | usage | [non-English text removed]satisfied | RFC 9147 Section 9 Connection IDs | wolfSSL [non-English text removed] RFC 9147 NewConnectionId/RequestConnectionId [non-English text removed] usage=cid_spare/cid_immediate semantic。 | wolfssl-master/wolfssl/ssl.h:6150<br>wolfssl-master/wolfssl/internal.h:3793<br>wolfssl-master/src/dtls13.c:1163<br>wolfssl-master/src/dtls13.c:1185<br>wolfssl-master/src/internal.c:38422 |
| 187 | usage | [non-English text removed]satisfied | RFC 9147 Section 9 Connection IDs | wolfSSL [non-English text removed] RFC 9147 NewConnectionId/RequestConnectionId [non-English text removed] usage=cid_spare/cid_immediate semantic。 | wolfssl-master/wolfssl/ssl.h:6150<br>wolfssl-master/wolfssl/internal.h:3793<br>wolfssl-master/src/dtls13.c:1163<br>wolfssl-master/src/dtls13.c:1185<br>wolfssl-master/src/internal.c:38422 |

## Phase 2 [non-English text removed]

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