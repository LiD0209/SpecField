# DTLS 1.3 ConnectionIdUsage and RequestConnectionId Response Are Not Implemented

## Summary

This report covers IDs 185, 186, and 187.

RFC 9147 defines dynamic DTLS 1.3 Connection ID update messages. `NewConnectionId` carries a `usage` field with two defined semantics: `cid_immediate` and `cid_spare`. `RequestConnectionId` carries `num_cids`, and endpoints should respond by sending `NewConnectionId` with `usage = cid_spare`.

wolfSSL has static DTLS CID support. It can negotiate/configure a CID with the `connection_id` extension and can carry that CID in the DTLS 1.3 unified record header. However, the audited source does not define or dispatch `RequestConnectionId` or `NewConnectionId`, does not define `ConnectionIdUsage`, and has no `cid_spare`, `cid_immediate`, or `num_cids` state machine.

This confirms IDs 185, 186, and 187 as **unsatisfied**. The root cause is the same as the earlier dynamic CID finding for IDs 145 and 146: wolfSSL implements static CID negotiation/header use, but not RFC 9147 Section 9 dynamic CID updates.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: RFC 9147 Section 9, `Connection ID Updates`.

Relevant original English text from RFC 9147:

```text
If the client and server have negotiated the "connection_id" extension [RFC9146], either side can send a new CID that it wishes the other side to use in a NewConnectionId message.
```

```text
enum {
    cid_immediate(0), cid_spare(1), (255)
} ConnectionIdUsage;
```

```text
struct {
    ConnectionId cids<0..2^16-1>;
    ConnectionIdUsage usage;
} NewConnectionId;
```

```text
usage:  Indicates whether the new CIDs should be used immediately or are spare.
```

```text
If usage is set to "cid_immediate", then one of the new CIDs MUST be used immediately for all future records.
```

```text
If it is set to "cid_spare", then either an existing or new CID MAY be used.
```

```text
struct {
  uint8 num_cids;
} RequestConnectionId;
```

```text
num_cids:  The number of CIDs desired.
```

```text
Endpoints SHOULD respond to RequestConnectionId by sending a NewConnectionId with usage "cid_spare" containing num_cids CIDs as soon as possible.
```

RFC 9147 Appendix A.2 also lists these DTLS 1.3 handshake message body alternatives:

```text
case request_connection_id: RequestConnectionId;
case new_connection_id:     NewConnectionId;
```

These are post-handshake protocol messages. Static CID negotiation through the `connection_id` extension is not enough to satisfy the Section 9 update semantics.

## Relevant Source Code

### Static CID Support Exists

`D:\project\wolfssl-master\wolfssl\internal.h:6042`

```c
typedef struct ConnectionID {
    byte length;
    byte id[];
} ConnectionID;
```

`D:\project\wolfssl-master\wolfssl\internal.h:6052`

```c
typedef struct CIDInfo {
    ConnectionID* tx;
    ConnectionID* rx;
    byte negotiated : 1;
} CIDInfo;
```

`CIDInfo` stores one current transmit CID and one current receive CID. It does not store a spare CID list, receiver-provided CID queue, usage value, or outstanding RequestConnectionId state.

`D:\project\wolfssl-master\src\dtls.c:1258`

```c
int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,
    byte isRequest)
```

The `connection_id` extension parser can negotiate the current transmit CID:

```c
else if (cidSz > 0) {
    ConnectionID* id = (ConnectionID*)XMALLOC(sizeof(*id) + cidSz,
            ssl->heap, DYNAMIC_TYPE_TLSX);
    ...
    info->tx = id;
}
```

`D:\project\wolfssl-master\src\dtls13.c:1170`

```c
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
```

The DTLS 1.3 unified header sender can include a negotiated CID:

```c
*flags |= DTLS13_CID_BIT;
ret = wolfSSL_dtls_cid_get_tx(ssl, out + *idx, cidSz);
```

`D:\project\wolfssl-master\src\dtls13.c:1192`

```c
static int Dtls13UnifiedHeaderParseCID(WOLFSSL* ssl, byte flags,
    const byte* input, word16 inputSize, word16* idx)
```

The receiver checks that a record's CID matches the configured receive CID:

```c
if (!DtlsCIDCheck(ssl, input + *idx, inputSize - *idx)) {
    WOLFSSL_MSG("Not matching or wrong CID, ignoring");
    return DTLS_CID_ERROR;
}
```

This is valid static CID support, but it is not dynamic CID update support.

### Dynamic CID Handshake Types Are Missing

`D:\project\wolfssl-master\wolfssl\internal.h:6752`

```c
enum HandShakeType {
    hello_request        =   0,
    client_hello         =   1,
    server_hello         =   2,
    hello_verify_request =   3,
    session_ticket       =   4,
    end_of_early_data    =   5,
    hello_retry_request  =   6,
    encrypted_extensions =   8,
    certificate          =  11,
    certificate_request  =  13,
    certificate_verify   =  15,
    finished             =  20,
    key_update           =  24,
    message_hash         = 254,
    no_shake             = 255
};
```

There is no `request_connection_id = 9` and no `new_connection_id = 10`.

In `D:\project\wolfssl-master\src\tls13.c`, `DoTls13HandShakeMsgType` dispatches supported TLS 1.3 handshake messages. It has cases for `session_ticket`, `certificate_request`, `finished`, and `key_update`, but no `case request_connection_id` and no `case new_connection_id`. Unknown messages fall to:

```c
default:
    WOLFSSL_MSG("Unknown handshake message type");
    ret = UNKNOWN_HANDSHAKE_TYPE;
    break;
```

Therefore a peer-sent `RequestConnectionId` or `NewConnectionId` cannot reach a parser or state transition.

### cid_spare and cid_immediate Semantics Are Missing

Repository-wide source checks found no protocol symbols or state for:

```text
ConnectionIdUsage
cid_spare
cid_immediate
num_cids
RequestConnectionId
NewConnectionId
```

Without those symbols, wolfSSL cannot implement:

| RFC 9147 behavior | wolfSSL audited behavior |
|---|---|
| Parse `NewConnectionId.usage` | No `NewConnectionId` parser |
| Apply `cid_immediate` by switching to one of the new CIDs for all future records | No `cid_immediate` state or handler |
| Store `cid_spare` CIDs for later use | `CIDInfo` has only one `tx` and one `rx` pointer |
| Parse `RequestConnectionId.num_cids` | No `RequestConnectionId` parser |
| Respond with `NewConnectionId(usage = cid_spare)` | No sender or response state machine |

### Existing API Rejects In-Connection CID Changes

`D:\project\wolfssl-master\src\dtls.c:1364`

```c
int wolfSSL_dtls_cid_set(WOLFSSL* ssl, unsigned char* cid, unsigned int size)
```

`D:\project\wolfssl-master\src\dtls.c:1375`

```c
if (cidInfo->rx != NULL) {
    WOLFSSL_MSG("wolfSSL doesn't support changing the CID during a "
                "connection");
    return WOLFSSL_FAILURE;
}
```

The extension parser also rejects changing the negotiated transmit CID:

```c
/* For now we don't support changing the CID on a rehandshake */
if (cidSz != info->tx->length ||
        XMEMCMP(info->tx->id, input + OPAQUE8_LEN, cidSz) != 0)
    return DTLS_CID_ERROR;
```

This reinforces the conclusion that wolfSSL's CID model is static/configured, not the dynamic Section 9 update model.

## Existing wolfSSL Test Coverage

`D:\project\wolfssl-master\tests\api\test_dtls.c` contains `test_dtls13_basic_connection_id`. That test enables CID, configures client/server CIDs with `wolfSSL_dtls_cid_set`, and verifies that DTLS 1.3 traffic carries and validates the configured CID.

This proves basic static CID support. It does not send `RequestConnectionId`, parse `num_cids`, generate `NewConnectionId`, or assert `usage = cid_spare` / `usage = cid_immediate` behavior.

## Runtime Evidence

Compiled source-behavior harness:

`D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\151-187\repro_usage_185_186_187_source_check.c`

Observed result:

```text
Conclusion: PASS - source behavior confirms IDs 185/186/187 are unsatisfied: wolfSSL supports static DTLS CID negotiation/header parsing, but it has no RequestConnectionId/NewConnectionId message types, no cid_spare/cid_immediate usage semantics, and no response state machine.
```

Selected assertions:

```text
PASS CIDInfo has tx CID pointer                                           contains "ConnectionID* tx;"
PASS CIDInfo has rx CID pointer                                           contains "ConnectionID* rx;"
PASS DTLS 1.3 unified header can add CID                                  contains "*flags |= DTLS13_CID_BIT;"
PASS no request_connection_id handshake enum                              does not contain "request_connection_id"
PASS no new_connection_id handshake enum                                  does not contain "new_connection_id"
PASS no ConnectionIdUsage enum                                            does not contain "ConnectionIdUsage"
PASS no cid_spare usage                                                   does not contain "cid_spare"
PASS no cid_immediate usage                                               does not contain "cid_immediate"
PASS no RequestConnectionId response code                                 does not contain "RequestConnectionId"
PASS CID API rejects changing CID during connection                       contains "wolfSSL doesn't support changing the CID during a "
```

This is a compiled and executed source-behavior check. It confirms the implemented static CID path and the missing dynamic usage/update path.

## Inconsistency Reason

Implemented behavior:

| Area | wolfSSL behavior |
|---|---|
| `connection_id` extension negotiation | Implemented. |
| DTLS 1.3 unified header CID bit and CID bytes | Implemented. |
| CID mismatch rejection | Implemented. |
| Static CID API and tests | Implemented. |

Missing behavior:

| RFC 9147 Section 9 behavior | wolfSSL audited behavior |
|---|---|
| `NewConnectionId` message | Not defined or dispatched. |
| `RequestConnectionId` message | Not defined or dispatched. |
| `ConnectionIdUsage` enum | Not defined. |
| `cid_spare` semantics | Not implemented. |
| `cid_immediate` semantics | Not implemented. |
| `RequestConnectionId.num_cids` response | Not implemented. |
| Spare CID list / receiver-provided CID queue | Not present in `CIDInfo`. |

Thus IDs 185, 186, and 187 are real unsatisfied findings.

## Impact

wolfSSL peers can use a configured or negotiated static DTLS CID, but they cannot interoperate with peers that use RFC 9147 dynamic CID update messages. In particular:

- a peer sending `NewConnectionId(usage = cid_immediate)` cannot force an immediate CID switch;
- a peer sending `NewConnectionId(usage = cid_spare)` cannot populate a spare CID pool;
- a peer sending `RequestConnectionId(num_cids = N)` will not receive the expected `NewConnectionId(usage = cid_spare)` response.

This affects mobility, multipath, privacy, and CID refresh behavior described by RFC 9147 Section 9.

## Suggested Fix Direction

1. Add `request_connection_id = 9` and `new_connection_id = 10` to the TLS/DTLS handshake type enum.
2. Add parsers and serializers for `RequestConnectionId` and `NewConnectionId`.
3. Add a `ConnectionIdUsage` enum with `cid_immediate` and `cid_spare`.
4. Extend `CIDInfo` or a new DTLS 1.3 CID state object to maintain receiver-provided spare CID lists and outstanding request state.
5. Implement `RequestConnectionId` response behavior by sending `NewConnectionId` with `usage = cid_spare`.
6. Add tests for `cid_immediate`, `cid_spare`, excessive `num_cids`, no-CID-negotiated unexpected-message errors, and outstanding-request restrictions.
