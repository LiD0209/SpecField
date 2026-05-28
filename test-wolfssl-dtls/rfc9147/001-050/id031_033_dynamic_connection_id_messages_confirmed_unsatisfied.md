# DTLS 1.3 Dynamic Connection ID Messages Are Missing

## Summary

wolfSSL supports a static DTLS Connection ID extension and DTLS 1.3 unified-header CID encoding/checking. It does not implement RFC 9147 dynamic CID handshake messages: `RequestConnectionId` and `NewConnectionId`.

This affects the DTLSHandshake body selection and the NewConnectionId behaviors for `cid_immediate`, `cid_spare`, and receiver-provided CID ordering.

## Standard Requirement

Standard: [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)

Relevant section: `5.7 Handshake Protocol` and `9 Connection ID`

Relevant original English text from the standard:

```text
select (msg_type) {
    case request_connection_id: RequestConnectionId;
    case new_connection_id:     NewConnectionId;
} body;
```

```text
If usage is set to "cid_immediate", then one of the new CIDs MUST be used immediately for all future records.
```

```text
Implementations which receive more spare CIDs than they wish to maintain MAY simply discard any extra CIDs.
```

```text
Endpoints SHOULD use receiver-provided CIDs in the order they were provided.
```

The CID update rules require message parsing, a list of receiver-provided CIDs, usage handling, and selection for future record construction.

## Relevant Source Code

`wolfssl-master/wolfssl/internal.h:6644`

```c
enum HandShakeType {
    client_hello         =   1,
    server_hello         =   2,
    session_ticket       =   4,
    end_of_early_data    =   5,
    encrypted_extensions =   8,
    certificate          =  11,
    certificate_request  =  13,
    certificate_verify   =  15,
    finished             =  20,
    key_update           =  24,
};
```

No `request_connection_id` or `new_connection_id` handshake type is present.

`wolfssl-master/src/tls13.c:13174`

```c
switch (type) {
    case server_hello:
    case encrypted_extensions:
    case certificate_request:
    case session_ticket:
    case client_hello:
    case end_of_early_data:
    case certificate:
    case certificate_verify:
    case finished:
    case key_update:
        ...
}
```

The handshake dispatcher has no dynamic CID message branch.

`wolfssl-master/src/dtls.c:1297`

```c
/* For now we don't support changing the CID on a rehandshake */
if (cidSz != info->tx->length ||
        XMEMCMP(info->tx->id, input + OPAQUE8_LEN, cidSz) != 0)
    return DTLS_CID_ERROR;
```

`wolfssl-master/src/dtls.c:1372`

```c
if (cidInfo->rx != NULL) {
    WOLFSSL_MSG("wolfSSL doesn't support changing the CID during a "
                "connection");
    return WOLFSSL_FAILURE;
}
```

`wolfssl-master/src/dtls13.c:1163`

```c
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
```

The DTLS 1.3 record layer can add the current negotiated TX CID into unified headers, but this is not a dynamic NewConnectionId implementation.

## Implementation Behavior

Implemented part:

```text
connection_id extension setup and parse
current TX/RX CID storage
DTLS 1.3 unified header C bit encoding
received CID match validation
rejection when CID is present without negotiation
```

Missing part:

```text
RequestConnectionId handshake message
NewConnectionId handshake message
ConnectionIdUsage values such as cid_immediate and cid_spare
spare CID queue
receiver-provided CID ordering
future-record CID switch on cid_immediate
extra spare CID discard policy
```

## Inconsistency Reason

The standard requirement is not just that records can carry a CID. It defines dynamic post-handshake CID management. wolfSSL's existing code implements a static extension-negotiated CID and explicitly rejects in-connection CID changes through the public setter path. Therefore it cannot satisfy the NewConnectionId usage and spare-CID semantics.

## Runtime Evidence

Focused runtime command:

```text
..\build\wolfssl-dtls13-audit-tests\tests\unit.test.exe -test_dtls13_ack_order -test_dtls13_ack_overflow -test_dtls13_ack_dup_write_counter -test_dtls13_basic_connection_id -test_wolfSSL_dtls_cid_parse
```

Relevant log: `phase2_wolfssl_builtin_dtls13_tests.log`

The static CID tests pass:

```text
test_dtls13_basic_connection_id : passed
test_wolfSSL_dtls_cid_parse     : passed
```

Static symbol verification:

```text
rg -n "request_connection_id|new_connection_id|cid_immediate|cid_spare|RequestConnectionId|NewConnectionId|ConnectionIdUsage|too_many_cids_requested" wolfssl-master\src wolfssl-master\wolfssl wolfssl-master\tests
```

Relevant log: `phase2_dynamic_cid_symbol_check.log`

Result:

```text
No matches found.
```

## Impact

Peers that rely on RFC 9147 dynamic CID update cannot request or provide replacement CIDs through wolfSSL. A peer sending `NewConnectionId` or expecting immediate CID migration will not interoperate according to the RFC 9147 dynamic CID rules.

## Fix Direction

Add `RequestConnectionId` and `NewConnectionId` handshake types and parser/serializer support. Store receiver-provided CID lists with usage metadata, implement `cid_immediate` switch for future records, maintain/discard spare CIDs according to local policy, and select receiver-provided CIDs in supplied order unless a documented policy overrides it.
