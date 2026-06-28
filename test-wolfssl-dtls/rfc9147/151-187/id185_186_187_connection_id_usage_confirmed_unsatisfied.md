# DTLS 1.3 Dynamic Connection ID Updates Are Not Implemented

## Summary

This report covers IDs 185, 186, and 187.

The finding is about RFC 9147 Section 9 dynamic Connection ID updates, not about basic DTLS CID negotiation. wolfSSL supports a static/configured DTLS CID: it can negotiate the `connection_id` extension, put a negotiated CID into the DTLS 1.3 unified record header, and reject records with the wrong CID.

The missing part is the post-handshake dynamic CID mechanism. The audited wolfSSL source does not define or dispatch `RequestConnectionId` or `NewConnectionId`, does not define `ConnectionIdUsage`, and does not implement the `cid_immediate`, `cid_spare`, or `num_cids` state machine.

Conclusion: IDs 185, 186, and 187 are **confirmed unsatisfied**. This is a static-CID-only implementation gap against RFC 9147 dynamic CID update requirements.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Local standard text: `document/dtls/RFC9147.txt`

Relevant section: RFC 9147 Section 9, `Connection ID Updates`.

Relevant normative text:

```text
If the client and server have negotiated the "connection_id"
extension [RFC9146], either side can send a new CID that it wishes
the other side to use in a NewConnectionId message.
```

```text
enum {
    cid_immediate(0), cid_spare(1), (255)
} ConnectionIdUsage;

opaque ConnectionId<0..2^8-1>;

struct {
    ConnectionId cids<0..2^16-1>;
    ConnectionIdUsage usage;
} NewConnectionId;
```

```text
usage:  Indicates whether the new CIDs should be used immediately or
   are spare.  If usage is set to "cid_immediate", then one of the
   new CIDs MUST be used immediately for all future records.  If it
   is set to "cid_spare", then either an existing or new CID MAY be
   used.
```

```text
struct {
  uint8 num_cids;
} RequestConnectionId;

num_cids:  The number of CIDs desired.

Endpoints SHOULD respond to RequestConnectionId by sending a
NewConnectionId with usage "cid_spare" containing num_cids CIDs as
soon as possible.
```

RFC 9147 Appendix A.2 also lists these DTLS 1.3 handshake body alternatives:

```text
case request_connection_id: RequestConnectionId;
case new_connection_id:     NewConnectionId;
```

In protocol terms, RFC 9147 expects DTLS 1.3 peers to process CID update messages after the connection has already been established. Static `connection_id` extension negotiation alone is not enough.

## Relevant Source Code

### Static CID Support Exists

`wolfssl-master/wolfssl/internal.h:6047`

```c
typedef struct ConnectionID {
    byte length;
    byte id[];
} ConnectionID;
```

`wolfssl-master/wolfssl/internal.h:6057`

```c
typedef struct CIDInfo {
    ConnectionID* tx;
    ConnectionID* rx;
    byte negotiated : 1;
} CIDInfo;
```

`CIDInfo` stores one transmit CID and one receive CID. It does not store a spare CID list, a receiver-provided CID queue, a `usage` value, or outstanding `RequestConnectionId` state.

`wolfssl-master/src/dtls.c:1264`

```c
int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,
    byte isRequest)
```

This parser supports the `connection_id` extension negotiation path.

`wolfssl-master/src/dtls13.c:1170`

```c
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
```

The DTLS 1.3 sender can add CID bytes to the unified record header.

`wolfssl-master/src/dtls13.c:1192`

```c
static int Dtls13UnifiedHeaderParseCID(WOLFSSL* ssl, byte flags,
    const byte* input, word16 inputSize, word16* idx)
```

The receiver validates an incoming record CID. These paths prove static CID support, but they do not implement dynamic Section 9 updates.

### Dynamic CID Handshake Types Are Missing

`wolfssl-master/wolfssl/internal.h:6753`

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

`wolfssl-master/src/tls13.c:13741`

```c
WOLFSSL_MSG("Unknown handshake message type");
ret = UNKNOWN_HANDSHAKE_TYPE;
```

The TLS 1.3 handshake dispatcher has cases for ordinary TLS 1.3 post-handshake messages such as `session_ticket`, `certificate_request`, `finished`, and `key_update`, but no `case request_connection_id` and no `case new_connection_id`. A peer-sent dynamic CID update message therefore cannot reach a parser or state transition.

### CID Usage Semantics Are Missing

Repository-wide source checks found no protocol symbols or state for:

```text
ConnectionIdUsage
cid_spare
cid_immediate
num_cids
RequestConnectionId
NewConnectionId
```

Without those symbols and handlers, wolfSSL cannot implement the RFC 9147 behaviors for parsing `NewConnectionId.usage`, switching immediately on `cid_immediate`, storing spare CIDs on `cid_spare`, parsing `RequestConnectionId.num_cids`, or responding with `NewConnectionId(usage = cid_spare)`.

### Existing API Rejects In-Connection CID Changes

`wolfssl-master/src/dtls.c:1383`

```c
WOLFSSL_MSG("wolfSSL doesn't support changing the CID during a "
            "connection");
return WOLFSSL_FAILURE;
```

This API behavior reinforces the static-CID conclusion: wolfSSL supports setting/negotiating a CID, but does not support changing the CID dynamically during the connection.

## Implementation Behavior

Implemented behavior:

| Area | wolfSSL behavior |
|---|---|
| `connection_id` extension negotiation | Implemented |
| DTLS 1.3 unified record header CID bit and CID bytes | Implemented |
| Incoming CID mismatch rejection | Implemented |
| Static DTLS 1.3 CID API/test path | Implemented |

Missing behavior:

| RFC 9147 Section 9 behavior | wolfSSL audited behavior |
|---|---|
| `NewConnectionId` post-handshake message | Not defined or dispatched |
| `RequestConnectionId` post-handshake message | Not defined or dispatched |
| `ConnectionIdUsage` enum | Not defined |
| `cid_immediate` switch semantics | Not implemented |
| `cid_spare` storage semantics | Not implemented |
| `RequestConnectionId.num_cids` parsing | Not implemented |
| `NewConnectionId(usage = cid_spare)` response | Not implemented |
| Spare CID list / receiver-provided CID queue | Not present in `CIDInfo` |

## Inconsistency Reason

RFC 9147 requires dynamic CID update messages after the `connection_id` extension has been negotiated. The implementation only supports the negotiated/static CID that is already configured for the connection.

This means wolfSSL can use a CID in records, but it cannot process or generate the post-handshake messages that update CIDs:

```text
RFC 9147: dynamic CID update messages and usage semantics are part of DTLS 1.3.
wolfSSL: only static CID negotiation/header usage is implemented.
```

Therefore IDs 185, 186, and 187 are not the same kind of issue as close-notify ordering. They are a distinct dynamic CID feature gap.

## Static Evidence

Source-behavior harness:

`test-wolfssl-dtls/rfc9147/151-187/repro_usage_185_186_187_source_check.c`

Observed log:

`test-wolfssl-dtls/rfc9147/151-187/repro_usage_185_186_187_source_check.log`

Selected results:

```text
PASS CIDInfo has tx CID pointer
PASS CIDInfo has rx CID pointer
PASS DTLS 1.3 unified header can add CID
PASS DTLS 1.3 unified header checks received CID
PASS no request_connection_id handshake enum
PASS no new_connection_id handshake enum
PASS no ConnectionIdUsage enum
PASS no cid_spare usage
PASS no cid_immediate usage
PASS no num_cids field
PASS no RequestConnectionId response code
PASS CID API rejects changing CID during connection
```

This is a compiled source-behavior check. It proves both sides of the finding: static CID support exists, while dynamic CID update support is absent.

## Impact

wolfSSL peers can use a configured or negotiated static DTLS CID, but they cannot interoperate with peers that rely on RFC 9147 Section 9 dynamic CID updates.

Concrete effects:

| Peer behavior | wolfSSL effect |
|---|---|
| Sends `NewConnectionId(usage = cid_immediate)` | wolfSSL has no parser/handler to switch CID immediately |
| Sends `NewConnectionId(usage = cid_spare)` | wolfSSL has no spare CID pool to store the offered CIDs |
| Sends `RequestConnectionId(num_cids = N)` | wolfSSL has no response path to send `NewConnectionId(usage = cid_spare)` |

This can affect CID refresh, mobility, multipath behavior, and privacy properties that RFC 9147 Section 9 is designed to support.

## Fix Direction

1. Add `request_connection_id = 9` and `new_connection_id = 10` to the DTLS/TLS handshake type enum.
2. Add parsers and serializers for `RequestConnectionId` and `NewConnectionId`.
3. Add a `ConnectionIdUsage` enum with `cid_immediate` and `cid_spare`.
4. Extend CID state beyond a single `tx`/`rx` pair so receiver-provided spare CIDs and outstanding requests can be tracked.
5. Implement `cid_immediate` by switching to one of the new CIDs for all future records.
6. Implement `cid_spare` by storing usable spare CIDs.
7. Implement `RequestConnectionId` response behavior with `NewConnectionId(usage = cid_spare)`.
8. Add tests for dynamic CID parsing, immediate switch, spare CID storage, excessive requests, missing-CID-negotiation errors, and outstanding-request restrictions.
