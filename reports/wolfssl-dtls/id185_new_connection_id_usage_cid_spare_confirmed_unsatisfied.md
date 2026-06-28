# NewConnectionId cid_spare Usage Is Not Implemented

## Summary

This is a confirmed unsatisfied DTLS 1.3 compliance finding in wolfSSL. RFC 9147 Section 9 defines `NewConnectionId` as a DTLS 1.3 handshake message and defines `usage = cid_spare` as a way to provide spare receiver-selected CIDs. The audited wolfSSL tree supports static CID negotiation and CID bytes in the DTLS 1.3 unified record header, but it does not implement the `NewConnectionId` message or spare-CID state.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Local standard text: `document/dtls/RFC9147.txt:2227`

Section: RFC 9147 Section 9, Connection ID Updates

```text
struct {
    ConnectionId cids<0..2^16-1>;
    ConnectionIdUsage usage;
} NewConnectionId;
```

```text
If it is set to "cid_spare", then either an existing or new CID MAY be used.
```

```text
Endpoints SHOULD use receiver-provided CIDs in the order they were provided.
Implementations which receive more spare CIDs than they wish to maintain MAY
simply discard any extra CIDs.
```

The requirement is not just that CID bytes can appear in the record header. A DTLS 1.3 endpoint that receives `NewConnectionId(usage = cid_spare)` needs a parser for the message and state capable of storing or selecting from the receiver-provided spare CIDs.

## Relevant Source Code

`wolfssl-master/wolfssl/internal.h:6057`

```c
typedef struct CIDInfo {
    ConnectionID* tx;
    ConnectionID* rx;
    byte negotiated : 1;
} CIDInfo;
```

`CIDInfo` stores one current transmit CID and one current receive CID. It has no spare CID list, no `ConnectionIdUsage` field, and no queue of receiver-provided CIDs.

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
```

The RFC 9147 DTLS 1.3 handshake types `request_connection_id = 9` and `new_connection_id = 10` are absent.

`wolfssl-master/src/tls13.c:13740`

```c
default:
    WOLFSSL_MSG("Unknown handshake message type");
    ret = UNKNOWN_HANDSHAKE_TYPE;
    break;
```

The TLS 1.3/DTLS 1.3 handshake dispatcher has no `new_connection_id` case, so a peer-sent `NewConnectionId` cannot reach a parser or spare-CID update path.

`wolfssl-master/src/dtls13.c:1170`

```c
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
{
    byte cidSz;
    int ret;

    if (!wolfSSL_dtls_cid_is_enabled(ssl))
        return 0;
```

This code adds the currently configured transmit CID to outgoing DTLS 1.3 records. It does not process a `NewConnectionId` message or store spare CIDs.

## Implementation Behavior

wolfSSL implements a static CID model:

- it can negotiate/configure the `connection_id` extension;
- it can include a configured CID in the DTLS 1.3 unified record header;
- it can reject records whose CID does not match the configured receive CID.

It does not implement the dynamic RFC 9147 Section 9 model:

- no `NewConnectionId` handshake type;
- no `ConnectionIdUsage` enum;
- no `cid_spare` parser or state transition;
- no storage for multiple spare receiver-provided CIDs.

## Inconsistency Reason

RFC 9147 requires `NewConnectionId(usage = cid_spare)` to carry spare CIDs that the peer may use later. wolfSSL only has static current-CID storage and record-header CID handling. Because no `NewConnectionId` parser or spare-CID state exists, wolfSSL cannot apply the RFC 9147 `cid_spare` semantics.

## Runtime Evidence

Focused verification script: `test-wolfssl-dtls/rfc9147/151-187/verify_wolfssl_dtls13_151_187.ps1`

Log: `test-wolfssl-dtls/rfc9147/151-187/verify_wolfssl_dtls13_151_187.log`

Command executed:

```text
powershell -NoProfile -ExecutionPolicy Bypass -File test-wolfssl-dtls/rfc9147/151-187/verify_wolfssl_dtls13_151_187.ps1
```

Key runtime output:

```text
== Dynamic CID message symbol scan ==
ABSENT request_connection_id
ABSENT new_connection_id
ABSENT RequestConnectionId
ABSENT NewConnectionId
ABSENT ConnectionIdUsage
ABSENT cid_spare
ABSENT cid_immediate
ABSENT num_cids
ABSENT too_many_cids_requested

== Static CID positive-control scans ==
PASS CIDInfo current-CID storage
wolfssl-master/wolfssl/internal.h:6058:    ConnectionID* tx;
wolfssl-master/wolfssl/internal.h:6059:    ConnectionID* rx;
PASS DTLS 1.3 unified header adds CID
wolfssl-master/src/dtls13.c:1183:    *flags |= DTLS13_CID_BIT;

== Dispatcher checks ==
PASS dispatcher unknown-message fallback returns UNKNOWN_HANDSHAKE_TYPE
ABSENT case request_connection_id
ABSENT case new_connection_id

== Decision ==
PASS dynamic CID update support is absent in wolfssl-master: the static CID extension/header paths are present, but no RequestConnectionId/NewConnectionId message types, ConnectionIdUsage values, num_cids handling, or cid_spare/cid_immediate state machine were found.
```

## Impact

A peer that sends `NewConnectionId(usage = cid_spare)` cannot populate a spare CID pool in wolfSSL. This limits interoperability with DTLS 1.3 peers that rely on RFC 9147 dynamic CID refresh for mobility, multipath use, or privacy-preserving CID rotation.

## Fix Direction

Add `new_connection_id = 10` to the DTLS 1.3 handshake type handling, implement `NewConnectionId` parsing, add `ConnectionIdUsage` with `cid_spare`, and extend the CID state to keep receiver-provided spare CIDs in RFC order. Add tests that receive `NewConnectionId(usage = cid_spare)` and verify that spare CIDs are stored, selectable, and bounded by implementation limits.
