# RequestConnectionId Response with cid_spare Is Not Implemented

## Summary

This is a confirmed unsatisfied DTLS 1.3 compliance finding in wolfSSL. RFC 9147 Section 9 defines `RequestConnectionId`, whose `num_cids` field asks the peer for new CIDs. Endpoints should respond with `NewConnectionId(usage = cid_spare)` containing the requested number of CIDs, subject to implementation limits. The audited wolfSSL tree does not implement `RequestConnectionId`, `NewConnectionId`, `num_cids`, or the response state machine.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Local standard text: `document/dtls/RFC9147.txt:2269`

Section: RFC 9147 Section 9, Connection ID Updates

```text
struct {
  uint8 num_cids;
} RequestConnectionId;
```

```text
num_cids:  The number of CIDs desired.
```

```text
Endpoints SHOULD respond to RequestConnectionId by sending a
NewConnectionId with usage "cid_spare" containing num_cids CIDs as
soon as possible.
```

This requirement needs both receive-side processing for `RequestConnectionId.num_cids` and send-side generation of a `NewConnectionId` response with `usage = cid_spare`.

## Relevant Source Code

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

The RFC 9147 handshake types `request_connection_id = 9` and `new_connection_id = 10` are absent.

`wolfssl-master/src/tls13.c:13548`

```c
if (ssl->options.handShakeState == HANDSHAKE_DONE &&
        type != session_ticket && type != certificate_request &&
        type != certificate && type != key_update && type != finished) {
    WOLFSSL_MSG("HandShake message after handshake complete");
    SendAlert(ssl, alert_fatal, unexpected_message);
    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
    return OUT_OF_ORDER_E;
}
```

`RequestConnectionId` is a DTLS 1.3 CID update handshake message, but it is not accepted in the post-handshake message allow-list.

`wolfssl-master/src/tls13.c:13740`

```c
default:
    WOLFSSL_MSG("Unknown handshake message type");
    ret = UNKNOWN_HANDSHAKE_TYPE;
    break;
```

There is no `request_connection_id` dispatch case and no parser that could read `num_cids`.

`wolfssl-master/src/dtls.c:1264`

```c
int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,
    byte isRequest)
```

`TLSX_ConnectionID_Parse` handles the `connection_id` extension during negotiation. It is not a `RequestConnectionId` post-handshake message parser and does not process a `num_cids` field.

## Implementation Behavior

wolfSSL can negotiate and use a static CID through the `connection_id` extension, and it can put that configured CID into DTLS 1.3 unified headers. It does not implement the dynamic request/response mechanism:

- no `RequestConnectionId` handshake type;
- no `num_cids` field parser;
- no `NewConnectionId` serializer for responses;
- no `cid_spare` response behavior;
- no `too_many_cids_requested` handling.

## Inconsistency Reason

RFC 9147 says endpoints should respond to `RequestConnectionId` with `NewConnectionId(usage = cid_spare)` containing the requested CIDs as soon as possible. wolfSSL has no code path that can receive `RequestConnectionId`, interpret `num_cids`, decide how many CIDs to provide, or send the required `NewConnectionId` response. Static CID extension negotiation does not satisfy this request/response behavior.

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
ABSENT num_cids
ABSENT too_many_cids_requested

== Static CID positive-control scans ==
PASS connection_id extension parser
wolfssl-master/src/tls.c:13098:#define CID_PARSE  TLSX_ConnectionID_Parse
wolfssl-master/src/dtls.c:1264:int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,
wolfssl-master/wolfssl/internal.h:3876:WOLFSSL_LOCAL int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input,

== Dispatcher checks ==
PASS dispatcher unknown-message fallback returns UNKNOWN_HANDSHAKE_TYPE
ABSENT case request_connection_id
ABSENT case new_connection_id

== Decision ==
PASS dynamic CID update support is absent in wolfssl-master: the static CID extension/header paths are present, but no RequestConnectionId/NewConnectionId message types, ConnectionIdUsage values, num_cids handling, or cid_spare/cid_immediate state machine were found.
```

## Impact

A peer that requests fresh CIDs with `RequestConnectionId(num_cids = N)` will not receive the expected `NewConnectionId(usage = cid_spare)` response from wolfSSL. This prevents RFC 9147 dynamic CID replenishment and can reduce interoperability in deployments that use CID refresh for path migration, multipath operation, or privacy.

## Fix Direction

Add `request_connection_id = 9` and `new_connection_id = 10` to the DTLS 1.3 handshake handling. Implement parsing for `RequestConnectionId.num_cids`, response generation for `NewConnectionId(usage = cid_spare)`, request tracking so outstanding requests are not duplicated, limit handling for excessive requests, and tests that verify the response count and `cid_spare` usage value.
