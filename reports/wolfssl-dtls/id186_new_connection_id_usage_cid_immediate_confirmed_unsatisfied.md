# NewConnectionId cid_immediate Usage Is Not Implemented

## Summary

This is a confirmed unsatisfied DTLS 1.3 compliance finding in wolfSSL. RFC 9147 Section 9 defines `NewConnectionId` with `usage = cid_immediate`, which requires an endpoint to switch to one of the newly provided CIDs immediately for future records. The audited wolfSSL tree supports static CID negotiation and record-header CID use, but it does not implement `NewConnectionId` or any immediate CID-switch state machine.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Local standard text: `document/dtls/RFC9147.txt:2227`

Section: RFC 9147 Section 9, Connection ID Updates

```text
enum {
    cid_immediate(0), cid_spare(1), (255)
} ConnectionIdUsage;
```

```text
usage:  Indicates whether the new CIDs should be used immediately or
   are spare.  If usage is set to "cid_immediate", then one of the
   new CIDs MUST be used immediately for all future records.
```

The requirement is an active state transition. After receiving `NewConnectionId(usage = cid_immediate)`, the endpoint must select one of the newly supplied CIDs and use it for all future outbound records.

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

The RFC 9147 handshake type `new_connection_id = 10` is absent, so wolfSSL has no named message type for the message that carries `cid_immediate`.

`wolfssl-master/src/tls13.c:13527`

```c
if ((ret = SanityCheckTls13MsgReceived(ssl, type)) != 0) {
    WOLFSSL_MSG("Sanity Check on handshake message type received failed");
    if (ret == WC_NO_ERR_TRACE(VERSION_ERROR))
        SendAlert(ssl, alert_fatal, wolfssl_alert_protocol_version);
    else
        SendAlert(ssl, alert_fatal, unexpected_message);
    return ret;
}
```

`wolfssl-master/src/tls13.c:13488`

```c
default:
    WOLFSSL_MSG("Unknown message type");
    WOLFSSL_ERROR_VERBOSE(SANITY_MSG_E);
    return SANITY_MSG_E;
```

An unknown handshake type fails the TLS 1.3 sanity check before any dynamic CID handler can run.

`wolfssl-master/src/dtls13.c:1178`

```c
cidSz = DtlsGetCidTxSize(ssl);

/* no cid */
if (cidSz == 0)
    return 0;
*flags |= DTLS13_CID_BIT;
ret = wolfSSL_dtls_cid_get_tx(ssl, out + *idx, cidSz);
```

Outgoing records use the currently configured transmit CID. There is no code path here that switches to a CID received in a `NewConnectionId` message.

`wolfssl-master/src/dtls.c:1382`

```c
if (cidInfo->rx != NULL) {
    WOLFSSL_MSG("wolfSSL doesn't support changing the CID during a "
                "connection");
    return WOLFSSL_FAILURE;
}
```

The public CID API is also static in practice and rejects changing the configured receive CID during a connection.

## Implementation Behavior

wolfSSL can put an already configured CID into outgoing DTLS 1.3 records. It can also validate an incoming record's CID against the configured receive CID. However, there is no `NewConnectionId` parser, no `ConnectionIdUsage` enum, and no branch that applies `cid_immediate` by replacing the transmit CID used for future records.

## Inconsistency Reason

RFC 9147 requires immediate CID activation when `NewConnectionId.usage` is `cid_immediate`. wolfSSL has no implementation path that can receive that message, read the `usage` value, select a new CID from the message body, and switch future records to that CID. Static CID header support is therefore insufficient to satisfy this requirement.

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
ABSENT NewConnectionId
ABSENT ConnectionIdUsage
ABSENT cid_immediate
ABSENT cid_spare
ABSENT num_cids

== Static CID positive-control scans ==
PASS DTLS 1.3 unified header adds CID
wolfssl-master/src/dtls13.c:1183:    *flags |= DTLS13_CID_BIT;
PASS DTLS 1.3 unified header checks CID
wolfssl-master/src/dtls13.c:1204:        if (!DtlsCIDCheck(ssl, input + *idx, inputSize - *idx)) {
PASS CID API rejects in-connection CID changes
wolfssl-master/src/dtls.c:1383:        WOLFSSL_MSG("wolfSSL doesn't support changing the CID during a "

== Dispatcher checks ==
PASS dispatcher unknown-message fallback returns UNKNOWN_HANDSHAKE_TYPE
ABSENT case new_connection_id

== Decision ==
PASS dynamic CID update support is absent in wolfssl-master: the static CID extension/header paths are present, but no RequestConnectionId/NewConnectionId message types, ConnectionIdUsage values, num_cids handling, or cid_spare/cid_immediate state machine were found.
```

## Impact

A peer that sends `NewConnectionId(usage = cid_immediate)` cannot force wolfSSL to switch to a fresh CID for future records. This breaks the dynamic CID rotation behavior RFC 9147 expects for path changes, privacy refresh, and peer-directed CID management.

## Fix Direction

Add `new_connection_id = 10` to the DTLS 1.3 handshake type handling, parse `NewConnectionId`, define `ConnectionIdUsage`, and implement the `cid_immediate` transition by replacing the transmit CID used by the record layer for all subsequent records. Add tests that inject `NewConnectionId(usage = cid_immediate)` and assert that the next outbound DTLS 1.3 records use one of the newly received CIDs.
