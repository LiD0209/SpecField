# DTLS 1.3 Dynamic Connection ID Request Messages Are Not Implemented

## Summary
wolfSSL has DTLS CID extension support and can place a negotiated CID into the DTLS 1.3 unified header, but this audit did not find RFC 9147 `RequestConnectionId` or `NewConnectionId` post-handshake message handling.

## Standard Requirement
Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant sections: RFC 9147 Section 9.1 "New Connection ID" and Section 9.2 "Request Connection ID".

Original English normative text:

```text
Endpoints SHOULD respond to RequestConnectionId by sending a NewConnectionId with usage "cid_spare" containing num_cids CIDs as soon as possible.

An endpoint MAY handle requests which it considers excessive by responding with a NewConnectionId message containing fewer than num_cids CIDs, including no CIDs at all.
```

The standard requires a peer to understand a request for additional CIDs and to respond with `NewConnectionId` messages using the requested `num_cids` value, subject to the excessive-request exception.

## Relevant Source Code
`src/dtls.c:1254`, `src/dtls.c:1344`, `src/dtls13.c:1163`, `src/dtls13.c:1176`, `wolfssl/internal.h:6622`

```c
/* Existing DTLS CID extension support, not RFC 9147 post-handshake messages. */
int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,
    byte isRequest)

int wolfSSL_dtls_cid_use(WOLFSSL* ssl)

static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
{
    ...
    *flags |= DTLS13_CID_BIT;
    ...
}
```

`wolfssl/internal.h:6622` defines the ACK content type, and the searched handshake enum contains common TLS/DTLS handshake messages, but no `RequestConnectionId` or `NewConnectionId` handshake message.

## Implementation Behavior
The implementation supports a static/extension-driven CID model:

- `TLSX_ConnectionID_Parse` parses the connection_id extension.
- `wolfSSL_dtls_cid_use` and `wolfSSL_dtls_cid_set` configure local CID use.
- `Dtls13AddCID` sets the unified header CID bit and writes the configured transmit CID.

The audit search did not find `RequestConnectionId`, `NewConnectionId`, `num_cids`, `cid_spare`, or parser/sender logic for these post-handshake messages.

## Inconsistency Reason
RFC 9147's dynamic CID update mechanism is a runtime handshake-message protocol. Existing wolfSSL code proves only extension negotiation and header encoding for a configured CID. It does not implement the variable change in which `num_cids` is copied from `RequestConnectionId` into one or more `NewConnectionId` responses, nor the excessive-request exception returning fewer CIDs.

## Runtime Evidence
The focused source assertion test passed:

```text
[PASS] request_new_connection_id_absent: 源码未发现 RequestConnectionId/NewConnectionId/num_cids/cid_spare。
```

Full handshake-level runtime testing was blocked because the current `build/CMakeCache.txt` has `WOLFSSL_DTLS13:BOOL=no` and `WOLFSSL_DTLS_CID:BOOL=no`, and no wolfSSL library binary was present in `wolfssl-master/build`.

## Impact
Applications that rely on RFC 9147 dynamic CID rotation or spare CID provisioning cannot use wolfSSL's DTLS 1.3 stack for that behavior. They may be limited to preconfigured or extension-negotiated CIDs and cannot interoperate with peers expecting RequestConnectionId/NewConnectionId.

## Fix Direction
Add DTLS 1.3 post-handshake message definitions and state-machine paths for `RequestConnectionId` and `NewConnectionId`. The implementation should parse `num_cids`, enforce bounds and excessive-request policy, generate `NewConnectionId` messages with `usage = cid_spare`, and add regression tests covering normal, zero, and excessive request cases.
