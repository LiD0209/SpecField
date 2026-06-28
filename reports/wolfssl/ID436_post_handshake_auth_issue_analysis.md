# ID436 Issue Analysis: post_handshake_auth Receive-Side Enforcement

## Problem Summary

- ID: `436`
- Variable: `post_handshake_auth`
- Rule: `invalid if value check fails`
- Condition: `If a client receives a CertificateRequest message without having sent this extension`

This item focuses on whether a TLS 1.3 client in wolfSSL will reject a post-handshake `CertificateRequest` when the client did not previously advertise the `post_handshake_auth` extension in `ClientHello`.

Our conclusion is:

- wolfSSL has a clear send-side restriction for compliant peers.
- wolfSSL does not have an equally clear receive-side RFC check for this condition.
- Therefore, this item is best classified as `partially satisfied`.

## RFC Original Text

Source file: `D:\project\conditionFuzzing\document\TLS1.3.txt`

Relevant section: `4.6.2. Post-Handshake Authentication`

Original English requirement:

> A client that receives a CertificateRequest message without having sent the "post_handshake_auth" extension MUST send an "unexpected_message" fatal alert.

This sentence is the core normative requirement for ID436. The key points are:

- The subject is the client receive side.
- The trigger is receiving a post-handshake `CertificateRequest` without having sent the extension.
- The required behavior is explicit: send `unexpected_message` as a fatal alert.

## wolfSSL Code Description

### 1. Extension parsing on ClientHello

File: `wolfssl-master/src/tls.c`

In `TLSX_PostHandAuth_Parse(...)`, when the extension appears in `client_hello`, wolfSSL checks that the extension body is empty and then sets:

```c
ssl->options.postHandshakeAuth = 1;
```

This means wolfSSL does record whether the client advertised support for post-handshake authentication.

### 2. Server-side sending restriction exists

File: `wolfssl-master/src/tls13.c`

In `wolfSSL_request_certificate(...)`, wolfSSL rejects server-side attempts to send a post-handshake `CertificateRequest` unless:

```c
ssl->options.postHandshakeAuth == 1
```

The key guard is:

```c
if (!ssl->options.postHandshakeAuth)
    return POST_HAND_AUTH_ERROR;
```

This is a useful protection, but it is a sender-side policy check. It is not the RFC-mandated client receive-side rejection.

### 3. Client receive path does not contain the explicit RFC guard

File: `wolfssl-master/src/tls13.c`

When the client receives `certificate_request`, the message first passes through the TLS 1.3 handshake message sanity logic. The checks there mainly cover:

- whether the message is received on the correct side
- whether it appears in an allowed state
- whether PSK is being used
- whether it is duplicated in an invalid way

However, this path does not include an explicit check equivalent to:

```c
if (!ssl->options.postHandshakeAuth) {
    SendAlert(ssl, alert_fatal, unexpected_message);
    return ...;
}
```

After that, the message is processed by `DoTls13CertificateRequest(...)`, and the function can complete successfully.

### 4. POST_HAND_AUTH_ERROR is not the same as the RFC receive-side alert

Another relevant path in `tls13.c` can map some failures in the post-handshake auth flow to:

```c
POST_HAND_AUTH_ERROR
```

But this still does not establish the specific RFC behavior:

- client receives forbidden `CertificateRequest`
- client immediately sends fatal `unexpected_message`

So the current implementation has an error-handling path around post-handshake auth, but not a dedicated receive-side enforcement point for the exact RFC condition.

## Runtime Validation Summary

We also performed a runtime re-check to verify whether this gap is observable in behavior.

### 1. Normal wolfSSL behavior

With `WOLFSSL_POSTAUTH` enabled, if the client does not advertise `post_handshake_auth`, the server-side call to `wolfSSL_request_certificate(...)` fails with `POST_HAND_AUTH_ERROR`.

That shows the send-side restriction is real.

### 2. Forced invalid peer behavior

To test the RFC condition directly, we temporarily bypassed the server-side guard in `wolfSSL_request_certificate(...)` so that a non-compliant peer could still send post-handshake `CertificateRequest`.

The temporary validation change was conceptually:

```c
if (!ssl->options.postHandshakeAuth) {
    /* test-only bypass */
}
```

instead of:

```c
if (!ssl->options.postHandshakeAuth)
    return POST_HAND_AUTH_ERROR;
```

Under that forced-invalid scenario:

- the server successfully sent post-handshake `CertificateRequest`
- the client did not immediately fail with `unexpected_message`
- the connection continued instead of being aborted at that point

This runtime result matches the static code analysis: wolfSSL relies on send-side correctness, but the client receive side does not enforce the RFC requirement in a clear dedicated check.

## Why the Implementation and RFC Are Inconsistent

The mismatch comes from where the validation is placed.

- RFC 8446 defines a client receive-side obligation.
- wolfSSL mainly enforces the condition on the server send side.
- If the peer is malicious, buggy, or intentionally non-compliant, sender-side self-restraint is not sufficient.

In other words, wolfSSL currently assumes that a correct peer will not send this message unless the extension was negotiated. That assumption is weaker than the RFC requirement, because the RFC explicitly requires the receiving client to reject the message.

## Suggested Fix

### Implementation suggestion

Add an explicit receive-side check in the client path before accepting post-handshake `CertificateRequest`.

Recommended logic:

```c
if (ssl->options.side == WOLFSSL_CLIENT_END &&
    ssl->options.clientState == CLIENT_FINISHED_COMPLETE &&
    ssl->options.serverState >= SERVER_FINISHED_COMPLETE &&
    !ssl->options.postHandshakeAuth) {
    SendAlert(ssl, alert_fatal, unexpected_message);
    return SANITY_MSG_E;
}
```

The exact return code can be adjusted to fit wolfSSL's internal conventions, but the key requirement is:

- send `unexpected_message`
- fail immediately
- do so on the client receive side

### Testing suggestion

Add a regression test that covers both cases:

1. compliant case:
`post_handshake_auth` was sent, server sends post-handshake `CertificateRequest`, client accepts

2. non-compliant case:
`post_handshake_auth` was not sent, peer still sends post-handshake `CertificateRequest`, client must send fatal `unexpected_message`

This second test should use a deliberately injected or mocked invalid peer behavior, because a compliant wolfSSL server will not naturally generate the violating message.

## Final Assessment

The current wolfSSL implementation is not completely missing protection for post-handshake authentication. It does have a meaningful send-side restriction. However, for ID436, that is not enough to claim full compliance with the RFC text.

The core gap is:

- the RFC requirement is on the client receive side
- wolfSSL's strongest explicit check is on the server send side
- the client receive side lacks a dedicated `unexpected_message` fatal alert check for this exact condition

Therefore, marking ID436 as `partially satisfied` is justified.
