# HelloVerifyRequest Syntax Is Receive-Only in Product Code

## Summary

RFC 6347 defines the HelloVerifyRequest syntax for the DTLS cookie exchange. BoringSSL's product client can parse that syntax, store the cookie, reset the transcript, and resend ClientHello. The product server path, however, does not generate HelloVerifyRequest at all.

The runner can also generate HelloVerifyRequest as a test peer, but that logic lives under `ssl/test/runner`, not in shipped `libssl`. So the RFC syntax is supported in the receive direction for the product client, but not in the product server send direction.

This confirms ID 078 as **partially satisfied**.

## Standard Requirement

RFC 6347, Section 4.2.1, "Denial-of-Service Countermeasures":

```text
When the client sends its ClientHello message to the server, the server MAY respond with a HelloVerifyRequest message.  This message contains a stateless cookie generated using the technique of [PHOTURIS].  The client MUST retransmit the ClientHello with the cookie added.  The server then verifies the cookie and proceeds with the handshake only if it is valid.
```

The HelloVerifyRequest syntax is:

```text
struct {
  ProtocolVersion server_version;
  opaque cookie<0..2^8-1>;
} HelloVerifyRequest;
```

The message type is:

```text
The HelloVerifyRequest message type is hello_verify_request(3).
```

The client-side rule is also explicit:

```text
Clients MUST be prepared to do a cookie exchange with every
handshake.
```

And when HVR is used, the transcript excludes the initial ClientHello and HVR:

```text
If HelloVerifyRequest is used, the initial ClientHello and
HelloVerifyRequest are not included in the calculation of the
handshake_messages (for the CertificateVerify message) and
verify_data (for the Finished message).
```

The expected behavior is:

| Step | Expected behavior |
|---|---|
| Receive HelloVerifyRequest | Parse the `server_version` and cookie fields |
| Store the cookie | Resend ClientHello with the cookie attached |
| Reset transcript | Exclude initial ClientHello and HVR from later transcript calculations |
| Send HelloVerifyRequest as server | Product server may emit HVR when implementing the exchange |

## Code Behavior

### Product Client Receive Path Exists

In `ssl/handshake_client.cc`, BoringSSL has the DTLS client path for `HelloVerifyRequest`:

```cpp
static bool handle_hello_verify_request(SSL_HANDSHAKE *hs,
                                        const SSLMessage &msg) {
  SSL *const ssl = hs->ssl;
  assert(SSL_is_dtls(ssl));
  assert(msg.type == DTLS1_MT_HELLO_VERIFY_REQUEST);
  assert(!hs->received_hello_verify_request);

  CBS hello_verify_request = msg.body, cookie;
  uint16_t server_version;
  if (!CBS_get_u16(&hello_verify_request, &server_version) ||
      !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
      CBS_len(&hello_verify_request) != 0) {
    ...
  }
```

It stores the cookie and resends ClientHello:

```cpp
  if (!hs->dtls_cookie.CopyFrom(cookie)) {
    ...
  }
  hs->received_hello_verify_request = true;

  ssl->method->next_message(ssl);

  // DTLS resets the handshake buffer after HelloVerifyRequest.
  if (!hs->transcript.Init()) {
    return false;
  }

  return ssl_add_client_hello(hs);
}
```

The dispatch path only accepts HVR once in DTLS:

```cpp
  if (SSL_is_dtls(ssl) && !hs->received_hello_verify_request &&
      msg.type == DTLS1_MT_HELLO_VERIFY_REQUEST) {
    if (!handle_hello_verify_request(hs, msg)) {
      goto err;
    }
```

This confirms product-client receive support for the RFC syntax and behavior.

### Product Server-Side HVR Generation Is Absent

Searches over `ssl/handshake_server.cc` found no product server path containing:

```text
DTLS1_MT_HELLO_VERIFY_REQUEST
HelloVerifyRequest
hello_verify_request
```

Public headers also do not expose legacy cookie-exchange APIs such as:

```text
SSL_OP_COOKIE_EXCHANGE
DTLSv1_listen
SSL_CTX_set_cookie_*
```

So BoringSSL product `libssl` can receive and process HVR on the client side, but it cannot emit HVR on the server side.

### Runner HVR Generation Is Test-Peer Logic

The Go runner can generate HelloVerifyRequest as a test peer:

```go
helloVerifyRequest := &helloVerifyRequestMsg{
    vers:   VersionDTLS10,
    cookie: make([]byte, cookieLen),
}
```

And it marshals the HVR message:

```go
func (m *helloVerifyRequestMsg) marshal() []byte {
    ...
    x[0] = typeHelloVerifyRequest
```

This is test-peer behavior, not product `libssl` server behavior.

## Runner Coverage

`ssl/test/runner/runner.go` registers DTLS tests:

```go
addDTLSRetransmitTests()
```

That runner logic demonstrates that the repository can model HVR in tests. It does not show that the audited product server generates HelloVerifyRequest.

## Runtime Evidence

A linked probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\repro_dtls12_hvr_receive_only_linked_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```text
cmake --build D:\project\SpecTrace\test-boringssl\rfc6347\051-098\build-linked-probe --config Release --target repro_dtls12_hvr_receive_only_linked_probe
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\build-linked-probe\Release\repro_dtls12_hvr_receive_only_linked_probe.exe D:\project\boringssl-main
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\repro_dtls12_hvr_receive_only_linked_probe.log
```

Observed output:

```text
LINK SSL_CTX_new(DTLS_method): PASS
LINK DTLS1_2_VERSION min/max: PASS
LINK OpenSSL_version: BoringSSL
HVR handshake type constant is present: PASS
Client dispatches HelloVerifyRequest only once: PASS
Client parses HVR server_version and u8 cookie syntax: PASS
Client copies cookie and resends ClientHello: PASS
Client excludes initial ClientHello/HVR from transcript: PASS
Product server has no HVR generation path: PASS
Product public API exposes no legacy DTLS HVR cookie exchange: PASS
Runner has HVR generation but is not product libssl: PASS

EXIT_CODE: 0
```

The probe links against BoringSSL and checks that the product client receive path exists, while the product server generation path is absent and the runner HVR generation is test-peer code.

## Inconsistency

| RFC 6347 behavior | BoringSSL behavior |
|---|---|
| Parse HelloVerifyRequest syntax | Implemented in product client |
| Store cookie and resend ClientHello | Implemented in product client |
| Reset transcript after HVR | Implemented in product client |
| Product server may emit HelloVerifyRequest | No product server generation path found |
| Product server may use legacy cookie-exchange APIs | No such product API found |
| Runner-generated HVR proves product support | Runner HVR generation is test-peer only |

The implementation therefore supports HelloVerifyRequest syntax only on the product receive side.

## Root Cause

BoringSSL's DTLS client includes the RFC 6347 HelloVerifyRequest receive path, but the shipped `libssl` server has no HelloVerifyRequest generation machinery.

The missing server-side pieces are:

```text
generate HelloVerifyRequest
serialize server_version and cookie
emit the HVR record from product libssl
```

The runner can model these behaviors for testing, but the product server cannot.

## Impact

This is a DTLS 1.2 server-side feature gap with a working client-side parser.

| Impact area | Description |
|---|---|
| Product client | HVR receive syntax is supported. |
| Product server | HVR generation is absent. |
| Interoperability | A conforming peer server can still interoperate with the BoringSSL client. |
| Feature completeness | The product library does not implement the full two-sided HVR exchange. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as receive-only HelloVerifyRequest support in product code.

## Suggested Fix

To fully support RFC 6347 HVR behavior, BoringSSL would need:

| Required change | Expected effect |
|---|---|
| Add a production DTLS 1.2 server HelloVerifyRequest send path | Enables product-server HVR generation |
| Add a product-server cookie generation API or callback | Supports stateless cookie exchange |
| Serialize HVR in the server handshake | Allows the server to challenge clients |
| Keep the existing client receive path | Preserves current interoperability |
| Add product-server regression tests | Covers the send side and the full exchange |
