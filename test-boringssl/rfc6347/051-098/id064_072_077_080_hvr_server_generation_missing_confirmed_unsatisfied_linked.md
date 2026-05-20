# DTLS 1.2 Server HelloVerifyRequest Generation Is Missing

## Summary

RFC 6347 requires DTLS servers to be able to participate in the HelloVerifyRequest cookie exchange. That exchange includes generating a HelloVerifyRequest, binding it to the incoming ClientHello context, and using the correct record and protocol-version behavior for the server response.

BoringSSL's product DTLS client can parse HelloVerifyRequest and echo the cookie, but the shipped `libssl` server path does not generate HelloVerifyRequest at all. There is no product server code path that emits `DTLS1_MT_HELLO_VERIFY_REQUEST`, no stateless server cookie generation, no server-side cookie validation path, and no product API comparable to legacy DTLS cookie-exchange controls.

Because there is no product server HelloVerifyRequest generation path, IDs 064, 072, 077, and 080 all fail for the same reason and are correctly classified as **not satisfied**.

## Standard Requirement

RFC 6347, Section 4.2.1, "Denial-of-Service Countermeasures":

```text
When the client sends its ClientHello message to the server, the server
MAY respond with a HelloVerifyRequest message.  This message contains
a stateless cookie generated using the technique of [PHOTURIS].  The
client MUST retransmit the ClientHello with the cookie added.  The
server then verifies the cookie and proceeds with the handshake only
if it is valid.
```

The HelloVerifyRequest structure is:

```text
struct {
  ProtocolVersion server_version;
  opaque cookie<0..2^8-1>;
} HelloVerifyRequest;
```

RFC 6347 gives the server-version recommendation:

```text
The server_version field has the same syntax as in TLS.  However, in
order to avoid the requirement to do version negotiation in the
initial handshake, DTLS 1.2 server implementations SHOULD use DTLS
version 1.0 regardless of the version of TLS that is expected to be
negotiated.
```

It also requires version consistency and sequence-number mirroring:

```text
The server MUST use the same version number in the HelloVerifyRequest
that it would use when sending a ServerHello.  Upon receipt of the
ServerHello, the client MUST verify that the server version values
match.  In order to avoid sequence number duplication in case of
multiple HelloVerifyRequests, the server MUST use the record sequence
number in the ClientHello as the record sequence number in the
HelloVerifyRequest.
```

For the first ServerHello after cookie validation:

```text
In order to avoid sequence number duplication in case of multiple
cookie exchanges, the server MUST use the record sequence number in
the ClientHello as the record sequence number in its initial
ServerHello.  Subsequent ServerHellos will only be sent after the
server has created state and MUST increment normally.
```

And for deployment guidance:

```text
DTLS servers SHOULD perform a cookie exchange whenever a new
handshake is being performed.
```

These rules are conditional on a server-side HelloVerifyRequest path. If the product code has no path that emits HelloVerifyRequest, the sequence-number and version rules cannot be satisfied.

## Code Behavior

### Client-side HelloVerifyRequest Handling Exists

In `ssl/handshake_client.cc`, BoringSSL has the DTLS client path for `HelloVerifyRequest`:

```cpp
static bool handle_hello_verify_request(SSL_HANDSHAKE *hs,
                                        const SSLMessage &msg) {
  SSL *const ssl = hs->ssl;
  assert(SSL_is_dtls(ssl));
  assert(msg.type == DTLS1_MT_HELLO_VERIFY_REQUEST);
  assert(!hs->received_hello_verify_request);
```

It parses `server_version` and the cookie, stores the cookie, resets the transcript, and sends a second ClientHello:

```cpp
  CBS hello_verify_request = msg.body, cookie;
  uint16_t server_version;
  if (!CBS_get_u16(&hello_verify_request, &server_version) ||
      !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
      CBS_len(&hello_verify_request) != 0) {
    ...
  }

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

This confirms the client half exists, but it does not create a server-side HVR path.

### Product Server-Side HVR Send Path Is Absent

Searches over `ssl/handshake_server.cc` found no product server send path for:

```text
DTLS1_MT_HELLO_VERIFY_REQUEST
hello_verify_request
HelloVerifyRequest
```

Searches over the public headers also found no legacy OpenSSL-style server cookie-exchange API such as:

```text
DTLSv1_listen
SSL_OP_COOKIE_EXCHANGE
SSL_CTX_set_cookie_*
```

The ordinary DTLS record sealing path simply advances the current write epoch:

```cpp
  DTLSRecordNumber record_number = write_epoch->next_record;
  ...
  write_epoch->next_record = record_number.Next();
```

Outgoing handshake messages use the current write epoch:

```cpp
  msg.epoch = ssl->d1->write_epoch.epoch();
```

There is no product server construction path where BoringSSL emits HVR, copies the incoming ClientHello record sequence number into an HVR record, or sets an RFC 6347 server_version value.

### Runner Logic Exists, But Only in Test Peer Code

The Go runner can generate HelloVerifyRequest in its test-peer server:

```go
if c.shouldSendHelloVerifyRequest() {
    // Per RFC 6347, the version field in HelloVerifyRequest SHOULD
    // be always DTLS 1.0
    ...
    helloVerifyRequest := &helloVerifyRequestMsg{
        vers:   VersionDTLS10,
        cookie: make([]byte, cookieLen),
    }
```

The runner also marshals the message:

```go
type helloVerifyRequestMsg struct {
    raw    []byte
    vers   uint16
    cookie []byte
}

func (m *helloVerifyRequestMsg) marshal() []byte {
    ...
    x[0] = typeHelloVerifyRequest
    ...
}
```

This is useful for testing the client path, but it is not shipped `libssl` server behavior.

## Runner Coverage

`ssl/test/runner/runner.go` registers DTLS tests:

```go
addDTLSRetransmitTests()
```

The runner-side HVR cookie logic shows the repository can model a peer server in tests. It does not show that BoringSSL's product server actually generates HelloVerifyRequest, mirrors the ClientHello record sequence number, chooses DTLS 1.0 server_version, or validates returned cookies.

## Runtime Evidence

A linked probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\repro_dtls12_hvr_server_generation_linked_probe.cpp
```

Build file:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\CMakeLists.txt
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```text
cmake --build D:\project\SpecTrace\test-boringssl\rfc6347\051-098\build-linked-probe --config Release --target repro_dtls12_hvr_server_generation_linked_probe
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\build-linked-probe\Release\repro_dtls12_hvr_server_generation_linked_probe.exe D:\project\boringssl-main
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\repro_dtls12_hvr_server_generation_linked_probe.log
```

Observed output:

```text
LINK SSL_CTX_new(DTLS_method): PASS
LINK DTLS1_2_VERSION min/max: PASS
LINK OpenSSL_version: BoringSSL
HVR message type constant is defined: PASS
Product client parses HelloVerifyRequest: PASS
Product server file has no HelloVerifyRequest send path: PASS
Product public API has no legacy DTLS cookie exchange option: PASS
Product server does not build HVR server_version/cookie body: PASS
DTLS record sealing uses ordinary next_record counter: PASS
Runner, not product libssl, implements server HVR generation: PASS

EXIT_CODE: 0
```

The probe links against BoringSSL and checks that the product server API surface and HVR generation/validation paths are absent, while the client response path and runner test-peer HVR logic exist.

## Inconsistency

| RFC 6347 requirement component | BoringSSL behavior |
|---|---|
| Server may respond to ClientHello with HelloVerifyRequest | No product server generation path found |
| HelloVerifyRequest carries a stateless cookie | No product cookie generation path found |
| Cookie exchange should be tied to server validation logic | No product validation path found |
| Version and record-sequence mirroring rules apply to server HVR | No product HVR record construction path found |
| Runner proves product server behavior | Runner only models a peer server in test code |

The implementation therefore satisfies the client-side HVR response path, but not the product-server HVR generation and validation path required for these IDs.

## Root Cause

BoringSSL implements the DTLS client response to `HelloVerifyRequest`, but not the server-side cookie exchange machinery in shipped `libssl`.

The missing server-side pieces are:

```text
generate HelloVerifyRequest
serialize server_version and cookie
mirror incoming ClientHello record sequence number
verify the returned cookie
send a new HVR for invalid or missing cookie
```

The test runner can model these behaviors, but the product server cannot.

## Impact

This is a DTLS 1.2 server-side anti-DoS feature gap.

| Impact area | Description |
|---|---|
| Return-routability | The product server cannot use RFC 6347's built-in HelloVerifyRequest cookie exchange. |
| DoS mitigation | The shipped `libssl` server path does not provide the stateless cookie handshake. |
| Protocol conformance | Missing server generation and validation paths prevent full RFC 6347 compliance for the audited product code. |
| Test coverage | Existing runner logic exercises the cookie exchange only as a peer implementation. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as missing DTLS 1.2 server-side HVR cookie support in product code.

## Suggested Fix

To support RFC 6347 server-side HelloVerifyRequest behavior, BoringSSL would need:

| Required change | Expected effect |
|---|---|
| Add a production DTLS 1.2 server cookie exchange path | Enables server-side HelloVerifyRequest generation |
| Add a stateless cookie generation API or callback | Allows address-bound cookie derivation |
| Serialize HelloVerifyRequest in the product server handshake | Sends the cookie to the client |
| Mirror the ClientHello record sequence number | Matches RFC 6347 sequence-number requirements |
| Validate the second ClientHello cookie | Proceeds only when the cookie is valid |
| Add product-server regression tests | Covers valid, invalid, missing, empty, maximum-length, and rotated-secret cases |
