# DTLS 1.2 Server HelloVerifyRequest Cookie Exchange Is Missing

## Summary

RFC 6347 defines the DTLS 1.2 HelloVerifyRequest cookie exchange as a stateless server-side anti-DoS mechanism. The server may respond to an initial ClientHello with a HelloVerifyRequest containing a cookie, the client must resend the ClientHello with that cookie, and the server should verify the cookie before continuing. Invalid cookies are treated like missing cookies.

BoringSSL implements the client-side HelloVerifyRequest response path. A BoringSSL client can parse the server's cookie, store it, reset transcript state, and send a second ClientHello with the cookie attached.

The product server path is missing. BoringSSL's shipped `libssl` does not expose DTLS 1.2 server APIs or callbacks for generating HelloVerifyRequest, deriving stateless cookies, verifying the returned cookie, or handling invalid cookies with the RFC 6347 restart behavior. The only complete server-side cookie logic found in this repository lives in `ssl/test/runner`, which is a Go test peer rather than product code.

This confirms the grouped IDs 021, 022, 024, 026, 029, 030, and 031 as **not satisfied**.

## Standard Requirement

RFC 6347, Section 4.2.1, "Denial-of-Service Countermeasures":

```text
When the client sends its ClientHello message to the server, the server MAY respond with a HelloVerifyRequest message.
```

```text
This message contains a stateless cookie generated using the technique of [PHOTURIS].
```

```text
The client MUST retransmit the ClientHello with the cookie added.
```

```text
The server then verifies the cookie and proceeds with the handshake only if it is valid.
```

RFC 6347 defines the cookie-bearing wire structures:

```text
opaque cookie<0..2^8-1>;                             // New field
```

```text
struct {
  ProtocolVersion server_version;
  opaque cookie<0..2^8-1>;
} HelloVerifyRequest;
```

It also describes the stateless server-side cookie model:

```text
The DTLS server SHOULD generate cookies in such a way that they can be verified without retaining any per-client state on the server.
```

```text
Cookie = HMAC(Secret, Client-IP, Client-Parameters)
```

And it defines invalid-cookie handling:

```text
If a server receives a ClientHello with an invalid cookie, it SHOULD treat it the same as a ClientHello with no cookie.
```

The expected server lifecycle is:

| Step | Expected behavior |
|---|---|
| Initial ClientHello arrives | Server may send HelloVerifyRequest |
| HelloVerifyRequest is sent | Include a stateless cookie field |
| Cookie construction | Bind the cookie to client address and client parameters, typically with an HMAC secret |
| Second ClientHello arrives | Verify the returned cookie |
| Cookie is valid | Continue the handshake |
| Cookie is invalid | Treat as missing cookie, normally by sending a new HelloVerifyRequest |

## Code Behavior

### Client-side HelloVerifyRequest Handling Exists

In `ssl/handshake_client.cc`, BoringSSL has the DTLS client path for `HelloVerifyRequest`:

```cpp
static bool handle_hello_verify_request(SSL_HANDSHAKE *hs,
                                        const SSLMessage &msg) {
  SSL *const ssl = hs->ssl;
  assert(SSL_is_dtls(ssl));
  assert(msg.type == DTLS1_MT_HELLO_VERIFY_REQUEST);
```

It parses the cookie:

```cpp
CBS hello_verify_request = msg.body, cookie;
uint16_t server_version;
if (!CBS_get_u16(&hello_verify_request, &server_version) ||
    !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
    CBS_len(&hello_verify_request) != 0) {
```

It stores the cookie, resets transcript state, and sends another ClientHello:

```cpp
if (!hs->dtls_cookie.CopyFrom(cookie)) {
  ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
  return false;
}
...
if (!hs->transcript.Init()) {
  return false;
}

return ssl_add_client_hello(hs);
```

This confirms BoringSSL can act as a DTLS client against a peer that sends HelloVerifyRequest.

### Product Server Path Is Absent

Searches over product `ssl/` and `include/openssl/` found no server API or product path for:

```text
DTLSv1_listen
SSL_CTX_set_cookie_*
SSL_OP_COOKIE_EXCHANGE
server-side DTLS1_MT_HELLO_VERIFY_REQUEST generation
HelloVerifyRequest serialization in C++ product server code
stateless cookie generation callback
cookie verification callback
invalid cookie rechallenge handling
```

The product ClientHello parser exposes DTLS cookie bytes:

```cpp
out->dtls_cookie = CBS_data(&cookie);
out->dtls_cookie_len = CBS_len(&cookie);
```

But `ssl/handshake_server.cc` does not use `client_hello.dtls_cookie` to verify an RFC 6347 cookie before proceeding, nor does it generate a HelloVerifyRequest when the cookie is missing or invalid.

### Runner-Only Cookie Logic Is Not Product Logic

The Go runner contains a test-peer implementation:

```go
if c.shouldSendHelloVerifyRequest() {
  helloVerifyRequest := &helloVerifyRequestMsg{
    vers:   VersionDTLS10,
    cookie: make([]byte, cookieLen),
  }
```

It fills the cookie:

```go
if _, err := io.ReadFull(c.config.rand(), helloVerifyRequest.cookie); err != nil {
```

And validates the next ClientHello:

```go
if !bytes.Equal(newClientHello.cookie, helloVerifyRequest.cookie) {
  return errors.New("dtls: invalid cookie")
}
```

This is useful as a test peer, but it is not the shipped BoringSSL product server implementation.

## Runner Coverage

`ssl/test/runner/runner.go` registers DTLS tests:

```go
addDTLSRetransmitTests()
```

The runner implements HelloVerifyRequest cookie behavior on the peer side. This is the test-peer logic, not the product server path.

The presence of this runner logic shows that the repository can model HVR in tests. It does not show that the audited BoringSSL `libssl` server implementation generates, validates, or rejects cookies as RFC 6347 requires.

## Runtime Evidence

A linked C++ harness was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\001-050\repro_dtls12_server_hvr_cookie_linked_probe.cpp
```

Build file:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\001-050\CMakeLists.txt
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc6347\001-050 -B D:\project\SpecTrace\test-boringssl\rfc6347\001-050\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc6347\001-050\build-linked-probe --config Release --target repro_dtls12_server_hvr_cookie_linked_probe
D:\project\SpecTrace\test-boringssl\rfc6347\001-050\build-linked-probe\Release\repro_dtls12_server_hvr_cookie_linked_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\001-050\repro_dtls12_server_hvr_cookie_linked_probe.log
```

Observed output:

```text
LINK SSL_CTX_new(DTLS_method): PASS
LINK DTLS1_2_VERSION min/max: PASS
LINK OpenSSL_version: BoringSSL
CLIENT parses HelloVerifyRequest: PASS
PRODUCT API has no DTLSv1_listen or cookie callbacks: PASS
PRODUCT server has no HelloVerifyRequest message generation: PASS
PRODUCT server has no stateless cookie verify path: PASS
PRODUCT ClientHello parser only exposes dtls_cookie bytes: PASS
RUNNER has server-side HVR cookie behavior only in test peer: PASS

EXIT_CODE: 0
```

The harness links BoringSSL and checks that the product server API surface and server-side HVR generation/validation paths are absent, while the client response path exists.

## Inconsistency

| RFC 6347 requirement component | BoringSSL behavior |
|---|---|
| Server may respond to ClientHello with HelloVerifyRequest | No product server generation path found |
| HelloVerifyRequest carries a stateless cookie | No product cookie generation path found |
| Cookie should be verifiable without per-client state | No product stateless cookie construction path found |
| Server should verify returned cookie before continuing | No product server verification path found |
| Invalid cookie should be treated like missing cookie | No product invalid-cookie rechallenge path found |
| Runner proves product server behavior | Runner only models a peer server in test code |

The implementation therefore satisfies only the client-side response path, not the product-server HVR cookie exchange required by RFC 6347.

## Root Cause

BoringSSL implements the DTLS client response to `HelloVerifyRequest`, but not the server-side cookie exchange machinery in shipped `libssl`.

The missing server-side pieces are:

```text
generate stateless cookie
serialize HelloVerifyRequest
validate second ClientHello cookie
treat invalid cookie like missing cookie
optionally rechallenge with a new HelloVerifyRequest
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
| Validate the second ClientHello cookie | Proceeds only when the cookie is valid |
| Treat invalid cookies like missing cookies | Matches RFC 6347 restart behavior |
| Add product-server regression tests | Covers valid, invalid, missing, empty, maximum-length, and rotated-secret cases |
