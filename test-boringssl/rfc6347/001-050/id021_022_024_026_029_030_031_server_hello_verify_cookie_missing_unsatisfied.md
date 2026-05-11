# DTLS 1.2 Server HelloVerifyRequest Cookie Path Missing

## Summary

BoringSSL implements the DTLS 1.2 client-side response to `HelloVerifyRequest`, but the audited production `libssl` server path does not implement server-side `HelloVerifyRequest` generation, stateless cookie construction, cookie verification, invalid-cookie rechallenge behavior, or secret rotation handling. The only complete server-side cookie behavior found is in `ssl/test/runner`, which is a protocol test peer rather than the shipped implementation.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc6347

Section: RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures

```text
"The server then verifies the cookie"
"only if it is valid"
```

RFC 6347 defines an optional but normative cookie exchange mechanism when the server chooses to use `HelloVerifyRequest`. In that mechanism, the server sends a cookie, the client retransmits `ClientHello` with the cookie, and the server proceeds only after validating it. The RFC also describes treating invalid cookies like missing cookies and allowing a limited transition window when rotating the secret used to compute cookies.

## Relevant Source Code

`ssl/handshake_client.cc:517`

```c++
static bool handle_hello_verify_request(SSL_HANDSHAKE *hs,
                                        const SSLMessage &msg) {
  SSL *const ssl = hs->ssl;
  assert(SSL_is_dtls(ssl));
  assert(msg.type == DTLS1_MT_HELLO_VERIFY_REQUEST);
```

`ssl/handshake_client.cc:524`

```c++
  CBS hello_verify_request = msg.body, cookie;
  uint16_t server_version;
  if (!CBS_get_u16(&hello_verify_request, &server_version) ||
      !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
      CBS_len(&hello_verify_request) != 0) {
```

`ssl/handshake_client.cc:534`

```c++
  if (!hs->dtls_cookie.CopyFrom(cookie)) {
    ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    return false;
  }
```

`ssl/handshake_server.cc:334`

```c++
      {TLSEXT_TYPE_cookie, false},
```

`ssl/test/runner/handshake_server.go:299`

```go
	if c.shouldSendHelloVerifyRequest() {
		helloVerifyRequest := &helloVerifyRequestMsg{
			vers:   VersionDTLS10,
			cookie: make([]byte, cookieLen),
		}
```

`ssl/test/runner/handshake_server.go:326`

```go
		if !bytes.Equal(newClientHello.cookie, helloVerifyRequest.cookie) {
			return errors.New("dtls: invalid cookie")
		}
```

The production client accepts a `HelloVerifyRequest`, stores the cookie, resets transcript state, and sends another `ClientHello`. The product server evidence is negative: searches found no `DTLSv1_listen`, `SSL_CTX_set_cookie_*`, server `DTLS1_MT_HELLO_VERIFY_REQUEST` generation, cookie HMAC, or verification callback path. The runner code demonstrates the behavior only for tests.

## Implementation Behavior

For a BoringSSL DTLS client, `handle_hello_verify_request` parses `server_version` and a one-byte-length-prefixed cookie, copies it to `hs->dtls_cookie`, resets the transcript, and invokes `ssl_add_client_hello`.

For a BoringSSL production DTLS server, the audited code negotiates DTLS versions and parses `ClientHello`, but no product path constructs a `HelloVerifyRequest`, computes a stateless cookie from client address/parameters, validates a returned cookie, treats invalid cookies as missing cookies, or handles cookie secret rotation. The cookie exchange exists in the Go runner used to test the C++ shim.

## Inconsistency Reason

RFC 6347's server-side cookie exchange requires a server behavior: generate a cookie, send `HelloVerifyRequest`, validate the returned cookie, and proceed only on success. BoringSSL implements the peer client behavior but lacks the corresponding production server behavior. Because the only server-side implementation is in the test runner, the shipped `libssl` server does not satisfy these server-cookie requirements.

This confirms the unsatisfied classification for the server cookie entries covering generation, required presence in `HelloVerifyRequest`, verification, invalid-cookie behavior, HMAC-style derivation guidance, second-`ClientHello` validity, and secret rotation invalidation.

## Runtime Evidence

Focused verification script: `verify_dtls12_cookie_paths.py`

Log: `verify_dtls12_cookie_paths.log`

Result summary:

```text
passed=true
no production server HelloVerifyRequest cookie API/generation/verification path found
client parses HelloVerifyRequest and copies cookie
```

No prebuilt `ssl_test.exe` or `bssl.exe` was present under `boringssl-main`, so the verification is an executable source-level test over the audited product and runner files.

## Impact

A BoringSSL DTLS 1.2 server cannot use RFC 6347's stateless `HelloVerifyRequest` cookie exchange from the audited product API path. Deployments relying on BoringSSL alone do not get this RFC anti-DoS mechanism and must handle spoofed-source amplification risk or stateless validation outside `libssl`.

## Fix Direction

Add a production DTLS 1.2 server cookie exchange path, likely with an API compatible with application-owned address binding. The implementation should generate `HelloVerifyRequest`, encode a 0..255 byte cookie, validate returned cookies before proceeding, rechallenge invalid cookies, support secret rotation windows, and include focused tests for valid, missing, invalid, empty, and 255-byte cookies.
