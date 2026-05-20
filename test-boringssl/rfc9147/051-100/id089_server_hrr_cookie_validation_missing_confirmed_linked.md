# DTLS 1.3 Server HRR Cookie Generation and Validation Are Missing

## Summary

RFC 9147 reuses the TLS 1.3 HelloRetryRequest `cookie` extension as a DTLS 1.3 return-routability check. A complete server-side implementation must be able to generate a stateless cookie, bind it to the client address or equivalent context, send it in HelloRetryRequest, validate the returned cookie in the second ClientHello, and reject invalid cookies with an `illegal_parameter` alert.

BoringSSL implements the client-side HRR cookie echo path. A BoringSSL client can parse a `cookie` extension in HelloRetryRequest and include it in the second ClientHello. The runner also has tests where the Go runner server sends an HRR cookie and checks that the BoringSSL client echoes it.

The product server path is missing. BoringSSL's server HelloRetryRequest construction does not emit `TLSEXT_TYPE_cookie`, the server extension table ignores ClientHello `cookie`, and there is no DTLS 1.3 stateless-cookie generation, client-address binding, second-ClientHello validation, or invalid-cookie `illegal_parameter` path. This confirms RFC 9147 ID 089 as **not satisfied**.

## Standard Requirement

RFC 9147, Section 5, "Overview of DTLS":

```text
In addition, DTLS reuses TLS 1.3's "cookie" extension to provide a
return-routability check as part of connection establishment.  This
is an important DoS prevention mechanism for UDP-based protocols,
unlike TCP-based protocols, for which TCP establishes return-
routability as part of the connection establishment.
```

RFC 9147, Section 5.1, "Denial-of-Service Countermeasures":

```text
In order to counter both of these attacks, DTLS borrows the stateless
cookie technique used by Photuris [RFC2522] and IKE [RFC7296].  When
the client sends its ClientHello message to the server, the server
MAY respond with a HelloRetryRequest message.  The HelloRetryRequest
message, as well as the "cookie" extension, is defined in TLS 1.3.
The HelloRetryRequest message contains a stateless cookie (see
[TLS13], Section 4.2.2).  The client MUST send a new ClientHello with
the cookie added as an extension.  The server then verifies the
cookie and proceeds with the handshake only if it is valid.  This
mechanism forces the attacker/client to be able to receive the
cookie, which makes DoS attacks with spoofed IP addresses difficult.
```

RFC 9147 also recommends default server-side use of the exchange:

```text
DTLS servers SHOULD perform a cookie exchange whenever a new
handshake is being performed.  If the server is being operated in an
environment where amplification is not a problem, e.g., where ICE
[RFC8445] has been used to establish bidirectional connectivity, the
server MAY be configured not to perform a cookie exchange.  The
default SHOULD be that the exchange is performed, however.
```

Invalid-cookie handling is mandatory:

```text
If a server receives a ClientHello with an invalid cookie, it MUST
terminate the handshake with an "illegal_parameter" alert.  This
allows the client to restart the connection from scratch without a
cookie.
```

RFC 9147, Section 11, "Security Considerations", describes required cookie properties:

```text
Some key properties required of the cookie for the cookie-exchange
mechanism to be functional are described in Section 3.3 of [RFC2522]:

*  The cookie MUST depend on the client's address.

*  It MUST NOT be possible for anyone other than the issuing entity
   to generate cookies that are accepted as valid by that entity.
   This typically entails an integrity check based on a secret key.
```

The expected server lifecycle is:

| Step | Expected server behavior |
|---|---|
| First ClientHello received | Decide whether to perform DTLS return-routability cookie exchange |
| HelloRetryRequest sent | Include a stateless TLS 1.3 `cookie` extension |
| Cookie construction | Bind cookie to client address and protect it with server-only integrity |
| Second ClientHello received | Verify the returned `cookie` extension |
| Cookie valid | Continue the handshake |
| Cookie invalid | Abort with fatal `illegal_parameter` |

## Code Behavior

### Client HRR Cookie Echo Is Implemented

In `ssl/tls13_client.cc`, BoringSSL's client recognizes the HRR `cookie` extension:

```cpp
SSLExtension cookie(TLSEXT_TYPE_cookie),
    key_share(TLSEXT_TYPE_key_share, !hs->pake_prover),
    supported_versions(TLSEXT_TYPE_supported_versions),
    ech_unused(TLSEXT_TYPE_encrypted_client_hello,
               hs->selected_ech_config || hs->config->ech_grease_enabled);
```

The client parses a non-empty cookie value and stores it:

```cpp
if (cookie.present) {
  CBS cookie_value;
  if (!CBS_get_u16_length_prefixed(&cookie.data, &cookie_value) ||  //
      CBS_len(&cookie_value) == 0 ||                                //
      CBS_len(&cookie.data) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  if (!hs->cookie.CopyFrom(cookie_value)) {
    return ssl_hs_error;
  }
}
```

In `ssl/extensions.cc`, the stored cookie is emitted in the next ClientHello:

```cpp
static bool ext_cookie_add_clienthello(const SSL_HANDSHAKE *hs, CBB *out,
                                       CBB *out_compressible,
                                       ssl_client_hello_type_t type) {
  if (hs->cookie.empty()) {
    return true;
  }

  CBB contents, cookie;
  if (!CBB_add_u16(out_compressible, TLSEXT_TYPE_cookie) ||
      !CBB_add_u16_length_prefixed(out_compressible, &contents) ||
      !CBB_add_u16_length_prefixed(&contents, &cookie) ||
      !CBB_add_bytes(&cookie, hs->cookie.data(), hs->cookie.size()) ||
      !CBB_flush(out_compressible)) {
    return false;
  }

  return true;
}
```

This satisfies the client echo side. It does not implement the server-side cookie exchange.

### Server HRR Construction Does Not Request a Cookie

In `ssl/tls13_server.cc`, the server HelloRetryRequest path explicitly states that it does not request a cookie:

```cpp
static enum ssl_hs_wait_t do_send_hello_retry_request(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (hs->hints_requested) {
    return ssl_hs_hints_ready;
  }

  // Although a server could HelloRetryRequest with PAKEs to request a cookie,
  // we never do so.
  assert(hs->pake_verifier == nullptr);
```

The HRR extension list contains `supported_versions` and `key_share`:

```cpp
if (!ssl->method->init_message(ssl, cbb.get(), &body, SSL3_MT_SERVER_HELLO) ||
    !CBB_add_u16(&body,
                 SSL_is_dtls(ssl) ? DTLS1_2_VERSION : TLS1_2_VERSION) ||
    !CBB_add_bytes(&body, kHelloRetryRequest, SSL3_RANDOM_SIZE) ||
    !CBB_add_u8_length_prefixed(&body, &session_id) ||
    !CBB_add_bytes(&session_id, hs->session_id.data(),
                   hs->session_id.size()) ||
    !CBB_add_u16(&body, SSL_CIPHER_get_protocol_id(hs->new_cipher)) ||
    !CBB_add_u8(&body, 0 /* no compression */) ||
    !CBB_add_u16_length_prefixed(&body, &extensions) ||
    !CBB_add_u16(&extensions, TLSEXT_TYPE_supported_versions) ||
    !CBB_add_u16(&extensions, 2 /* length */) ||
    !CBB_add_u16(&extensions, ssl->s3->version) ||
    !CBB_add_u16(&extensions, TLSEXT_TYPE_key_share) ||
    !CBB_add_u16(&extensions, 2 /* length */) ||
    !CBB_add_u16(&extensions, hs->new_session->group_id)) {
  return ssl_hs_error;
}
```

There is no `TLSEXT_TYPE_cookie` emission in this product server HRR path.

### Server Extension Layer Does Not Validate ClientHello Cookie

In `ssl/extensions.cc`, the cookie extension table entry uses server-side ignore behavior:

```cpp
{
    TLSEXT_TYPE_cookie,
    ext_cookie_add_clienthello,
    forbid_parse_serverhello,
    ignore_parse_clienthello,
    dont_add_serverhello,
},
```

This means the generic extension layer does not verify a ClientHello cookie on the server.

In `ssl/handshake_server.cc`, the JDK workaround extension-order list includes `TLSEXT_TYPE_cookie`:

```cpp
{TLSEXT_TYPE_cookie, false},
```

That is not cookie validation. It only makes the extension recognizable for an ordering workaround.

### DoS Callback Is Not the RFC 9147 Cookie Exchange

In `ssl/tls13_server.cc`, BoringSSL has a generic DoS-protection callback:

```cpp
if (ssl->ctx->dos_protection_cb != nullptr &&
    ssl->ctx->dos_protection_cb(&client_hello) == 0) {
  // Connection rejected for DOS reasons.
  OPENSSL_PUT_ERROR(SSL, SSL_R_CONNECTION_REJECTED);
  ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
  return ssl_hs_error;
}
```

This callback can reject a connection. It does not generate a stateless HRR cookie, does not bind a cookie to the client address, does not validate the returned cookie in the second ClientHello, and does not continue the handshake after successful cookie validation. It is not a substitute for RFC 9147 Section 5.1.

## Runner Coverage

The runner registers TLS 1.3 and DTLS tests from `ssl/test/runner/runner.go`:

```go
addDTLSRetransmitTests()
...
addTLS13HandshakeTests()
```

The cookie HRR tests exercise BoringSSL as the client. In `ssl/test/runner/tls13_tests.go`, the Go runner server can send an HRR cookie:

```go
testCases = append(testCases, testCase{
    name: "HelloRetryRequest-Cookie-TLS13",
    config: Config{
        MaxVersion: VersionTLS13,
        Bugs: ProtocolBugs{
            SendHelloRetryRequestCookie: []byte("cookie"),
        },
    },
})
```

Related variants include:

```text
HelloRetryRequest-DuplicateCookie-TLS13
HelloRetryRequest-EmptyCookie-TLS13
HelloRetryRequest-Cookie-Curve-TLS13
```

In `ssl/test/runner/dtls_tests.go`, DTLS retransmit scenarios can also make the runner send an HRR cookie:

```go
SendHelloRetryRequestCookie: []byte("cookie"), // Send HelloRetryRequest
```

In `ssl/test/runner/handshake_server.go`, the Go runner server checks that the BoringSSL client echoes the cookie:

```go
if len(helloRetryRequest.cookie) > 0 {
    if !bytes.Equal(newClientHello.tls13Cookie, helloRetryRequest.cookie) {
        return errors.New("tls: cookie from HelloRetryRequest not present in new ClientHello")
    }
    ignoreExtensions = append(ignoreExtensions, extensionCookie)
}
```

No runner coverage was found for:

```text
BoringSSL server generates a DTLS 1.3 stateless HRR cookie
Runner client echoes that cookie
BoringSSL server validates the second ClientHello cookie
BoringSSL server rejects an invalid cookie with illegal_parameter
```

Runner coverage therefore confirms client echo support, not product-server cookie issuance and validation.

## Runtime Evidence

A linked BoringSSL probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\repro_dtls13_hrr_cookie_probe.cpp
```

CMake target:

```text
repro_dtls13_hrr_cookie_probe
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc9147\051-100 -B D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe --config Release --target repro_dtls13_hrr_cookie_probe
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe\Release\repro_dtls13_hrr_cookie_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\repro_dtls13_hrr_cookie_probe.log
```

Observed output:

```text
linked BoringSSL DTLS_method successfully
ok: tls13_server.cc contains state13_send_hello_retry_request
ok: tls13_server.cc contains Although a server could HelloRetryRequest with PAKEs to request a cookie
ok: tls13_server.cc contains we never do so
ok: server HRR sender contains TLSEXT_TYPE_supported_versions
ok: server HRR sender contains TLSEXT_TYPE_key_share
ok: server HRR sender does not contain TLSEXT_TYPE_cookie
ok: server HRR sender does not contain hs->cookie
ok: extensions.cc contains TLSEXT_TYPE_cookie
ok: extensions.cc contains ext_cookie_add_clienthello
ok: extensions.cc contains forbid_parse_serverhello
ok: extensions.cc contains ignore_parse_clienthello
ok: extensions.cc contains dont_add_serverhello
ok: tls13_client.cc contains SSLExtension cookie(TLSEXT_TYPE_cookie)
ok: tls13_client.cc contains hs->cookie.CopyFrom(cookie_value)
ok: extensions.cc contains CBB_add_bytes(&cookie, hs->cookie.data()
ok: runner.go contains addTLS13HandshakeTests()
ok: runner.go contains addDTLSRetransmitTests()
ok: runner common.go contains SendHelloRetryRequestCookie []byte
ok: runner tls13_tests.go contains HelloRetryRequest-Cookie-TLS13
ok: runner dtls_tests.go contains SendHelloRetryRequestCookie: []byte("cookie")
ok: runner handshake_server.go contains newClientHello.tls13Cookie
RESULT: confirmed. BoringSSL client handles HRR cookie echo, but product server HRR construction never adds a cookie and there is no server-side DTLS 1.3 stateless cookie generation/verification path. Runner coverage exercises peer-sent HRR cookies against BoringSSL clients, not BoringSSL server cookie issuance and validation.
```

The probe links against BoringSSL, creates a `DTLS_method()` context, and checks product and runner source predicates for client cookie echo support, server HRR cookie omission, server extension behavior, and runner coverage shape.

## Inconsistency

| RFC 9147 server-side requirement | BoringSSL behavior |
|---|---|
| Server can send an HRR cookie for DTLS return-routability | Product server HRR does not emit `TLSEXT_TYPE_cookie` |
| Cookie depends on the client address | No product cookie construction or address-binding path found |
| Cookie cannot be forged by non-issuer | No product integrity-protected stateless cookie path found |
| Server verifies returned cookie in second ClientHello | Server extension layer uses `ignore_parse_clienthello` for `cookie` |
| Invalid cookie terminates handshake with `illegal_parameter` | No dedicated invalid-cookie validation branch found |
| Runner proves product-server cookie behavior | Runner covers BoringSSL client echoing a Go-runner-sent cookie |

The implementation therefore satisfies the client echo portion, but not the DTLS 1.3 server return-routability cookie exchange required for this finding.

## Root Cause

BoringSSL's TLS 1.3 HRR cookie support is implemented as a client-side echo mechanism. The product server HRR path is key-share driven and emits only `supported_versions` and `key_share`. The code explicitly states that the server never requests a cookie.

Because the server never sends an HRR cookie, the rest of the server-side state machine is also absent:

```text
construct stateless cookie
bind cookie to client address
protect cookie with server-only integrity
send cookie in HelloRetryRequest
parse returned cookie in second ClientHello
validate returned cookie
reject invalid cookie with illegal_parameter
```

## Impact

This is a DTLS 1.3 server-side protocol feature and DoS-countermeasure gap.

| Impact area | Description |
|---|---|
| Return-routability | BoringSSL server cannot use RFC 9147's HRR cookie exchange to prove the peer can receive packets at its source address. |
| DoS mitigation | The default RFC-recommended cookie exchange is not implemented by the product server path. |
| Protocol conformance | Invalid-cookie `illegal_parameter` behavior cannot be exercised because there is no validation path. |
| Test coverage | Existing runner tests validate BoringSSL as client, not BoringSSL as server issuing and checking cookies. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as missing DTLS 1.3 server-side HRR cookie generation and validation.

## Suggested Fix

To satisfy RFC 9147 server-side HRR cookie behavior, BoringSSL would need:

| Required change | Expected effect |
|---|---|
| Add a DTLS 1.3 server policy/API for HRR cookie exchange | Allows deployments to enable the return-routability check, ideally by default where appropriate |
| Construct stateless cookies bound to client address and ClientHello context | Matches RFC 9147 and Section 11 security properties |
| Protect cookies with server-only integrity | Prevents non-issuers from generating accepted cookies |
| Emit `TLSEXT_TYPE_cookie` from the server HRR path | Sends the cookie to the client |
| Parse and validate the returned ClientHello cookie | Allows the server to proceed only when the cookie is valid |
| Send fatal `illegal_parameter` for invalid cookies | Matches RFC 9147 invalid-cookie behavior |
| Add runner tests with BoringSSL as server | Covers valid cookie, invalid cookie, missing cookie, and configured no-cookie modes |
