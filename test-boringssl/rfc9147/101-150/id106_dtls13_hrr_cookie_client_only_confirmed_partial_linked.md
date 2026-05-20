# DTLS 1.3 HRR Cookie Is Client-Only in Product Code

## Summary

RFC 9147 reuses the TLS 1.3 HelloRetryRequest `cookie` extension as a DTLS 1.3 return-routability mechanism. The complete behavior has two sides:

```text
server sends a stateless cookie in HelloRetryRequest
client echoes the cookie in the second ClientHello
server verifies the returned cookie before continuing
```

BoringSSL implements the client-side TLS 1.3 HRR cookie behavior. A client can parse a cookie extension from HelloRetryRequest, store it, and send it back in the second ClientHello.

The product server side is missing for DTLS 1.3. BoringSSL's server HRR path does not generate a stateless cookie, does not send `TLSEXT_TYPE_cookie` in HelloRetryRequest, and does not validate a returned cookie in the second ClientHello. This confirms RFC 9147 ID 106 as **partially satisfied**.

This issue is separate from the DTLS ClientHello `legacy_cookie` field covered by IDs 102 and 108. ID 106 concerns the TLS 1.3 `cookie` extension carried in HelloRetryRequest and then echoed in the second ClientHello.

## Standard Requirement

RFC 9147, Section 5.1, "Denial-of-Service Countermeasures":

```text
DTLS reuses TLS 1.3's "cookie" extension to provide a
return-routability check as part of connection establishment.
```

The same section describes the HelloRetryRequest cookie exchange:

```text
When the client sends its ClientHello message to the server, the server
MAY respond with a HelloRetryRequest message.  The HelloRetryRequest
message, as well as the "cookie" extension, is defined in TLS 1.3.
The HelloRetryRequest message contains a stateless cookie (see
[TLS13], Section 4.2.2).  The client MUST send a new ClientHello with
the cookie added as an extension.  The server then verifies the
cookie and proceeds with the handshake only if it is valid.
```

RFC 9147 also states:

```text
DTLS 1.3 reuses the HelloRetryRequest message and
conveys the cookie to the client via an extension.  The client
receiving the cookie uses the same extension to place the cookie
subsequently into a ClientHello message.
```

For an implementation that supports the DTLS 1.3 HRR cookie exchange, the expected lifecycle is:

| Step | Expected behavior |
|---|---|
| First ClientHello arrives | Server decides whether a return-routability check is needed |
| HelloRetryRequest is sent | Server includes a stateless `cookie` extension |
| Second ClientHello arrives | Client includes the received `cookie` extension |
| Cookie is valid | Server continues the handshake |
| Cookie is invalid | Server terminates the handshake with `illegal_parameter` |

## Code Behavior

### Client Parses HRR Cookie

In `ssl/tls13_client.cc`, BoringSSL's TLS 1.3 client recognizes the `cookie` extension in HelloRetryRequest:

```cpp
SSLExtension cookie(TLSEXT_TYPE_cookie),
    key_share(TLSEXT_TYPE_key_share, !hs->pake_prover),
    supported_versions(TLSEXT_TYPE_supported_versions),
    ech_unused(TLSEXT_TYPE_encrypted_client_hello,
               hs->selected_ech_config || hs->config->ech_grease_enabled);
```

If the extension is present, the client requires a non-empty `uint16` length-prefixed value and stores it in `hs->cookie`:

```cpp
if (cookie.present) {
  CBS cookie_value;
  if (!CBS_get_u16_length_prefixed(&cookie.data, &cookie_value) ||
      CBS_len(&cookie_value) == 0 ||
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

This satisfies the client parsing portion of the HRR cookie exchange.

### Client Echoes HRR Cookie

In `ssl/extensions.cc`, BoringSSL serializes the stored HRR cookie into the next ClientHello:

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

This satisfies the client echo portion of the HRR cookie exchange.

### Product Server Does Not Generate an HRR Cookie

In `ssl/tls13_server.cc`, the server HelloRetryRequest writer constructs a ServerHello-formatted HRR and emits `supported_versions` and `key_share` extensions:

```cpp
if (!ssl->method->init_message(ssl, cbb.get(), &body, SSL3_MT_SERVER_HELLO) ||
    !CBB_add_u16(&body,
                 SSL_is_dtls(ssl) ? DTLS1_2_VERSION : TLS1_2_VERSION) ||
    !CBB_add_bytes(&body, kHelloRetryRequest, SSL3_RANDOM_SIZE) ||
    ...
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

No `TLSEXT_TYPE_cookie` extension is emitted by this product server HRR path.

The file also contains an explicit implementation note:

```cpp
// Although a server could HelloRetryRequest with PAKEs to request a cookie,
// we never do so.
```

This confirms that the product server does not request an HRR cookie.

### Product Server Does Not Validate a Returned HRR Cookie

After HelloRetryRequest, the server reads the second ClientHello and validates properties such as the selected key share and transcript consistency. The checked product server code does not contain a stateless HRR cookie generation or validation path.

The linked probe checked `ssl/tls13_server.cc` for server-side cookie markers including `TLSEXT_TYPE_cookie`, `cookie.CopyFrom`, invalid-cookie handling, and cookie assignment in the server HRR path. No product server generation or verification path was found.

## Runner Coverage

The runner has explicit knobs and tests for BoringSSL-as-client HRR cookie handling:

```text
SendHelloRetryRequestCookie
HelloRetryRequest-Cookie-TLS13
HelloRetryRequest-DuplicateCookie-TLS13
HelloRetryRequest-EmptyCookie-TLS13
HelloRetryRequest-Cookie-Curve-TLS13
```

In `ssl/test/runner/handshake_server.go`, the Go runner server can simulate a HelloRetryRequest cookie and require the BoringSSL client to echo it:

```go
if config.Bugs.SendHelloRetryRequestCookie != nil {
    sendHelloRetryRequest = true
    helloRetryRequest.cookie = config.Bugs.SendHelloRetryRequestCookie
}

if len(helloRetryRequest.cookie) > 0 {
    if !bytes.Equal(newClientHello.tls13Cookie, helloRetryRequest.cookie) {
        return errors.New("tls: cookie from HelloRetryRequest not present in new ClientHello")
    }
    ignoreExtensions = append(ignoreExtensions, extensionCookie)
}
```

This runner coverage validates BoringSSL's client behavior. It does not prove that BoringSSL's product server generates or validates DTLS 1.3 HRR cookies, because the cookie-generating server in this test path is the Go runner, not `ssl/tls13_server.cc`.

## Runtime Evidence

A linked BoringSSL probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\repro_dtls13_hrr_cookie_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc9147\101-150 -B D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe --config Release --target repro_dtls13_hrr_cookie_probe
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe\Release\repro_dtls13_hrr_cookie_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\repro_dtls13_hrr_cookie_probe.log
```

Observed output:

```text
linked BoringSSL probe: PASS
client behavior: HRR cookie extension is parsed, stored, and echoed in the second ClientHello
server behavior: product HRR sends supported_versions/key_share only and explicitly never requests a cookie
server verification: no product stateless HRR cookie generation or validation path was found in tls13_server.cc
runner coverage: runner covers BoringSSL as client handling HRR cookie; runner server can simulate SendHelloRetryRequestCookie
conclusion: RFC 9147 ID 106 is confirmed partially satisfied
```

The probe confirms linkage with `DTLS_method()`, then checks the relevant product and runner source predicates for client support, server omission, and runner coverage shape.

## Inconsistency

| Requirement component | BoringSSL behavior |
|---|---|
| Client must echo an HRR cookie in the second ClientHello | Implemented |
| Server may use HRR cookie for DTLS 1.3 return-routability | Product server has no cookie-generation path |
| Server using this exchange must verify the returned cookie | Product server has no validation path |
| Invalid returned cookie must cause `illegal_parameter` | No product server invalid-cookie branch was found |
| Runner should cover product server generation and validation if supported | Runner coverage is client-oriented |

The result is partial satisfaction: BoringSSL supports the generic TLS 1.3 client-side HRR cookie extension, but does not implement the DTLS 1.3 product-server return-routability cookie exchange.

## Root Cause

BoringSSL's HRR implementation is centered on key-share retry. On the client side, the implementation is generic enough to process and echo the TLS 1.3 `cookie` extension. On the server side, the product HRR writer only emits `supported_versions` and `key_share`, and the code explicitly states that the server never requests a cookie.

There is therefore no DTLS 1.3 server state machine for:

```text
construct stateless cookie
send cookie in HelloRetryRequest
receive second ClientHello
validate returned cookie
reject invalid cookie with illegal_parameter
```

## Impact

This is a protocol feature-completeness and conformance gap for DTLS 1.3 server deployments that require RFC 9147 return-routability checks.

| Impact area | Description |
|---|---|
| Return-routability | The product server cannot use the RFC 9147 HRR cookie exchange to validate the peer address before continuing. |
| Protocol conformance | The client half is present, but the server half of the described DTLS 1.3 cookie exchange is absent. |
| Test coverage | Existing runner tests cover BoringSSL as the client, not BoringSSL as the product server generating and validating the cookie. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as missing DTLS 1.3 server-side HRR cookie support.

## Suggested Fix

To fully support the RFC 9147 DTLS 1.3 HRR cookie exchange, BoringSSL would need:

| Change | Expected effect |
|---|---|
| Add a DTLS 1.3 server policy/API for HRR cookie use | Lets applications or the stack request a return-routability check |
| Construct a stateless cookie bound to the client address and ClientHello context | Prevents accepting an unauthenticated reflected cookie |
| Emit `TLSEXT_TYPE_cookie` from the server HRR path | Sends the cookie to the client |
| Parse and validate the returned second-ClientHello cookie | Completes the return-routability check |
| Reject invalid cookies with `illegal_parameter` | Matches RFC 9147 behavior |
| Add runner tests with BoringSSL as server | Pins product server generation and validation behavior |
