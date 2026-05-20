# DTLS 1.3 Non-Zero legacy_cookie Is Not Rejected

## Summary

RFC 9147 requires a DTLS 1.3 server to abort the handshake with an `illegal_parameter` alert when it receives a ClientHello whose legacy `cookie` field is non-empty.

BoringSSL parses and exposes the DTLS ClientHello legacy cookie field, but the DTLS 1.3 server handshake path does not validate that the field is zero length. As a result, a malformed DTLS 1.3 ClientHello with a non-zero `legacy_cookie` is accepted by the parser and is not rejected by the server-side version-specific validation path.

This confirms RFC 9147 IDs 102 and 108 as **not satisfied**. Both IDs have the same root cause.

## Standard Requirement

RFC 9147, Section 5.3, "ClientHello Message":

```text
legacy_cookie:  A DTLS 1.3-only client MUST set the legacy_cookie
   field to zero length.  If a DTLS 1.3 ClientHello is received with
   any other value in this field, the server MUST abort the handshake
   with an "illegal_parameter" alert.
```

This is a server-side input-validation requirement. The valid relationship is:

| Received ClientHello state | Expected server behavior |
|---|---|
| DTLS 1.3 ClientHello with zero-length `legacy_cookie` | Continue processing |
| DTLS 1.3 ClientHello with non-zero `legacy_cookie` | Abort with fatal `illegal_parameter` |
| DTLS 1.2 ClientHello carrying an HVR cookie | Not governed by this DTLS 1.3 rule |

The rule is independent from the TLS 1.3 `cookie` extension. It applies to the legacy DTLS ClientHello cookie vector that remains in the DTLS 1.3 ClientHello structure.

## Code Behavior

### Decode Path Exposes the legacy_cookie Field

In `ssl/extensions.cc`, BoringSSL's generic ClientHello parser reads the DTLS cookie vector and stores both a pointer and a length in the parsed `SSL_CLIENT_HELLO` structure:

```cpp
if (SSL_is_dtls(out->ssl)) {
  CBS cookie;
  if (!CBS_get_u8_length_prefixed(cbs, &cookie)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    return false;
  }
  out->dtls_cookie = CBS_data(&cookie);
  out->dtls_cookie_len = CBS_len(&cookie);
}
```

This decode behavior is structurally correct for reading a DTLS ClientHello. It also means the server has enough parsed state to enforce RFC 9147 Section 5.3 after it determines that the handshake is DTLS 1.3.

### Server Handshake Continues Without the Required Validation

In `ssl/handshake_server.cc`, the server parses the ClientHello, negotiates the protocol version, and then continues into normal ClientHello extension processing:

```cpp
if (!SSL_parse_client_hello(ssl, &client_hello, CBS_data(&msg.body),
                            CBS_len(&msg.body))) {
  ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
  return ssl_hs_error;
}

if (!negotiate_version(hs, &alert, &client_hello)) {
  ssl_send_alert(ssl, SSL3_AL_FATAL, alert);
  return ssl_hs_error;
}

if (!ssl_parse_clienthello_tlsext(hs, &client_hello)) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
  return ssl_hs_error;
}
```

The checked server handshake file does not reference `dtls_cookie_len`. There is no branch equivalent to:

```cpp
if (SSL_is_dtls(ssl) &&
    ssl_protocol_version(ssl) >= TLS1_3_VERSION &&
    client_hello.dtls_cookie_len != 0) {
  ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
  return ssl_hs_error;
}
```

Therefore, BoringSSL implements the generic DTLS ClientHello cookie parser, but it does not implement the DTLS 1.3-specific rejection rule for a non-zero legacy cookie.

### Runner Coverage Is Not a Product-Server Validation Test

The BoringSSL runner code has parser-level awareness of the DTLS cookie field, and runner-side helper comments note that DTLS 1.3 forbids the legacy cookie. However, `ssl/test/runner/runner.go` does not contain a named shim test that sends a DTLS 1.3 ClientHello with a non-zero legacy cookie to the BoringSSL server and expects an `illegal_parameter` alert.

Thus the runner material does not cover the product-code server validation gap described above.

## Runtime Evidence

A linked BoringSSL probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\repro_dtls13_legacy_cookie_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc9147\101-150 -B D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe --config Release --target repro_dtls13_legacy_cookie_probe
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe\Release\repro_dtls13_legacy_cookie_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\repro_dtls13_legacy_cookie_probe.log
```

Observed output:

```text
linked BoringSSL probe: PASS
parser behavior: non-zero DTLS legacy_cookie is accepted and exposed as dtls_cookie_len=1
server behavior: ssl/handshake_server.cc has no dtls_cookie_len rejection path
runner coverage: parser helper comments know DTLS 1.3 forbids legacy cookie, but runner.go has no named shim test for non-zero legacy_cookie rejection
conclusion: RFC 9147 IDs 102 and 108 are confirmed unsatisfied with the same root cause
```

The probe constructs a minimal DTLS ClientHello body with a one-byte legacy cookie, calls `SSL_parse_client_hello`, and verifies that BoringSSL accepts the message and reports `dtls_cookie_len == 1`. It then checks the server handshake source for the absence of a `dtls_cookie_len` rejection path.

## Inconsistency

| Requirement or expected check | BoringSSL behavior |
|---|---|
| DTLS 1.3 ClientHello with non-zero `legacy_cookie` must be rejected | The parser accepts and exposes the field as `dtls_cookie_len == 1` |
| Server must abort with `illegal_parameter` | No server-side `dtls_cookie_len != 0` branch was found |
| DTLS 1.3 legacy cookie validation should be covered by a server test | No named runner shim test for this rejection case was found |

The inconsistency is not that BoringSSL cannot parse the field. The inconsistency is that parsing succeeds, but the required DTLS 1.3 server-side validation is not applied.

## Root Cause

The DTLS ClientHello parser is shared across DTLS versions and treats the legacy cookie vector as a syntactic field. That is appropriate for decoding. However, after the server negotiates DTLS 1.3, the handshake path does not apply the RFC 9147 Section 5.3 rule that this field must be zero length.

The DTLS 1.2 HelloVerifyRequest cookie mechanism and DTLS 1.3 TLS `cookie` extension are separate protocol mechanisms. Support for either one does not satisfy this DTLS 1.3 legacy-cookie rejection requirement.

## Impact

This is a protocol conformance and input-validation issue.

| Impact area | Description |
|---|---|
| Protocol compliance | A malformed DTLS 1.3 ClientHello can proceed instead of being rejected as required by RFC 9147. |
| Interoperability | Strict peers and conformance tests may expect a fatal `illegal_parameter` alert for this case. |
| Test coverage | The runner does not currently pin the server behavior for this invalid ClientHello shape. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as missing DTLS 1.3 server-side validation for a malformed ClientHello field.

## Suggested Fix

Add a DTLS 1.3-only validation check after server version negotiation and before TLS extension processing:

```cpp
if (SSL_is_dtls(ssl) &&
    ssl_protocol_version(ssl) >= TLS1_3_VERSION &&
    client_hello.dtls_cookie_len != 0) {
  ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
  return ssl_hs_error;
}
```

The check should not apply to DTLS 1.2, where the legacy ClientHello cookie field is used by the HelloVerifyRequest mechanism.

Regression coverage should include:

| Test case | Expected result |
|---|---|
| DTLS 1.3 ClientHello with zero-length `legacy_cookie` | Continue normal handshake processing |
| DTLS 1.3 ClientHello with non-zero `legacy_cookie` | Abort with fatal `illegal_parameter` |
| DTLS 1.2 ClientHello carrying an HVR cookie | Preserve DTLS 1.2 behavior |
