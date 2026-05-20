# DTLS 1.2 HelloVerifyRequest Cookie 255-Byte Limit Is Only Partially Reflected

## Summary

RFC 6347 allows the DTLS 1.2 HelloVerifyRequest cookie to be up to 255 bytes. BoringSSL's product DTLS client parser follows that rule: it parses the cookie as an 8-bit length-prefixed field and stores the full value.

The remaining mismatch is in the in-repository Go runner. The runner still rejects HelloVerifyRequest cookies above 32 bytes in its unmarshal logic, even though nearby DTLS 1.2 test data acknowledges the 255-byte limit. This means the shipped product parser is fine, but the test peer still carries an obsolete DTLS 1.0-era cap.

This confirms RFC 6347 ID 023 as **partially satisfied**.

## Standard Requirement

RFC 6347, Section 4.2.2, "Handshake Message Format":

```text
opaque cookie<0..2^8-1>;                             // New field
```

The `HelloVerifyRequest` structure uses the same cookie vector:

```text
struct {
  ProtocolVersion server_version;
  opaque cookie<0..2^8-1>;
} HelloVerifyRequest;
```

RFC 6347 also explicitly states:

```text
In DTLS 1.2, the cookie size limit has been increased to 255 bytes for greater future flexibility.
```

So a DTLS 1.2 HelloVerifyRequest parser must accept cookie lengths in the range 0..255 bytes, subject to normal message validity.

## Code Behavior

### Product Client Parser Uses the RFC 6347 Limit

In `ssl/handshake_client.cc`, BoringSSL parses `HelloVerifyRequest` using an 8-bit length-prefixed cookie field:

```cpp
CBS hello_verify_request = msg.body, cookie;
uint16_t server_version;
if (!CBS_get_u16(&hello_verify_request, &server_version) ||
    !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
    CBS_len(&hello_verify_request) != 0) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
  ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
  return false;
}
```

It then copies the full parsed cookie:

```cpp
if (!hs->dtls_cookie.CopyFrom(cookie)) {
  ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
  return false;
}
```

There is no obsolete 32-byte cap in this product client parser.

### Runner Still Rejects Cookies Above 32 Bytes

The Go runner models `HelloVerifyRequest` in `ssl/test/runner/handshake_messages.go`:

```go
type helloVerifyRequestMsg struct {
  raw    []byte
  vers   uint16
  cookie []byte
}
```

Its marshaler writes the cookie length as a single byte:

```go
x[6] = uint8(len(m.cookie))
copy(x[7:7+len(m.cookie)], m.cookie)
```

But the unmarshaler still rejects cookies above 32 bytes:

```go
cookieLen := int(data[6])
if cookieLen > 32 || len(data) != 7+cookieLen {
  return false
}
m.cookie = data[7 : 7+cookieLen]
```

This is inconsistent with RFC 6347's 255-byte limit.

Nearby runner test data acknowledges the correct limit:

```go
// DTLS 1.2 allows up to a 255-byte HelloVerifyRequest cookie, which
// is the largest encodable value.
```

## Runner Coverage

The runner therefore contains both:

| Item | Status |
|---|---|
| A test vector acknowledging a 255-byte DTLS 1.2 cookie | Present |
| A `HelloVerifyRequest` unmarshal path that still rejects cookies above 32 bytes | Present |

This means the repository's protocol peer can reject valid DTLS 1.2 HelloVerifyRequest messages in the 33..255 byte range, even though the product client parser is already correct.

## Runtime Evidence

A linked C++ harness was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\001-050\repro_dtls12_hvr_cookie_255_limit_linked_probe.cpp
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
cmake --build D:\project\SpecTrace\test-boringssl\rfc6347\001-050\build-linked-probe --config Release --target repro_dtls12_hvr_cookie_255_limit_linked_probe
D:\project\SpecTrace\test-boringssl\rfc6347\001-050\build-linked-probe\Release\repro_dtls12_hvr_cookie_255_limit_linked_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\001-050\repro_dtls12_hvr_cookie_255_limit_linked_probe.log
```

Observed output:

```text
LINK SSL_CTX_new(DTLS_method): PASS
LINK DTLS1_2_VERSION min/max: PASS
LINK OpenSSL_version: BoringSSL
PRODUCT HVR parser uses u8 length-prefixed cookie: PASS
PRODUCT HVR parser has no obsolete 32-byte cookie cap: PASS
RUNNER HVR unmarshal rejects cookieLen > 32: PASS
RUNNER has DTLS-HelloVerifyRequest-255 test vector: PASS
RUNNER comments acknowledge RFC 6347 255-byte limit: PASS

EXIT_CODE: 0
```

The harness links BoringSSL and checks that the product parser matches the RFC while the runner parser still enforces the obsolete 32-byte limit.

## Inconsistency

| RFC 6347 requirement component | BoringSSL behavior |
|---|---|
| DTLS 1.2 HelloVerifyRequest cookie may be up to 255 bytes | Product client parser accepts the RFC-sized field |
| Cookie should be parsed as an 8-bit length-prefixed vector | Product client parser uses `CBS_get_u8_length_prefixed` |
| Test peer should model the same RFC limit | Runner unmarshaler still rejects cookies above 32 bytes |

The inconsistency is therefore limited to the repository runner/test peer, not the product parser.

## Root Cause

BoringSSL's product DTLS client parser was updated to use the correct 8-bit cookie vector. The Go runner's `helloVerifyRequestMsg.unmarshal`, however, still carries a legacy 32-byte cap.

The correct runner behavior should be:

```text
accept any cookie length from 0 to 255 bytes
```

Instead, the runner only accepts:

```text
cookieLen <= 32
```

## Impact

This is mainly a test-peer fidelity issue.

| Impact area | Description |
|---|---|
| Product compliance | The shipped BoringSSL client parser is aligned with RFC 6347. |
| Test fidelity | The runner may reject valid 33..255 byte HelloVerifyRequest cookies. |
| Interoperability evidence | A conforming DTLS 1.2 peer using a large cookie may not be modeled accurately in tests. |
| Regression risk | The obsolete 32-byte cap can hide or distort boundary coverage around the RFC limit. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as runner-side mismatch with the RFC 6347 maximum cookie size.

## Suggested Fix

Update `ssl/test/runner/handshake_messages.go` so `helloVerifyRequestMsg.unmarshal` accepts RFC-valid cookie lengths up to 255 bytes.

The simplest fix is to remove the obsolete 32-byte cap:

```go
if len(data) != 7+cookieLen {
  return false
}
```

or, if a length check is preferred for clarity:

```go
if cookieLen > 255 || len(data) != 7+cookieLen {
  return false
}
```

Since `cookieLen` is already read from one byte, the explicit `> 255` check is redundant. Regression coverage should include a DTLS 1.2 HelloVerifyRequest with a 255-byte cookie and at least one value in the 33..255 range.
