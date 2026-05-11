# HelloVerifyRequest Cookie 255 Byte Limit Partially Implemented

## Summary

BoringSSL's production client-side `HelloVerifyRequest` parser accepts the DTLS 1.2 one-byte-length cookie vector, so 255-byte cookies are supported there. However, the in-repo DTLS test runner still rejects `HelloVerifyRequest` cookies longer than 32 bytes, which is the old DTLS limit. This is a confirmed partial issue in repository test/interoperability behavior rather than the shipped client parser.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc6347

Section: RFC 6347 Section 4.2.2, Handshake Message Format

```text
opaque cookie<0..2^8-1>;
```

RFC 6347 raises the DTLS cookie vector to a one-byte length range, allowing values from 0 through 255 bytes.

## Relevant Source Code

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

`ssl/test/runner/handshake_messages.go:3007`

```go
	cookieLen := int(data[6])
	if cookieLen > 32 || len(data) != 7+cookieLen {
		return false
	}
```

`ssl/test/runner/basic_tests.go:1790`

```go
			// DTLS 1.2 allows up to a 255-byte HelloVerifyRequest cookie, which
			// is larger than the DTLS 1.0 limit of 32 bytes.
```

The C++ client path uses a generic one-byte-length-prefixed parser. The Go runner parser has a hard-coded `cookieLen > 32` rejection despite nearby tests documenting the DTLS 1.2 255-byte limit.

## Implementation Behavior

Implemented part: production `libssl` client handling parses the `HelloVerifyRequest` cookie as a `CBS_get_u8_length_prefixed` vector and copies the full value to `hs->dtls_cookie`. That matches the RFC field width.

Missing or inconsistent part: the test runner's `helloVerifyRequestMsg.unmarshal` still applies `cookieLen > 32`, so it cannot parse the 255-byte DTLS 1.2 cookie it should model. This can mask or distort interoperability tests around the RFC 6347 limit.

## Inconsistency Reason

The RFC allows a 255-byte cookie. BoringSSL production client code is consistent with that. The runner code, however, rejects cookies above 32 bytes. Because the repository includes the runner as the protocol peer used for DTLS behavior tests, the overall evidence is partial: the implementation path is correct, but the test peer/parser retains obsolete behavior.

## Runtime Evidence

Focused verification script: `verify_dtls12_cookie_paths.py`

Log: `verify_dtls12_cookie_paths.log`

Result summary:

```text
passed=true
runner still rejects HelloVerifyRequest cookies above 32 bytes
client parses HelloVerifyRequest and copies cookie
```

No prebuilt BoringSSL test binary was present, so the verification used executable source checks against the exact parser files.

## Impact

Production client interoperability with 255-byte cookies appears supported. The runner inconsistency can still cause false negatives or prevent accurate tests for peers that send valid 33..255 byte DTLS 1.2 cookies.

## Fix Direction

Change `helloVerifyRequestMsg.unmarshal` in the DTLS runner to allow `cookieLen <= 255` for DTLS 1.2. Add a runner unit or handshake test that unmarshals and processes a 255-byte `HelloVerifyRequest` cookie.
