# HVR server_version Is Parsed But Not Retained for an Explicit ServerHello Match Check

## Summary

RFC 6347 requires the client to verify that the server version in the HelloVerifyRequest matches the version later used in the ServerHello. BoringSSL parses the HelloVerifyRequest `server_version`, but it does not retain that value and does not perform an explicit equality check against the later ServerHello version.

The client still behaves correctly for the rest of the DTLS handshake, and the product parser does read the HVR version field. The missing piece is the explicit HVR-to-ServerHello version comparison described by RFC 6347. This confirms ID 076 as **partially satisfied**.

## Standard Requirement

RFC 6347, Section 4.2.1, "Denial-of-Service Countermeasures":

```text
The server MUST use the same version number in the HelloVerifyRequest
that it would use when sending a ServerHello.  Upon receipt of the
ServerHello, the client MUST verify that the server version values
match.
```

This is a client-side consistency check after a HelloVerifyRequest exchange:

| Step | Expected behavior |
|---|---|
| Receive HelloVerifyRequest | Parse and remember the server_version |
| Receive ServerHello | Compare the ServerHello version with the remembered HVR version |
| Versions match | Continue the handshake |
| Versions differ | Reject the handshake |

The requirement is not merely to parse the HVR version field. It is to verify that the later ServerHello matches it.

## Code Behavior

### HVR Parser Reads server_version

In `ssl/handshake_client.cc`, BoringSSL parses `server_version` from `HelloVerifyRequest`:

```cpp
  CBS hello_verify_request = msg.body, cookie;
  uint16_t server_version;
  if (!CBS_get_u16(&hello_verify_request, &server_version) ||
      !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
      CBS_len(&hello_verify_request) != 0) {
    ...
  }
```

It then stores the cookie and marks the HVR as received:

```cpp
  if (!hs->dtls_cookie.CopyFrom(cookie)) {
    ...
  }
  hs->received_hello_verify_request = true;
```

The parsed `server_version` is not retained in the handshake state.

### Handshake State Retains Cookie, Not HVR Version

In `ssl/internal.h`, the relevant handshake fields include the DTLS cookie and a boolean HVR marker:

```cpp
  Array<uint8_t> dtls_cookie;
  ...
  bool received_hello_verify_request : 1;
```

There is no retained HelloVerifyRequest `server_version` field in the handshake state.

### ServerHello Version Is Parsed Independently

Later, `ssl/handshake_client.cc` parses the ServerHello and derives the negotiated version from the ServerHello itself:

```cpp
  ParsedServerHello server_hello;
  uint16_t server_version;
  ...
  if (!ssl_parse_server_hello(&server_hello, &alert, msg) ||
      !parse_server_version(hs, &server_version, &alert, server_hello)) {
    ...
  }
```

If the initial handshake completes, BoringSSL sets the negotiated version from that ServerHello version:

```cpp
  if (!ssl->s3->initial_handshake_complete) {
    ...
    ssl->s3->version = server_version;
```

The checked source does not contain an explicit comparison between the remembered HelloVerifyRequest version and the later ServerHello version.

## Runner Coverage

`ssl/test/runner/runner.go` registers DTLS tests, but the relevant HVR client check is exercised in product client code rather than by a dedicated product-server path.

The runner is not needed to demonstrate the specific issue here. The missing behavior is in the product client's explicit HVR-to-ServerHello version comparison.

## Runtime Evidence

A linked probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\repro_dtls12_hvr_serverhello_version_linked_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```text
cmake --build D:\project\SpecTrace\test-boringssl\rfc6347\051-098\build-linked-probe --config Release --target repro_dtls12_hvr_serverhello_version_linked_probe
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\build-linked-probe\Release\repro_dtls12_hvr_serverhello_version_linked_probe.exe D:\project\boringssl-main
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\repro_dtls12_hvr_serverhello_version_linked_probe.log
```

Observed output:

```text
LINK SSL_CTX_new(DTLS_method): PASS
LINK DTLS1_2_VERSION min/max: PASS
LINK OpenSSL_version: BoringSSL
HVR parser reads server_version into a local variable: PASS
HVR parser stores cookie but not server_version: PASS
SSL_HANDSHAKE state has dtls_cookie but no HVR server_version field: PASS
ServerHello parsing derives version from ServerHello only: PASS
No explicit HVR-to-ServerHello server_version equality check: PASS
received_hello_verify_request occurrences in client: 5

EXIT_CODE: 0
```

The probe links against BoringSSL and checks the source predicates for HVR parsing, handshake-state retention, and the absence of an explicit HVR-to-ServerHello equality check.

## Inconsistency

| RFC 6347 requirement component | BoringSSL behavior |
|---|---|---|
| Parse HelloVerifyRequest `server_version` | Implemented |
| Retain the HVR version for later comparison | Not implemented |
| Verify that the later ServerHello version matches the HVR version | No explicit check found |
| Continue only when the versions match | Not explicitly enforced |

The implementation therefore satisfies the parsing half of the requirement but not the explicit version-match check.

## Root Cause

BoringSSL's DTLS client records the HVR cookie and a received-HVR flag, but not the HelloVerifyRequest `server_version`. The later ServerHello version is parsed independently and becomes the negotiated version without an explicit comparison to the earlier HVR version.

That is why the issue is partial rather than fully unsatisfied: the parser handles the HVR structure, but the explicit RFC 6347 version-match verification step is not implemented.

## Impact

This is a DTLS 1.2 client-side protocol-validation gap.

| Impact area | Description |
|---|---|
| Protocol conformance | The explicit HVR-to-ServerHello version comparison is missing. |
| Handshake validation | The handshake relies on later ServerHello parsing without retaining the earlier HVR version. |
| Interoperability evidence | A mismatched server_version in the HVR would not be rejected through an explicit compare path. |
| Parsing correctness | The HVR message is still parsed correctly. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as missing explicit verification of the HelloVerifyRequest version against the later ServerHello.

## Suggested Fix

Retain the parsed HelloVerifyRequest `server_version` in handshake state and compare it against the ServerHello version when the ServerHello arrives.

| Required change | Expected effect |
|---|---|
| Store HVR `server_version` in handshake state | Makes the RFC comparison possible |
| Compare HVR version to the later ServerHello version | Enforces RFC 6347 matching behavior |
| Reject mismatched values | Matches the client-side verification rule |
| Add regression coverage | Pins the HVR/ServerHello version match requirement |
