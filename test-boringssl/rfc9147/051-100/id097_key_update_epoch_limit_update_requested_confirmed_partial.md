# KeyUpdate update_requested Is Not Ignored at the DTLS Epoch Limit

## Summary

RFC 9147 modifies TLS 1.3 KeyUpdate behavior for DTLS. If an endpoint receives a KeyUpdate with `update_requested`, but sending its own responsive KeyUpdate would exceed the DTLS sending limits, it must not send that KeyUpdate and should ignore the `update_requested` flag.

BoringSSL implements normal TLS/DTLS 1.3 KeyUpdate behavior. It receives KeyUpdate messages, sends a response to `update_requested`, defers DTLS sending-key rotation until the KeyUpdate is ACKed, and has runner coverage for ordinary DTLS KeyUpdate flows.

The limit behavior is only partially aligned. BoringSSL's DTLS epoch model is `uint16_t` and fails at `0xffff` with `SSL_R_TOO_MANY_KEY_UPDATES`. When `tls13_receive_key_update` receives `update_requested`, it unconditionally attempts to send a response KeyUpdate with `SSL_KEY_UPDATE_NOT_REQUESTED`. There is no branch that checks whether the response would exceed the DTLS sending limit and then ignores `update_requested`. This confirms RFC 9147 ID 097 as **partially satisfied**.

## Standard Requirement

RFC 9147, Section 4.2, "Sequence Number and Epoch":

```text
The epoch number is initially zero and is incremented each time
keying material changes and a sender aims to rekey.  More details are
provided in Section 6.1.
```

RFC 9147, Section 4.2.1, "Processing Guidelines":

```text
Implementations MUST NOT allow the epoch to wrap, but instead MUST
establish a new association, terminating the old association.
```

RFC 9147, Section 8, "Key Updates":

```text
As with TLS 1.3, DTLS 1.3 implementations send a KeyUpdate message to
indicate that they are updating their sending keys.  As with other
handshake messages with no built-in response, KeyUpdates MUST be
acknowledged.  In order to facilitate epoch reconstruction
(Section 4.2.2), implementations MUST NOT send records with the new
keys or send a new KeyUpdate until the previous KeyUpdate has been
acknowledged (this avoids having too many epochs in active use).
```

RFC 9147 then defines the epoch limit and the `update_requested` exception:

```text
With a 128-bit key as in AES-128, rekeying 2^64 times has a high
probability of key reuse within a given connection.  Note that even
if the key repeats, the IV is also independently generated.  In order
to provide an extra margin of security, sending implementations MUST
NOT allow the epoch to exceed 2^48-1.  In order to allow this value
to be changed later, receiving implementations MUST NOT enforce this
rule.  If a sending implementation receives a KeyUpdate with
request_update set to "update_requested", it MUST NOT send its own
KeyUpdate if that would cause it to exceed these limits and SHOULD
instead ignore the "update_requested" flag.  Note: this overrides the
requirement in TLS 1.3 to always send a KeyUpdate in response to
"update_requested".
```

The expected behavior is:

| State | Expected behavior |
|---|---|
| KeyUpdate received without `update_requested` | Process the peer key update |
| KeyUpdate received with `update_requested` and response is within limits | Send a response KeyUpdate |
| KeyUpdate received with `update_requested` and response would exceed sending limits | Do not send a response KeyUpdate; ignore the flag |
| Epoch would wrap | Do not allow wrap; establish a new association or terminate the old one |

## Code Behavior

### DTLS Epoch Uses uint16_t and Fails at 0xffff

In `ssl/dtls_method.cc`, `next_epoch` uses `uint16_t` for the output and previous epoch:

```cpp
static bool next_epoch(const SSL *ssl, uint16_t *out,
                       ssl_encryption_level_t level, uint16_t prev) {
```

For application epochs, it rejects `0xffff` and reports `SSL_R_TOO_MANY_KEY_UPDATES`:

```cpp
case ssl_encryption_application:
  if (prev < ssl_encryption_application &&
      ssl_protocol_version(ssl) >= TLS1_3_VERSION) {
    *out = static_cast<uint16_t>(level);
    return true;
  }

  if (prev == 0xffff) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_KEY_UPDATES);
    return false;
  }
  *out = prev + 1;
  return true;
```

Read epoch setup sends a fatal alert if the next epoch cannot be allocated:

```cpp
if (!next_epoch(ssl, &new_epoch.epoch, level, ssl->d1->read_epoch.epoch)) {
  ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
  return false;
}
```

Write epoch setup also fails if `next_epoch` cannot allocate the next epoch:

```cpp
uint16_t epoch;
if (!next_epoch(ssl, &epoch, level, ssl->d1->write_epoch.epoch())) {
  return false;
}
```

This confirms that BoringSSL's DTLS epoch boundary is `0xffff`, not the RFC 9147 sending limit `2^48-1`.

### update_requested Always Attempts a Response KeyUpdate

In `ssl/tls13_both.cc`, `tls13_receive_key_update` responds to `SSL_KEY_UPDATE_REQUESTED` by directly calling `tls13_add_key_update`:

```cpp
if (key_update_request == SSL_KEY_UPDATE_REQUESTED &&
    !tls13_add_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED)) {
  return false;
}
```

This path does not check:

```text
current DTLS write epoch
whether the response KeyUpdate would exceed the DTLS sending limit
whether update_requested should be ignored at the limit
```

If `tls13_add_key_update` or the later DTLS key-rotation path cannot allocate the next epoch, the connection follows the error path rather than ignoring `update_requested`.

### DTLS Response KeyUpdate Eventually Uses next_epoch

In `ssl/tls13_both.cc`, `tls13_add_key_update` writes a KeyUpdate handshake message:

```cpp
if (!ssl->method->init_message(ssl, cbb.get(), &body_cbb,
                               SSL3_MT_KEY_UPDATE) ||
    !CBB_add_u8(&body_cbb, request_type) ||
    !ssl_add_message_cbb(ssl, cbb.get())) {
  return false;
}

// In DTLS, the actual key update is deferred until KeyUpdate is ACKed.
if (!SSL_is_dtls(ssl) && !tls13_rotate_traffic_key(ssl, evp_aead_seal)) {
  return false;
}
```

For DTLS, sending-key rotation is deferred until the KeyUpdate is acknowledged. In `ssl/d1_pkt.cc`:

```cpp
if (ssl->s3->key_update_pending) {
  if (!tls13_rotate_traffic_key(ssl, evp_aead_seal)) {
    return ssl_open_record_error;
  }
  ssl->s3->key_update_pending = false;
}
```

`tls13_rotate_traffic_key` reaches the DTLS method's write-state setup, which uses `next_epoch`. Thus, at the DTLS write epoch boundary, a response to `update_requested` can hit `SSL_R_TOO_MANY_KEY_UPDATES` rather than being ignored.

### Consecutive KeyUpdate DoS Limit Is Separate

In `ssl/tls13_both.cc`, BoringSSL also has a consecutive KeyUpdate limit:

```cpp
static const uint8_t kMaxKeyUpdates = 32;
```

```cpp
ssl->s3->key_update_count++;
if (SSL_is_quic(ssl) || ssl->s3->key_update_count > kMaxKeyUpdates) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_KEY_UPDATES);
  ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
  return false;
}
```

This is an anti-abuse limit for excessive consecutive KeyUpdates. It is not the RFC 9147 Section 8 behavior for ignoring `update_requested` when a response KeyUpdate would exceed the epoch sending limit.

## Runner Coverage

`ssl/test/runner/runner.go` registers KeyUpdate tests:

```go
addKeyUpdateTests()
```

The runner can send KeyUpdates:

```go
for i := 0; i < test.sendKeyUpdates; i++ {
    if err := tlsConn.SendKeyUpdate(test.keyUpdateRequest); err != nil {
        return err
    }
}
```

When the runner sends `update_requested`, it expects the shim response in normal cases:

```go
if test.sendKeyUpdates > 0 && test.keyUpdateRequest == keyUpdateRequested {
    if err := tlsConn.ReadKeyUpdate(); err != nil {
        return err
    }
}
```

In `ssl/test/runner/key_update_tests.go`, DTLS overflow tests explicitly use the 16-bit epoch boundary:

```go
const maxClientKeyUpdates = 0xffff - 3
```

The test comments acknowledge that this is not prescribed by RFC 9147:

```go
// Test that the shim, as a server, rejects KeyUpdates at epoch 0xffff. RFC
// 9147 does not prescribe this limit, but we enforce it. See
// https://mailarchive.ietf.org/arch/msg/tls/6y8wTv8Q_IPM-PCcbCAmDOYg6bM/
// and https://www.rfc-editor.org/errata/eid8050
```

Relevant overflow test names include:

```text
KeyUpdate-ReadEpochOverflow-DTLS
KeyUpdate-WriteEpochOverflow-DTLS
```

The expected failures use:

```text
:TOO_MANY_KEY_UPDATES:
```

This runner coverage confirms that BoringSSL intentionally fails at the `0xffff` DTLS epoch boundary. It does not cover the RFC 9147 Section 8 rule that `update_requested` should be ignored when sending a response would exceed the sending limits.

## Runtime Evidence

A linked BoringSSL probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\repro_dtls13_key_update_epoch_limit_probe.cpp
```

CMake target:

```text
repro_dtls13_key_update_epoch_limit_probe
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc9147\051-100 -B D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe --config Release --target repro_dtls13_key_update_epoch_limit_probe
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe\Release\repro_dtls13_key_update_epoch_limit_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\repro_dtls13_key_update_epoch_limit_probe.log
```

Observed output:

```text
linked BoringSSL DTLS_method successfully
ok: next_epoch contains uint16_t *out
ok: next_epoch contains uint16_t prev
ok: next_epoch contains if (prev == 0xffff)
ok: next_epoch contains SSL_R_TOO_MANY_KEY_UPDATES
ok: next_epoch contains return false
ok: next_epoch contains *out = prev + 1
ok: next_epoch does not contain 0xffffffffffff
ok: next_epoch does not contain 2^48
ok: tls13_receive_key_update contains key_update_request == SSL_KEY_UPDATE_REQUESTED
ok: tls13_receive_key_update contains tls13_add_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED)
ok: tls13_receive_key_update does not contain SSL_R_TOO_MANY_KEY_UPDATES
ok: tls13_receive_key_update does not contain ignore
ok: tls13_receive_key_update does not contain 0xffff
ok: tls13_both.cc contains static const uint8_t kMaxKeyUpdates = 32
ok: d1_pkt.cc contains queued_key_update
ok: d1_pkt.cc contains SSL_KEY_UPDATE_REQUESTED
ok: d1_pkt.cc contains tls13_add_key_update(ssl, request_type)
ok: runner.go contains addKeyUpdateTests()
ok: runner.go contains SendKeyUpdate(test.keyUpdateRequest)
ok: runner.go contains ReadKeyUpdate()
ok: common.go contains keyUpdateRequested
ok: common.go contains AllowEpochOverflow
ok: key_update_tests.go contains const maxClientKeyUpdates = 0xffff - 3
ok: key_update_tests.go contains KeyUpdate-ReadEpochOverflow-DTLS
ok: key_update_tests.go contains KeyUpdate-WriteEpochOverflow-DTLS
ok: key_update_tests.go contains expectedError:      ":TOO_MANY_KEY_UPDATES:"
ok: key_update_tests.go contains expectedError:                ":TOO_MANY_KEY_UPDATES:"
ok: key_update_tests.go contains rejects KeyUpdates at epoch 0xffff
ok: key_update_tests.go contains 9147 does not prescribe this limit
ok: key_update_tests.go contains but we enforce it
RESULT: confirmed partial. BoringSSL responds to received update_requested KeyUpdate by attempting tls13_add_key_update with SSL_KEY_UPDATE_NOT_REQUESTED. In DTLS this allocates the next write epoch through next_epoch, which is uint16_t-based and fails at 0xffff with SSL_R_TOO_MANY_KEY_UPDATES. The receiver path has no branch to ignore update_requested when sending a response would exceed the RFC 9147 sending limit. Runner tests explicitly expect TOO_MANY_KEY_UPDATES at the 0xffff DTLS epoch boundary, reflecting BoringSSL's 16-bit epoch model rather than RFC 9147's 2^48-1 sending limit and ignore-update_requested rule.
```

The probe links against BoringSSL, creates a `DTLS_method()` context, and checks product and runner source predicates for epoch width, KeyUpdate response behavior, write-epoch allocation, overflow tests, and the absence of an ignore-`update_requested` branch.

## Inconsistency

| RFC 9147 behavior | BoringSSL behavior |
|---|---|
| Normal DTLS KeyUpdate is supported | Implemented |
| KeyUpdate must be acknowledged before new keys are used | Implemented through DTLS ACK-deferred key rotation |
| Sender must not exceed `2^48-1` epoch | BoringSSL uses a `uint16_t` epoch and fails at `0xffff` |
| Receiver must not enforce the sender's `2^48-1` limit | BoringSSL's model cannot represent epochs beyond `UINT16_MAX` |
| If responding to `update_requested` would exceed sending limits, do not send response | No such branch was found |
| At the limit, ignore `update_requested` | BoringSSL attempts `tls13_add_key_update` and may fail the connection |

The issue is not a total absence of KeyUpdate support. The issue is the boundary behavior when `update_requested` would require a response KeyUpdate beyond the allowed sending epoch.

## Root Cause

There are two related root causes:

| Root cause | Effect |
|---|---|
| DTLS epochs are modeled as `uint16_t` and fail at `0xffff` | The implementation reaches an epoch limit much earlier than RFC 9147's sender limit |
| `tls13_receive_key_update` directly responds to `update_requested` | The receive path does not check whether the response would exceed the sending limit and should be ignored |

As a result, at the epoch boundary BoringSSL follows the error path (`SSL_R_TOO_MANY_KEY_UPDATES`) instead of applying RFC 9147's override of the TLS 1.3 response requirement.

## Impact

This is a DTLS 1.3 protocol-limit and interoperability issue.

| Impact area | Description |
|---|---|
| Long-lived DTLS associations | The effective KeyUpdate epoch space is limited to `0xffff`. |
| RFC 9147 conformance | The implementation does not apply the `update_requested` ignore rule at the sending limit. |
| Interoperability | A peer that sends `update_requested` near the implementation's epoch limit may cause a connection failure instead of being ignored. |
| Test coverage | Existing runner tests expect `TOO_MANY_KEY_UPDATES` at `0xffff`, not the RFC 9147 limit behavior. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as incomplete limit handling for DTLS 1.3 KeyUpdate.

## Suggested Fix

Full RFC 9147 alignment would require both epoch-width and `update_requested` response changes.

| Required change | Expected effect |
|---|---|
| Widen DTLS epoch state or otherwise model the RFC sender limit | Avoids the premature `0xffff` boundary |
| Before responding to `update_requested`, check whether a response KeyUpdate would exceed the sending limit | Detects the RFC 9147 exception case |
| Ignore `update_requested` at the limit instead of sending a response | Matches Section 8 |
| Preserve normal KeyUpdate response behavior below the limit | Maintains TLS 1.3 compatibility where allowed |
| Update runner tests | Cover normal response, limit-ignore behavior, and true epoch-wrap rejection |
