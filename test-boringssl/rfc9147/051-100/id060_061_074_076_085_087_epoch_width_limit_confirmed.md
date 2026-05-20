# DTLS 1.3 Epoch and RecordNumber Are Limited to a 16+48 Model

## Summary

RFC 9147 distinguishes between compact wire encodings and the expanded DTLS 1.3 record number model. Some record headers carry only low-order epoch or sequence bits for compatibility, but the expanded `RecordNumber` has a 64-bit epoch and a 64-bit sequence number.

BoringSSL's product code uses a compact internal model:

```text
16-bit epoch + 48-bit sequence
```

This affects record number storage, read/write epoch state, epoch reconstruction, ACK processing, KeyUpdate epoch growth, and runner overflow tests. The implementation has wrap protection, but the protection boundary is `0xffff`, not RFC 9147's DTLS 1.3 sender epoch limit of `2^48-1`, and the receiver cannot represent the RFC's 64-bit epoch space.

This confirms the grouped issue for IDs 060, 061, 074, 076, 085, and 087.

| ID | Result | Reason |
|---|---|---|
| 060 | Partially satisfied | The wire `DTLSPlaintext.epoch` is 16 bits, but BoringSSL also stores only a 16-bit internal epoch |
| 061 | Not satisfied | Receive-side epoch state and lookup use `uint16_t`, so the receiver cannot represent a 64-bit epoch space |
| 074 | Partially satisfied | Application epoch growth after KeyUpdate is limited by `uint16_t` and stops at `0xffff` |
| 076 | Partially satisfied | Epoch wrap protection exists, but the boundary is `0xffff` rather than the RFC sender limit `2^48-1` |
| 085 | Partially satisfied | `DTLSRecordNumber` is packed as `uint16 epoch + uint48 sequence`, not `uint64 epoch + uint64 sequence_number` |
| 087 | Partially satisfied | Overflow protection exists, but it triggers at the 16-bit epoch boundary |

## Standard Requirement

RFC 9147, Section 4, explains that the serialized fields are low-order compatibility fields:

```text
The DTLS epoch serialized in DTLSPlaintext is 2 octets long for
compatibility with DTLS 1.2.  However, this value is set as the
least significant 2 octets of the connection epoch, which is an 8
octet counter incremented on every KeyUpdate.  See Section 4.2
for details.  The sequence number is set to be the low order 48
bits of the 64 bit sequence number.  Plaintext records MUST NOT
be sent with sequence numbers that would exceed 2^48-1, so the
upper 16 bits will always be 0.
```

The same section defines the expanded record number:

```text
When expanded, the epoch and sequence number can be combined into an
unpacked RecordNumber structure, as shown below:

    struct {
        uint64 epoch;
        uint64 sequence_number;
    } RecordNumber;
```

RFC 9147, Section 4.2:

```text
The epoch number is initially zero and is incremented each time
keying material changes and a sender aims to rekey.
```

RFC 9147, Section 4.2.1:

```text
Implementations MUST either abandon an association or rekey prior to
allowing the sequence number to wrap.

Implementations MUST NOT allow the epoch to wrap, but instead MUST
establish a new association, terminating the old association.
```

RFC 9147, Section 6.1:

```text
Epoch values (4 to 2^64-1) are used for payloads protected using
keys from the [sender]_application_traffic_secret_N (N>0).
```

RFC 9147, Section 6.1, KeyUpdate limit:

```text
With a 128-bit key as in AES-128, rekeying 2^64 times has a high
probability of key reuse within a given connection.  Note that even
if the key repeats, the IV is also independently generated.  In order
to provide an extra margin of security, sending implementations MUST
NOT allow the epoch to exceed 2^48-1.  In order to allow this value
to be changed later, receiving implementations MUST NOT enforce this
rule.
```

The important distinction is:

| Layer | RFC 9147 meaning |
|---|---|
| Serialized DTLSPlaintext epoch | Low 16 bits of the connection epoch |
| Serialized sequence number | Low 48 bits of the 64-bit sequence number |
| Expanded `RecordNumber` | `uint64 epoch` and `uint64 sequence_number` |
| Sending KeyUpdate boundary | Sender must not allow epoch to exceed `2^48-1` |
| Receiving behavior | Receiver must not enforce the sender's `2^48-1` limit |

## Code Behavior

### DTLSRecordNumber Is a 16+48 Packed Value

In `ssl/internal.h`, BoringSSL defines `DTLSRecordNumber` as an 8-byte packed value:

```cpp
class DTLSRecordNumber {
 public:
  static constexpr uint64_t kMaxSequence = (uint64_t{1} << 48) - 1;

  DTLSRecordNumber() = default;
  DTLSRecordNumber(uint16_t epoch, uint64_t sequence) {
    BSSL_CHECK(sequence <= kMaxSequence);
    combined_ = (uint64_t{epoch} << 48) | sequence;
  }

  uint64_t combined() const { return combined_; }
  uint16_t epoch() const { return combined_ >> 48; }
  uint64_t sequence() const { return combined_ & kMaxSequence; }
```

This represents:

```text
uint16 epoch + uint48 sequence
```

It cannot represent RFC 9147's expanded:

```text
uint64 epoch + uint64 sequence_number
```

### Read and Write Epoch State Use uint16_t

In `ssl/internal.h`, the read epoch state uses a 16-bit epoch:

```cpp
struct DTLSReadEpoch {
  uint16_t epoch = 0;
  UniquePtr<SSLAEADContext> aead;
  UniquePtr<RecordNumberEncrypter> rn_encrypter;
  DTLSReplayBitmap bitmap;
  InplaceVector<uint8_t, SSL_MAX_MD_SIZE> traffic_secret;
};
```

The write epoch exposes a 16-bit epoch from `DTLSRecordNumber`:

```cpp
struct DTLSWriteEpoch {
  uint16_t epoch() const { return next_record.epoch(); }

  DTLSRecordNumber next_record;
```

Related record-layer APIs also take `uint16_t epoch`:

```cpp
size_t dtls_record_header_write_len(const SSL *ssl, uint16_t epoch);
size_t dtls_max_seal_overhead(const SSL *ssl, uint16_t epoch);
size_t dtls_seal_prefix_len(const SSL *ssl, uint16_t epoch);
size_t dtls_seal_max_input_len(const SSL *ssl, uint16_t epoch, size_t max_out);
DTLSReadEpoch *dtls_get_read_epoch(const SSL *ssl, uint16_t epoch);
DTLSWriteEpoch *dtls_get_write_epoch(const SSL *ssl, uint16_t epoch);
```

This supports ID 061: the receiver-side epoch model cannot represent a 64-bit connection epoch.

### Epoch Reconstruction Returns uint16_t

In `ssl/dtls_record.cc`, BoringSSL reconstructs the DTLS 1.3 low-bit wire epoch into a 16-bit epoch:

```cpp
static uint16_t reconstruct_epoch(uint8_t wire_epoch, uint16_t current_epoch) {
  uint16_t current_epoch_high = current_epoch & 0xfffc;
  uint16_t epoch = (wire_epoch & 0x3) | current_epoch_high;
  if (epoch > current_epoch && current_epoch_high > 0) {
    epoch -= 0x4;
  }
  return epoch;
}
```

Read epoch lookup is also limited to `uint16_t`:

```cpp
DTLSReadEpoch *dtls_get_read_epoch(const SSL *ssl, uint16_t epoch) {
  if (epoch == ssl->d1->read_epoch.epoch) {
    return &ssl->d1->read_epoch;
  }
```

This is a 16-bit reconstruction model, not an 8-octet connection epoch model.

### KeyUpdate Epoch Boundary Is 0xffff

In `ssl/dtls_method.cc`, application epochs are advanced by `next_epoch`, which also uses `uint16_t`:

```cpp
static bool next_epoch(const SSL *ssl, uint16_t *out,
                       ssl_encryption_level_t level, uint16_t prev) {
  switch (level) {
    case ssl_encryption_initial:
    case ssl_encryption_early_data:
    case ssl_encryption_handshake:
      *out = static_cast<uint16_t>(level);
      return true;

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
  }
```

BoringSSL prevents epoch wrap, but it does so at `0xffff`. RFC 9147's DTLS 1.3 sender limit is `2^48-1`, and the expanded epoch space is 64 bits.

### ACK RecordNumber Parses uint64 Then Rejects Larger Epochs

In `ssl/d1_pkt.cc`, ACK processing reads the wire `RecordNumber` epoch and sequence as 64-bit values:

```cpp
uint64_t epoch, seq;
if (!CBS_get_u64(&record_numbers, &epoch) ||
    !CBS_get_u64(&record_numbers, &seq)) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
  *out_alert = SSL_AD_DECODE_ERROR;
  return ssl_open_record_error;
}
```

But it rejects epochs beyond the 16-bit model and then casts to `uint16_t`:

```cpp
if ((ack_record_number.epoch() < ssl_encryption_application &&
     epoch > ack_record_number.epoch()) ||
    epoch > UINT16_MAX || seq > DTLSRecordNumber::kMaxSequence) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
  *out_alert = SSL_AD_ILLEGAL_PARAMETER;
  return ssl_open_record_error;
}

DTLSRecordNumber number(static_cast<uint16_t>(epoch), seq);
```

This shows that BoringSSL parses the RFC 9147 ACK wire field shape, but product state still reduces it to the 16+48 `DTLSRecordNumber` model.

### Sequence Number Limit Also Preserves the 48-Bit Model

In `ssl/dtls_record.cc`, BoringSSL explicitly documents that it retains the DTLS 1.2 `2^48-1` sequence limit:

```cpp
uint64_t reconstruct_seqnum(uint16_t wire_seq, uint64_t seq_mask,
                            uint64_t max_valid_seqnum) {
  // Although DTLS 1.3 can support sequence numbers up to 2^64-1, we continue to
  // enforce the DTLS 1.2 2^48-1 limit. With a minimal DTLS 1.3 record header (2
  // bytes), no payload, and 16 byte AEAD overhead, sending 2^48 records would
  // require 5 petabytes. This allows us to continue to pack a DTLS record
  // number into an 8-byte structure.
  assert(max_valid_seqnum <= DTLSRecordNumber::kMaxSequence);
```

This comment confirms the design choice: BoringSSL intentionally keeps record numbers packable into 8 bytes.

## Runner Coverage

The user requested checking `ssl/test/runner/runner.go`. That file registers KeyUpdate tests:

```go
addKeyUpdateTests()
```

It also contains KeyUpdate control fields used by the test runner:

```go
// sendKeyUpdates is the number of consecutive key updates to send
sendKeyUpdates int

// shimSendsKeyUpdateBeforeRead indicates the shim should send a KeyUpdate
shimSendsKeyUpdateBeforeRead bool
```

The actual DTLS epoch overflow cases are in `ssl/test/runner/key_update_tests.go`:

```go
// When the sender is the client, the first KeyUpdate is message 2 at epoch
// 3, so the epoch number overflows first.
const maxClientKeyUpdates = 0xffff - 3
```

Relevant test names include:

```text
KeyUpdate-MaxReadEpoch-DTLS
KeyUpdate-ReadEpochOverflow-DTLS
KeyUpdate-MaxWriteEpoch-DTLS
KeyUpdate-WriteEpochOverflow-DTLS
```

The runner's DTLS controller also uses a 16-bit epoch in `ssl/test/runner/dtls.go`:

```go
type DTLSMessage struct {
    Epoch              uint16
    IsChangeCipherSpec bool
```

```go
func (c *DTLSController) OutEpoch() uint16
func (c *DTLSController) InEpoch() uint16
func (c *DTLSController) WriteACK(epoch uint16, records []DTLSRecordNumberInfo)
```

The runner does have an ACK helper with a `uint64` epoch:

```go
type DTLSRecordNumber struct {
    // Store the Epoch as a uint64, so that tests can send ACKs for epochs that
    // the shim would never use.
    Epoch    uint64
    Sequence uint64
}
```

That helper can construct 64-bit ACK fields, but the product code rejects `epoch > UINT16_MAX`. Runner coverage therefore reinforces BoringSSL's current 16-bit epoch boundary rather than validating a full RFC 9147 64-bit receive model.

## Runtime Evidence

A linked BoringSSL probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\repro_dtls13_epoch_width_probe.cpp
```

Build file:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\CMakeLists.txt
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc9147\051-100 -B D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe --config Release --target repro_dtls13_epoch_width_probe
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe\Release\repro_dtls13_epoch_width_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\repro_dtls13_epoch_width_probe.log
```

Observed output:

```text
linked BoringSSL DTLS_method successfully
ok: internal.h contains DTLSRecordNumber(uint16_t epoch, uint64_t sequence)
ok: internal.h contains uint16_t epoch() const
ok: internal.h contains combined_ = (uint64_t{epoch} << 48) | sequence
ok: internal.h contains static constexpr uint64_t kMaxSequence = (uint64_t{1} << 48) - 1
ok: dtls_method.cc contains static bool next_epoch(const SSL *ssl, uint16_t *out
ok: dtls_method.cc contains if (prev == 0xffff)
ok: dtls_method.cc contains SSL_R_TOO_MANY_KEY_UPDATES
ok: dtls_record.cc contains static uint16_t reconstruct_epoch
ok: dtls_record.cc contains uint16_t max_epoch = ssl->d1->read_epoch.epoch
ok: d1_pkt.cc contains epoch > UINT16_MAX
ok: d1_pkt.cc contains DTLSRecordNumber number(static_cast<uint16_t>(epoch), seq)
ok: runner.go contains addKeyUpdateTests()
ok: runner dtls.go contains Epoch              uint16
ok: runner key_update_tests.go contains const maxClientKeyUpdates = 0xffff - 3
ok: runner key_update_tests.go contains KeyUpdate-ReadEpochOverflow-DTLS
ok: runner key_update_tests.go contains KeyUpdate-WriteEpochOverflow-DTLS
RESULT: confirmed. BoringSSL product code models DTLS epochs as uint16_t and rejects/wrap-guards at 0xffff, while runner tests intentionally cover this 16-bit overflow behavior. ACK RecordNumber carries uint64 fields on the wire, but product code casts epochs into the 16-bit DTLSRecordNumber model.
```

The probe links against BoringSSL, creates a `DTLS_method()` context, and checks product and runner source predicates for the 16+48 record number model, epoch reconstruction, KeyUpdate overflow behavior, ACK epoch casting, and runner coverage.

## Inconsistency

| RFC 9147 model | BoringSSL behavior |
|---|---|
| Expanded `RecordNumber` has `uint64 epoch` | `DTLSRecordNumber` stores a 16-bit epoch |
| Expanded `RecordNumber` has `uint64 sequence_number` | `DTLSRecordNumber` stores a 48-bit sequence |
| DTLSPlaintext serialized epoch is the low 16 bits of an 8-octet connection epoch | Product state keeps only the 16-bit value |
| Application epochs can range beyond 16 bits | KeyUpdate epoch growth stops at `0xffff` |
| Sender must not exceed `2^48-1` epoch | BoringSSL rejects at `0xffff` |
| Receiver must not enforce the sender's `2^48-1` rule | Receiver cannot represent epochs above `UINT16_MAX` |
| ACK `RecordNumber` carries 64-bit epoch on the wire | Product code rejects `epoch > UINT16_MAX` and casts to `uint16_t` |

The serialized low-bit wire fields are not the core problem. RFC 9147 also uses low-order fields on the wire. The mismatch is that BoringSSL does not maintain the full expanded connection epoch and record number semantics behind those wire fields.

## Root Cause

BoringSSL intentionally uses a compact 8-byte internal record number:

```text
combined_ = (uint16 epoch << 48) | uint48 sequence
```

This keeps record-number storage compatible with the DTLS 1.2 model and simplifies replay and record bookkeeping. However, it prevents the DTLS 1.3 implementation from representing the RFC 9147 expanded `RecordNumber` model and its larger epoch space.

The same root cause explains all grouped IDs:

| ID | Root cause mapping |
|---|---|
| 060 | Internal epoch state is 16-bit, not a full connection epoch |
| 061 | Receive epoch lookup and reconstruction are 16-bit |
| 074 | Application KeyUpdate epochs advance through `uint16_t` |
| 076 | Wrap guard is tied to `0xffff` |
| 085 | `DTLSRecordNumber` is packed as 16+48 |
| 087 | Overflow protection is present but fires at the 16-bit boundary |

## Impact

This is a DTLS 1.3 protocol-model conformance gap.

| Impact area | Description |
|---|---|
| Long-lived associations | BoringSSL cannot use the larger DTLS 1.3 epoch space for many KeyUpdates. |
| Receive compatibility | The receiver cannot accept or model peers using epochs beyond `UINT16_MAX`. |
| ACK processing | ACK `RecordNumber` epochs beyond 16 bits are rejected even though the wire field is 64-bit. |
| Runner coverage | Existing runner tests expect and cover the 16-bit overflow behavior. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as an intentional compact internal model that is narrower than RFC 9147's expanded DTLS 1.3 record number model.

## Suggested Fix

Fully aligning with RFC 9147 would require widening the DTLS record-number and epoch state model.

| Required change | Expected effect |
|---|---|
| Store the connection epoch as a 64-bit value | Represents RFC 9147's expanded `RecordNumber.epoch` |
| Separate wire low-bit epoch encoding from internal epoch state | Preserves compact wire headers without losing high bits |
| Widen read/write epoch lookup and reconstruction | Allows receive processing beyond `UINT16_MAX` |
| Rework ACK `RecordNumber` handling | Avoids rejecting valid 64-bit ACK epochs solely because they exceed 16 bits |
| Move sender KeyUpdate guard to the RFC boundary | Enforces `2^48-1` instead of `0xffff` |
| Update runner tests | Cover both RFC-sized epoch behavior and intended wrap/limit handling |
