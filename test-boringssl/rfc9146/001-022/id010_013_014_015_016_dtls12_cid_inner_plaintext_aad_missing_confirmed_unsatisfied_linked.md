# DTLS 1.2 CID Inner Plaintext and CID-Specific AAD Construction Are Missing

## Summary

RFC 9146 defines a DTLS 1.2 CID record format in which the plaintext is first wrapped into `DTLSInnerPlaintext`, the serialized inner plaintext length is carried as `length_of_DTLSInnerPlaintext`, and the AEAD additional data is rebuilt with CID-specific fields such as `tls12_cid(25)`, `cid_length`, the negotiated CID, and the `seq_num_placeholder` prefix of eight `0xff` bytes.

BoringSSL's shipped `libssl` does not implement that DTLS 1.2 CID record-protection path. The product code keeps the ordinary DTLS 1.2 record header, uses the standard record body as AEAD input, and only applies padding stripping for DTLS 1.3. There is no DTLS 1.2 CID-specific `DTLSInnerPlaintext` builder, no `length_of_DTLSInnerPlaintext` state, no `tls12_cid(25)` record type in the product record layer, and no CID-specific `seq_num_placeholder` / modified AAD construction.

This confirms IDs 010, 013, 014, 015, and 016 as **not satisfied**.

## Standard Requirement

RFC 9146 Section 4 and Section 5 describe the CID-specific record format and protection rules.

Original English requirement excerpts:

> When CIDs are being used, the content to be sent is first wrapped along with its content type and optional padding into a DTLSInnerPlaintext structure.

> struct { opaque content[length]; ContentType real_type; uint8 zeros[length_of_padding]; } DTLSInnerPlaintext;

> length_of_DTLSInnerPlaintext: The length (in bytes) of the serialized DTLSInnerPlaintext (two-byte integer).

> The outer content type of a DTLSCiphertext record carrying a CID is always set to tls12_cid(25).

> seq_num_placeholder: 8 bytes of 0xff.

> additional_data = seq_num_placeholder + tls12_cid + cid_length + tls12_cid + DTLSCiphertext.version + epoch + sequence_number + cid + length_of_DTLSInnerPlaintext;

These requirements apply to DTLS 1.2 records that carry a negotiated CID.

## Code Behavior

### DTLS 1.2 Record Parsing Does Not Carry CID Fields

In `ssl/dtls_record.cc`, the DTLS 1.2 parser reads only the ordinary DTLS plaintext header:

```cpp
static bool parse_dtls12_record(SSL *ssl, CBS *in, ParsedDTLSRecord *out) {
  uint64_t epoch_and_seq;
  if (!CBS_get_u16(in, &out->version) ||  //
      !CBS_get_u64(in, &epoch_and_seq) ||
      !CBS_get_u16_length_prefixed(in, &out->body)) {
    return false;
  }
```

The parse path has no CID field, no `tls12_cid(25)` branch, and no `DTLSInnerPlaintext` decoding step.

### DTLS 1.2 Write Path Emits the Ordinary Header

In the write path, BoringSSL emits the standard DTLS 1.2 header and then seals the caller-provided plaintext directly:

```cpp
} else {
  out[0] = type;
  CRYPTO_store_u16_be(out + 1, record_version);
  CRYPTO_store_u64_be(out + 3, record_number.combined());
  CRYPTO_store_u16_be(out + 11, ciphertext_len);
}
```

Later, the AEAD call uses the ordinary record header as additional data:

```cpp
if (!write_epoch->aead->SealScatter(
        out + record_header_len, out + prefix, out + prefix + in_len, type,
        record_version, dtls_aead_sequence(ssl, record_number), header, in,
        max_out - record_header_len)) {
```

There is no construction of:

```text
seq_num_placeholder + tls12_cid + cid_length + cid + length_of_DTLSInnerPlaintext
```

for DTLS 1.2 CID records.

### Inner Plaintext Length Is Only a Generic Plaintext Limit

BoringSSL does perform a plaintext-length check, but it is a generic limit:

```cpp
bool has_padding = !record.read_epoch->aead->is_null_cipher() &&
                   ssl_protocol_version(ssl) >= TLS1_3_VERSION;
size_t plaintext_limit = SSL3_RT_MAX_PLAIN_LENGTH + (has_padding ? 1 : 0);
if (out->size() > plaintext_limit) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_DATA_LENGTH_TOO_LONG);
  *out_alert = SSL_AD_RECORD_OVERFLOW;
  return ssl_open_record_error;
}
```

This is not an RFC 9146 `length_of_DTLSInnerPlaintext` field check. It is only a general record-size validation.

### Zero-Padding Logic Is DTLS 1.3 Only

The padding-stripping loop is gated to DTLS 1.3:

```cpp
bool has_padding = !record.read_epoch->aead->is_null_cipher() &&
                   ssl_protocol_version(ssl) >= TLS1_3_VERSION;
...
if (has_padding) {
  do {
    ...
    record.type = out->back();
    *out = out->subspan(0, out->size() - 1);
  } while (record.type == 0);
}
```

That logic does not implement RFC 9146 DTLS 1.2 CID inner plaintext padding.

### No CID-Specific Constants or State

Searches in `ssl/dtls_record.cc`, `ssl/internal.h`, and `ssl/extensions.cc` found no product implementation of:

```text
DTLSInnerPlaintext
length_of_DTLSInnerPlaintext
tls12_cid
cid_length
seq_num_placeholder
ConnectionId
```

The product code therefore has no CID-specific MAC/AAD state to hold or validate these values.

## Runner Coverage

`ssl/test/runner/runner.go` and the DTLS test helpers can model DTLS 1.3 record-header behavior, but they do not add RFC 9146 DTLS 1.2 CID support to `libssl`.

The runner contains DTLS 1.3 CID-bit test coverage:

```go
name:     "DTLS13RecordHeader-CIDBit",
Bugs: ProtocolBugs{
    DTLS13RecordHeaderSetCIDBit: true,
},
```

That coverage only proves the test peer can synthesize a DTLS 1.3 record-header variant. It does not provide a DTLS 1.2 CID `DTLSInnerPlaintext` implementation, CID-specific AAD construction, or `tls12_cid(25)` support in the shipped product code.

## Runtime Evidence

A linked probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9146\001-022\repro_rfc9146_dtls12_inner_plaintext_padding_linked_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```text
cmake --build D:\project\SpecTrace\test-boringssl\rfc9146\001-022\build-linked-probe --config Release --target repro_rfc9146_dtls12_inner_plaintext_padding_linked_probe
D:\project\SpecTrace\test-boringssl\rfc9146\001-022\build-linked-probe\Release\repro_rfc9146_dtls12_inner_plaintext_padding_linked_probe.exe D:\project\boringssl-main
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9146\001-022\repro_rfc9146_dtls12_inner_plaintext_padding_linked_probe.log
```

Observed output:

```text
LINK SSL_CTX_new(DTLS_method): PASS
LINK DTLS1_2_VERSION min/max: PASS
LINK OpenSSL_version: BoringSSL
Generic DTLS plaintext limit exists: PASS
Generic DTLS 1.2 record header length exists: PASS
No RFC9146 length_of_DTLSInnerPlaintext field: PASS
Zero padding removal is gated to DTLS 1.3: PASS
No DTLS 1.2 CID padding construction on write path: PASS
No CID-specific plaintext length state: PASS

EXIT_CODE: 0
```

The probe links against BoringSSL and confirms that the product code only has generic DTLS record handling and DTLS 1.3 padding stripping, not RFC 9146 DTLS 1.2 CID inner-plaintext or CID-AAD support.

## Inconsistency

| RFC 9146 requirement component | BoringSSL behavior |
|---|---|
| Wrap plaintext into `DTLSInnerPlaintext` | No DTLS 1.2 CID inner-plaintext path found |
| Track `length_of_DTLSInnerPlaintext` | No CID-specific length state found |
| Use `tls12_cid(25)` as the outer type | Product DTLS 1.2 write path emits the ordinary DTLS type byte |
| Use `seq_num_placeholder` and CID-specific AAD | Product AEAD uses the ordinary record header as AAD |
| Strip / validate CID padding in DTLS 1.2 | No DTLS 1.2 CID padding parser or builder found |

The implementation therefore does not provide the RFC 9146 DTLS 1.2 CID record-protection model.

## Root Cause

BoringSSL does not implement RFC 9146 DTLS 1.2 CID record framing in shipped `libssl`.

The product record layer keeps the ordinary DTLS 1.2 header and AEAD flow. It only has a DTLS 1.3 padding-aware read path, which is a different mechanism from RFC 9146's DTLS 1.2 CID inner plaintext and modified AAD construction.

## Impact

This is a DTLS 1.2 CID feature-completeness gap.

| Impact area | Description |
|---|---|
| CID record framing | No RFC 9146 `tls12_cid(25)` record path in product code |
| Inner plaintext protection | No `DTLSInnerPlaintext` builder or parser for DTLS 1.2 CID records |
| AAD construction | No CID-specific modified additional data |
| Padding semantics | DTLS 1.3 padding handling does not substitute for RFC 9146 DTLS 1.2 CID padding |

## Suggested Fix

To satisfy RFC 9146 DTLS 1.2 CID behavior, BoringSSL would need:

| Required change | Expected effect |
|---|---|
| Add DTLS 1.2 CID record framing | Carry `tls12_cid(25)` in the record layer |
| Add `DTLSInnerPlaintext` construction | Wrap content, type, and optional padding before encryption |
| Add CID-specific AAD construction | Include `seq_num_placeholder`, CID fields, and inner plaintext length |
| Add CID-aware parsing and validation | Decode and verify DTLS 1.2 CID records on receive |
| Add regression tests | Cover both negotiated and unnegotiated CID paths |
