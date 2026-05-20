# DTLS 1.2 CID Inner Plaintext Length and Zero Padding Are Only Partially Implemented

## Summary

RFC 9146 defines a CID-specific DTLS 1.2 record format that wraps application content into `DTLSInnerPlaintext`, includes a `length_of_DTLSInnerPlaintext` field, and permits zero-valued padding bytes. BoringSSL does not implement that DTLS 1.2 CID-specific inner-plaintext format. It does, however, implement a generic plaintext-length check and DTLS 1.3-only zero-padding stripping.

The result is a partial mismatch: the product code has related record-length and padding machinery, but not the RFC 9146 DTLS 1.2 CID `DTLSInnerPlaintext` structure, `length_of_DTLSInnerPlaintext` field, or DTLS 1.2 CID zero-padding parser/validator. This confirms IDs 012, 021, and 022 as **partially satisfied**.

## Standard Requirement

RFC 9146 says the CID-enhanced record format also provides content-type encryption and record-layer padding:

```text
The new ciphertext record format with the CID also provides content
type encryption and record layer padding.
```

The sender wraps content, type, and optional padding into `DTLSInnerPlaintext`:

```text
When CIDs are being used, the content to be sent is first wrapped
along with its content type and optional padding into a
DTLSInnerPlaintext structure.
```

The structure is:

```text
struct {
    opaque content[length];
    ContentType real_type;
    uint8 zeros[length_of_padding];
} DTLSInnerPlaintext;
```

The padding bytes are zero-valued:

```text
zeros:  An arbitrary-length run of zero-valued bytes may appear in
   the cleartext after the type field.
```

The inner plaintext length is part of the CID-specific protection model:

```text
length_of_DTLSInnerPlaintext:  The length (in bytes) of the
serialized DTLSInnerPlaintext (two-byte integer).  The length MUST
NOT exceed 2^14.
```

For AEAD, the RFC includes that length in the CID-specific additional data:

```text
additional_data = seq_num_placeholder +
                  tls12_cid +
                  cid_length +
                  tls12_cid +
                  DTLSCiphertext.version +
                  epoch +
                  sequence_number +
                  cid +
                  length_of_DTLSInnerPlaintext;
```

These rules are specific to DTLS 1.2 records that use RFC 9146 `tls12_cid(25)`.

## Code Behavior

### Generic Plaintext Length Limit Exists

In `ssl/dtls_record.cc`, BoringSSL checks the plaintext length with a generic limit:

```cpp
  bool has_padding = !record.read_epoch->aead->is_null_cipher() &&
                     ssl_protocol_version(ssl) >= TLS1_3_VERSION;
  // Check the plaintext length.
  size_t plaintext_limit = SSL3_RT_MAX_PLAIN_LENGTH + (has_padding ? 1 : 0);
  if (out->size() > plaintext_limit) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DATA_LENGTH_TOO_LONG);
    *out_alert = SSL_AD_RECORD_OVERFLOW;
    return ssl_open_record_error;
  }
```

This is a general plaintext limit. It is not an RFC 9146 `length_of_DTLSInnerPlaintext` field check.

### Zero Padding Stripping Is DTLS 1.3 Only

In `ssl/dtls_record.cc`, the padding logic is gated to DTLS 1.3:

```cpp
  // DTLS 1.3 hides the record type inside the encrypted data.
  bool has_padding = !record.read_epoch->aead->is_null_cipher() &&
                     ssl_protocol_version(ssl) >= TLS1_3_VERSION;
```

The stripping loop removes trailing zero bytes only in that DTLS 1.3 case:

```cpp
  if (has_padding) {
    do {
      if (out->empty()) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
        *out_alert = SSL_AD_DECRYPT_ERROR;
        return ssl_open_record_error;
      }
      record.type = out->back();
      *out = out->subspan(0, out->size() - 1);
    } while (record.type == 0);
  }
```

So the zero-padding behavior exists only for DTLS 1.3 encrypted-record handling, not for RFC 9146 DTLS 1.2 CID records.

### No DTLS 1.2 CID Inner Plaintext Path

Searches over `ssl/dtls_record.cc` and `ssl/internal.h` found no:

```text
DTLSInnerPlaintext
length_of_DTLSInnerPlaintext
tls12_cid
cid_length
ConnectionId
```

The DTLS 1.2 writer emits the ordinary DTLS record header and passes the caller's payload directly into the AEAD/MAC path:

```cpp
  } else {
    out[0] = type;
    CRYPTO_store_u16_be(out + 1, record_version);
    CRYPTO_store_u64_be(out + 3, record_number.combined());
    CRYPTO_store_u16_be(out + 11, ciphertext_len);
  }
```

There is no construction of:

```text
content || real_type || zero padding
```

for DTLS 1.2 CID records.

## Runner Coverage

`ssl/test/runner/runner.go` registers DTLS retransmission and handshake tests, but it does not add a DTLS 1.2 CID `DTLSInnerPlaintext` implementation to the product code.

The runner's DTLS 1.3 padding behavior does not change the product-code fact that there is no RFC 9146 DTLS 1.2 CID-specific inner plaintext structure or zero-padding parser.

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

The probe links against BoringSSL and checks that the product code has only generic plaintext-length logic and DTLS 1.3 padding stripping, not DTLS 1.2 CID inner-plaintext support.

## Inconsistency

| RFC 9146 requirement component | BoringSSL behavior |
|---|---|
| DTLS 1.2 CID record should wrap content into `DTLSInnerPlaintext` | No product DTLS 1.2 CID inner-plaintext path found |
| Serialized inner plaintext length should be enforced as a CID-specific field | No `length_of_DTLSInnerPlaintext` state or check found |
| Padding bytes may be zero-valued in the CID cleartext structure | No DTLS 1.2 CID padding constructor or parser found |
| Zero-padding stripping exists for DTLS 1.2 CID records | Not implemented; zero-padding logic is DTLS 1.3 only |
| Generic plaintext limit exists | Implemented |

The implementation therefore has related record-length and padding machinery, but not the RFC 9146 DTLS 1.2 CID-specific inner plaintext model.

## Root Cause

BoringSSL does not implement the RFC 9146 DTLS 1.2 CID record format. The product code keeps a generic DTLS plaintext limit and a DTLS 1.3-only zero-padding stripping path, but it does not build or validate `DTLSInnerPlaintext` for DTLS 1.2 CID records.

That is why the issue is partial rather than fully unsatisfied: related record-layer logic exists, but the RFC 9146 CID-specific structure and length/padding fields do not.

## Impact

This is a DTLS 1.2 CID feature-completeness gap.

| Impact area | Description |
|---|---|
| CID-specific plaintext format | The product code does not implement `DTLSInnerPlaintext` for DTLS 1.2 CID records. |
| CID padding semantics | Zero padding parsing/validation is not present for DTLS 1.2 CID. |
| Protocol conformance | RFC 9146's CID-specific inner plaintext model is absent. |
| Existing behavior | Generic plaintext-length enforcement and DTLS 1.3 padding stripping remain implemented. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as missing RFC 9146 DTLS 1.2 CID inner-plaintext and zero-padding handling.

## Suggested Fix

To fully support RFC 9146 CID records, BoringSSL would need to implement a DTLS 1.2 CID-specific inner plaintext layer.

| Required change | Expected effect |
|---|---|
| Add `DTLSInnerPlaintext` construction for DTLS 1.2 CID | Encodes content, real type, and optional zero padding |
| Add `length_of_DTLSInnerPlaintext` handling | Enforces the RFC CID-specific length field |
| Add DTLS 1.2 CID zero-padding parsing/validation | Handles the RFC zero-valued padding bytes |
| Keep the generic plaintext limit | Preserves the existing non-CID safety check |
| Add CID regression tests | Covers valid padding, empty padding, and length-boundary cases |
