# Inner Plaintext Length and Zero Padding Are Only Partially Covered

## Summary

BoringSSL enforces generic plaintext length limits and implements DTLS 1.3 encrypted inner content type padding. It does not implement RFC 9146 DTLS 1.2 `DTLSInnerPlaintext`, so the RFC 9146-specific length and padding behavior is only partially present.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146

Relevant sections: Section 4, "Record Layer Extensions"; Section 5, "Record Payload Protection".

Short original excerpts:

```text
uint8 zeros[length_of_padding];
```

```text
The length MUST NOT exceed 2^14.
```

The standard wraps content, real type, and optional zero padding in `DTLSInnerPlaintext` before encryption.

## Relevant Source Code

`ssl/dtls_record.cc:343`

```c
  // DTLS 1.3 hides the record type inside the encrypted data.
  bool has_padding = !record.read_epoch->aead->is_null_cipher() &&
                     ssl_protocol_version(ssl) >= TLS1_3_VERSION;
```

`ssl/dtls_record.cc:347`

```c
  size_t plaintext_limit = SSL3_RT_MAX_PLAIN_LENGTH + (has_padding ? 1 : 0);
```

`ssl/dtls_record.cc:354`

```c
  if (has_padding) {
    do {
      if (out->empty()) {
```

These lines show the implemented DTLS 1.3 padding logic.

## Implementation Behavior

Generic plaintext length checks exist. Zero padding is stripped only when DTLS 1.3 encrypted records hide the record type. The RFC 9146 DTLS 1.2 CID inner plaintext structure is not present.

## Inconsistency Reason

The implemented behavior covers a related DTLS 1.3 mechanism, not the RFC 9146 DTLS 1.2 CID mechanism. Thus the length and zero-padding requirements are partially implemented in spirit but not in the target record format.

## Runtime Evidence

The focused audit test verified `dtls_inner_plaintext_only_dtls13` and `plaintext_limit_present_but_not_cid_specific`.

## Impact

Applications using BoringSSL cannot rely on RFC 9146 padding for traffic analysis resistance in DTLS 1.2 CID records.

## Fix Direction

Introduce a DTLS 1.2 CID `DTLSInnerPlaintext` construction and parsing path, enforce the RFC 9146 internal length limit, and add tests for zero and non-zero padding.
