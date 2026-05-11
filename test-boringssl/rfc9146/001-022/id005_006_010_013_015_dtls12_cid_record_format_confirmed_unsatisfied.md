# DTLS 1.2 CID Record Format Is Not Implemented

## Summary

BoringSSL does not implement the RFC 9146 DTLS 1.2 CID-enhanced record format. The library does not negotiate `connection_id(54)`, does not emit `tls12_cid(25)`, and does not add a CID field between `sequence_number` and `length`.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146

Relevant sections: Section 3, "The connection_id Extension"; Section 4, "Record Layer Extensions"; Section 7, "Example".

Short original excerpts:

```text
enum { connection_id(54), (65535) } ExtensionType;
```

```text
ContentType outer_type = tls12_cid;
```

```text
opaque cid[cid_length]; // New field
```

The standard requires peers that negotiated a non-zero CID for a direction to use the CID-enhanced DTLS 1.2 ciphertext format after encryption is enabled.

## Relevant Source Code

`ssl/extensions.cc:3951`

```c
static const struct tls_extension kExtensions[] = {
```

The supported extension table contains many extension handlers, but no `connection_id(54)` entry or handler.

`ssl/dtls_record.cc:235`

```c
static bool parse_dtls12_record(SSL *ssl, CBS *in, ParsedDTLSRecord *out) {
  uint64_t epoch_and_seq;
  if (!CBS_get_u16(in, &out->version) ||  //
      !CBS_get_u64(in, &epoch_and_seq) ||
      !CBS_get_u16_length_prefixed(in, &out->body)) {
    return false;
  }
```

The parser reads the RFC 6347 DTLS 1.2 layout: version, epoch/sequence, length, and body. There is no CID-length-dependent field.

`ssl/dtls_record.cc:548`

```c
  } else {
    out[0] = type;
    CRYPTO_store_u16_be(out + 1, record_version);
    CRYPTO_store_u64_be(out + 3, record_number.combined());
    CRYPTO_store_u16_be(out + 11, ciphertext_len);
  }
```

The writer emits the caller-provided record type and the standard DTLS 1.2 header.

## Implementation Behavior

For DTLS 1.2 records, BoringSSL keeps the existing RFC 6347 record format. There is no connection ID negotiation state and no record-layer storage for a negotiated CID.

## Inconsistency Reason

RFC 9146 requires a new record shape for encrypted records when a non-zero CID is negotiated. BoringSSL cannot enter that state because it has no extension negotiation path and no CID-enhanced DTLS 1.2 record parser or writer.

## Runtime Evidence

`tests/verify_rfc9146_cid_support.py` was run and passed. It verified the absence of `connection_id` extension handlers, absence of `tls12_cid`, the DTLS 1.2 parser shape, and the DTLS 1.2 writer shape.

## Impact

Peers that require RFC 9146 CIDs for NAT rebinding or connection lookup cannot interoperate with BoringSSL using this feature.

## Fix Direction

Add DTLS 1.2 `connection_id(54)` negotiation state, APIs to configure received/sent CID values, CID-aware record parsing and writing, and tests for zero-length and non-zero-length directional CID negotiation.
