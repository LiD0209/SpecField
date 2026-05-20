# `tls12_cid(25)` Is Not Defined in the Product Code

## Summary

RFC 9146 registers `tls12_cid(25)` as the DTLS 1.2 CID record content type. BoringSSL's shipped `libssl` does not define or use that content type in its DTLS record layer. The product code keeps the ordinary DTLS 1.2 header path and rejects DTLS 1.3 CID-bit records when CID was not negotiated, but it never exposes a DTLS 1.2 `tls12_cid(25)` constant or a CID-bearing record path.

This confirms ID 018 as **not satisfied**.

## Standard Requirement

RFC 9146 Section 10.3 adds a new entry in the TLS ContentType registry for DTLS 1.2 CID records.

Original English requirement excerpt:

> The tls12_cid content type is only applicable to DTLS 1.2.

The RFC assigns the codepoint:

> tls12_cid(25)

This content type is part of the DTLS 1.2 CID record framing defined by RFC 9146.

## Code Behavior

### No Product `tls12_cid` Constant

Searches across `ssl/` and `include/` found no product definition of `tls12_cid` or `tls12_cid(25)`. The only DTLS CID-related runner code is test-peer logic for DTLS 1.3 record headers, not a product constant.

### Product DTLS Record Layer Uses Ordinary DTLS 1.2 Framing

In `ssl/dtls_record.cc`, the DTLS 1.2 write path emits the ordinary header:

```cpp
} else {
  out[0] = type;
  CRYPTO_store_u16_be(out + 1, record_version);
  CRYPTO_store_u64_be(out + 3, record_number.combined());
  CRYPTO_store_u16_be(out + 11, ciphertext_len);
}
```

The corresponding parser reads the ordinary DTLS 1.2 header:

```cpp
if (!CBS_get_u16(in, &out->version) ||  //
    !CBS_get_u64(in, &epoch_and_seq) ||
    !CBS_get_u16_length_prefixed(in, &out->body)) {
  return false;
}
```

There is no branch that emits or parses a `tls12_cid(25)` record type.

### DTLS 1.3 CID Bit Is Rejected, Not Negotiated

The DTLS 1.3 record-header parser explicitly rejects an unexpected CID bit:

```cpp
if (out->type & 0x10) {
  // Connection ID bit set, which we didn't negotiate.
  return false;
}
```

This confirms that the shipped product stack does not implement DTLS 1.2 CID content-type handling.

## Runner Coverage

The runner contains DTLS 1.3 record-header coverage, including a test that forces the CID bit:

```go
name:     "DTLS13RecordHeader-CIDBit",
Bugs: ProtocolBugs{
    DTLS13RecordHeaderSetCIDBit: true,
},
```

That is not a DTLS 1.2 `tls12_cid(25)` product test. The runner can model a DTLS 1.3 header variant, but it does not add a shipped `tls12_cid` constant or DTLS 1.2 CID record support to `libssl`.

## Runtime Evidence

A linked probe used for the RFC 9146 CID audit confirmed that the product code has no `tls12_cid(25)` support.

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9146\001-022\repro_rfc9146_dtls12_cid_missing_linked_probe.log
```

Observed output excerpt:

```text
tls12_cid(25) content type is absent: PASS
DTLS 1.2 parser has no CID field: PASS
DTLS 1.2 writer emits RFC 6347 header only: PASS
DTLS 1.3 CID bit is rejected rather than negotiated: PASS
```

## Inconsistency

| RFC 9146 requirement component | BoringSSL behavior |
|---|---|
| Define `tls12_cid(25)` for DTLS 1.2 CID records | No product constant found |
| Use the content type in the DTLS 1.2 record layer | Ordinary DTLS 1.2 header path only |
| Parse CID-bearing DTLS 1.2 records | No CID parser path found |

## Root Cause

BoringSSL does not implement RFC 9146 DTLS 1.2 CID framing in the shipped product record layer.

The codebase contains ordinary DTLS 1.2 record handling and some DTLS 1.3 test-peer CID-bit coverage, but no product `tls12_cid(25)` constant or DTLS 1.2 CID record path.

## Impact

This is a DTLS 1.2 CID feature-completeness gap.

| Impact area | Description |
|---|---|
| Content type registry | `tls12_cid(25)` is not available in the product code |
| Record framing | DTLS 1.2 CID-bearing record format is absent |
| Interoperability | Peers expecting RFC 9146 DTLS 1.2 CID framing cannot be matched by product `libssl` |

## Suggested Fix

To satisfy RFC 9146, BoringSSL would need to define and use the DTLS 1.2 CID content type in the product record layer and add regression tests for CID-bearing DTLS 1.2 records.
