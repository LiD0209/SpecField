# DTLS 1.2 CID Negotiation and Record Header CID Support Are Missing

## Summary

RFC 9146 adds the `connection_id` extension and the `tls12_cid(25)` record format for DTLS 1.2 CID support. When CID is negotiated, records are supposed to carry the negotiated CID in the record layer, and the additional data / record format changes are part of the CID protection model.

BoringSSL's product code does not implement that DTLS 1.2 CID path. The shipped `libssl` does not expose the `connection_id` extension, does not emit or parse `tls12_cid(25)` records, and does not maintain DTLS 1.2 CID record-header state. The runner can model some CID-related behavior for tests, but that is test-peer logic, not product support.

This confirms IDs 005 and 006 as **not satisfied**.

## Standard Requirement

RFC 9146 introduces the CID extension and record format:

```text
The connection_id extension allows endpoints to identify the
association they are using without relying on the source address.
```

The new DTLS 1.2 CID record format uses `tls12_cid(25)`:

```text
The CID is carried in the record layer using the new TLS content
type tls12_cid(25).
```

RFC 9146 also says that when CID is being used, the content is wrapped into a CID-aware inner plaintext / ciphertext construction and the record protection depends on the negotiated CID value.

The expected behavior is:

| Step | Expected behavior |
|---|---|
| Negotiate `connection_id` | Both endpoints agree on a CID value |
| Send encrypted DTLS 1.2 record | Carry the negotiated CID in the record layer |
| Receive encrypted DTLS 1.2 record | Parse the record using the negotiated CID-aware header |
| CID not negotiated | Do not use CID-specific record framing |

## Code Behavior

### Product CID Negotiation Is Absent

The product source does not expose a DTLS 1.2 CID negotiation API or extension path. In particular, searches in product `ssl/` and `include/openssl/` found no:

```text
connection_id
SSL_OP_COOKIE_EXCHANGE
DTLSv1_listen
CID negotiation API for product libssl
```

This means product `libssl` does not negotiate RFC 9146 CID.

### Product Record Layer Does Not Carry CID

In `ssl/dtls_record.cc`, the DTLS 1.2 record writer emits the ordinary DTLS header:

```cpp
  } else {
    out[0] = type;
    CRYPTO_store_u16_be(out + 1, record_version);
    CRYPTO_store_u64_be(out + 3, record_number.combined());
    CRYPTO_store_u16_be(out + 11, ciphertext_len);
  }
```

The DTLS 1.2 parser also reads the ordinary record header and body without a CID field:

```cpp
  if (!CBS_get_u16(in, &out->version) ||
      !CBS_get_u64(in, &epoch_and_seq) ||
      !CBS_get_u16_length_prefixed(in, &out->body)) {
    return false;
  }
```

There is no product DTLS 1.2 path that inserts or extracts a negotiated CID from the record header.

### DTLS 1.3 CID Bit Is Rejected Instead of Negotiated

BoringSSL's DTLS 1.3 parser rejects a CID bit in the record header when CID was not negotiated:

```cpp
if (out->type & 0x10) {
  // Connection ID bit set, which we didn't negotiate.
  return false;
}
```

This confirms that the product stack does not implement negotiated CID framing for DTLS 1.2.

### Runner Logic Is Not Product Logic

The runner can model CID-related behavior in test code, but that does not provide product `libssl` support.

The linked probe output confirms:

```text
connection_id(54) extension is absent
tls12_cid(25) content type is absent
DTLS 1.2 parser has no CID field
DTLS 1.2 writer emits RFC 6347 header only
DTLS 1.3 CID bit is rejected rather than negotiated
AEAD additional data has no RFC9146 CID construction
DTLSInnerPlaintext-like padding only exists for DTLS 1.3
No CID peer address update state machine
```

## Runner Coverage

`ssl/test/runner/runner.go` registers DTLS tests, and the runner can be used as a protocol peer for some CID-related scenarios.

However, runner behavior is not product `libssl`. The presence of test-peer logic does not change the fact that the shipped product server and record layer do not implement RFC 9146 DTLS 1.2 CID negotiation or CID-bearing record headers.

## Runtime Evidence

A linked probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9146\001-022\repro_rfc9146_dtls12_cid_missing_linked_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```text
cmake -S D:\project\SpecTrace\test-boringssl\rfc9146\001-022 -B D:\project\SpecTrace\test-boringssl\rfc9146\001-022\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9146\001-022\build-linked-probe --config Release --target repro_rfc9146_dtls12_cid_missing_linked_probe
D:\project\SpecTrace\test-boringssl\rfc9146\001-022\build-linked-probe\Release\repro_rfc9146_dtls12_cid_missing_linked_probe.exe D:\project\boringssl-main
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9146\001-022\repro_rfc9146_dtls12_cid_missing_linked_probe.log
```

Observed output:

```text
LINK SSL_CTX_new(DTLS_method): PASS
LINK DTLS1_2_VERSION min/max: PASS
LINK OpenSSL_version: BoringSSL
connection_id(54) extension is absent: PASS
tls12_cid(25) content type is absent: PASS
DTLS 1.2 parser has no CID field: PASS
DTLS 1.2 writer emits RFC 6347 header only: PASS
DTLS 1.3 CID bit is rejected rather than negotiated: PASS
AEAD additional data has no RFC9146 CID construction: PASS
DTLSInnerPlaintext-like padding only exists for DTLS 1.3: PASS
No CID peer address update state machine: PASS

EXIT_CODE: 0
```

The probe links against BoringSSL and checks that the product code lacks RFC 9146 DTLS 1.2 CID extension negotiation and CID-bearing record headers.

## Inconsistency

| RFC 9146 requirement component | BoringSSL behavior |
|---|---|
| Negotiate `connection_id` | No product CID negotiation path found |
| Carry the negotiated CID in the DTLS 1.2 record layer | No product CID record-header field found |
| Use `tls12_cid(25)` for CID-bearing records | `tls12_cid(25)` is absent in product code |
| Support CID-aware DTLS 1.2 record parsing | No product CID parser path found |

The implementation therefore does not provide the RFC 9146 DTLS 1.2 CID record format or the associated negotiated CID record framing.

## Root Cause

BoringSSL does not implement DTLS 1.2 CID negotiation or CID-aware record framing in shipped `libssl`.

The product code keeps the ordinary DTLS record layout and rejects DTLS 1.3 CID-bit records when CID was not negotiated. That is not the same as implementing RFC 9146 DTLS 1.2 CID support.

## Impact

This is a DTLS 1.2 CID feature-completeness gap.

| Impact area | Description |
|---|---|
| CID negotiation | The shipped product code does not negotiate `connection_id`. |
| CID record headers | The shipped product record layer does not emit or parse `tls12_cid(25)`. |
| Protocol conformance | RFC 9146 DTLS 1.2 CID framing is absent. |
| Test coverage | Runner logic can model peers, but does not change product support. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as missing DTLS 1.2 CID negotiation and CID record-header support.

## Suggested Fix

To satisfy RFC 9146 DTLS 1.2 CID behavior, BoringSSL would need:

| Required change | Expected effect |
|---|---|
| Add RFC 9146 `connection_id` negotiation | Allows endpoints to agree on a CID |
| Add DTLS 1.2 CID record framing | Inserts the negotiated CID into the record header |
| Add CID-aware record parsing | Extracts and validates the negotiated CID |
| Add CID-specific regression tests | Covers negotiated and unnegotiated cases |
