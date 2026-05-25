# DTLS CID Demultiplexing Is Missing

## Summary

RFC 9147 includes a demultiplexing path for CID-bearing records. BoringSSL's shipped `libssl` does not implement DTLS CID demultiplexing. Its DTLS 1.3 parser rejects records with the CID bit set when CID was not negotiated, and its sender fixes the CID bit to zero.

This confirms ID 153 as **not satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: `4.1 Demultiplexing DTLS Records`

Original English requirement excerpt:

```text
OCT == 25   -+--> DTLSCiphertext with CID (DTLS 1.2)
```

## Code Behavior

In `ssl/dtls_record.cc`, BoringSSL rejects an unexpected DTLS 1.3 CID bit:

```cpp
if (out->type & 0x10) {
  // Connection ID bit set, which we didn't negotiate.
  return false;
}
```

The sender side fixes the DTLS 1.3 encrypted-record header to C=0:

```cpp
// We set C=0 (no Connection ID), S=1 (16-bit sequence number), L=1 (length
// is present), which is a mask of 0x2c.
```

No DTLS 1.2 `tls12_cid(25)` demux path or `connection_id` implementation was found in product code.

## Runner Coverage

`ssl/test/runner` can synthesize DTLS 1.3 record-header variants for tests, but that is test-peer behavior. It does not provide product CID demultiplexing in `libssl`.

## Runtime Evidence

Focused static test:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\151-187\focused_static_id152_153_185_187.py
```

Linked probe log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\151-187\repro_dtls13_151_187_linked_probe.log
```

Observed output excerpt:

```text
ID153 DTLS 1.3 CID bit is rejected: PASS
ID153 sender fixes C bit to zero: PASS
ID153 no DTLS 1.2 tls12_cid demux symbols: PASS
```

## Inconsistency

| RFC 9147 requirement component | BoringSSL behavior |
|---|---|
| Demultiplex CID-bearing DTLS records | No product CID demux path exists |
| Accept negotiated CID-bearing input | CID-bit records are rejected when CID was not negotiated |
| Send CID-bearing DTLS records | Sender fixes C=0 |

## Root Cause

BoringSSL does not implement DTLS CID record demultiplexing in the shipped product record layer.

## Impact

Peers that require RFC 9147 CID-bearing records cannot interoperate with this product path.

## Suggested Fix

Add DTLS CID negotiation plus CID-bearing record parsing and serialization to `libssl`.
