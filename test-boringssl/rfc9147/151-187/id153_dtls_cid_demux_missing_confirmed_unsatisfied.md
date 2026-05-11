# DTLS CID Demultiplexing Is Missing

## Summary

BoringSSL ?? DTLS 1.2 CID/tls12_cid(25) ?????? CID demux?DTLS 1.3 ???????? C bit?

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Relevant section: `4.1 Demultiplexing DTLS Records`

Relevant original English text from the standard:

```text
OCT == 25   -+--> DTLSCiphertext with CID (DTLS 1.2)
```

????????? DTLS 1.3 ????????? CID ??????????/?? CID ???????????

## Relevant Source Code

ssl/dtls_record.cc:170

```c++
if (out->type & 0x10) {
  // Connection ID bit set, which we didn't negotiate.
  return false;
}
```

ssl/dtls_record.cc:533

```c++
// We set C=0 (no Connection ID), S=1 (16-bit sequence number), L=1 (length
// is present), which is a mask of 0x2c.
```

## Implementation Behavior

Static re-read found no tls12_cid/connection_id implementation. parse_dtls13_record returns false when the C bit is set, and the sender fixes C=0.

## Inconsistency Reason

Implemented part: Regular DTLS record parsing and rejection of unsupported records are implemented.

Missing or conditional part: Confirmed unsatisfied for CID-capable operation: the record layer has no DTLS 1.2 CID demux path and rejects DTLS 1.3 CID headers.

## Runtime Evidence

Test source: `test-boringssl/151-187/focused_static_id152_153_185_187.py`

focused_static_id152_153_185_187.py PASS: confirmed absence of CID symbols and presence of explicit C-bit rejection/fixed C=0 send header.

## Impact

The impact is limited to peers or deployments that exercise this specific protocol path. For CID-related findings, peers that require DTLS CID update messages cannot interoperate with this implementation path. For the empty ACK finding, loss recovery may wait for retransmission timeout instead of being shortened by an empty ACK.

## Fix Direction

Add an explicit implementation path for the missing protocol behavior, including parser/state-machine support, negative tests, and interop tests. Keep unsupported optional features rejected unless and until their negotiation and message handling are fully implemented.
