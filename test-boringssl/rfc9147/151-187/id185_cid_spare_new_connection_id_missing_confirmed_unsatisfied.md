# cid_spare NewConnectionId Handling Is Missing

## Summary

BoringSSL ?? NewConnectionId/ConnectionIdUsage ?????????????? cid_spare ???

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Relevant section: `9 Connection ID Updates`

Relevant original English text from the standard:

```text
If it is set to "cid_spare", then either an existing or new CID MAY be used.
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

No NewConnectionId or ConnectionIdUsage parser/state exists. The DTLS 1.3 sender never sends CID and the receiver rejects C bit.

## Inconsistency Reason

Implemented part: The DTLS 1.3 record layer and handshake fragmentation machinery are implemented, but not CID update semantics.

Missing or conditional part: Confirmed unsatisfied: BoringSSL cannot process cid_spare because DTLS CID update support is absent.

## Runtime Evidence

Test source: `test-boringssl/151-187/focused_static_id152_153_185_187.py`

focused_static_id152_153_185_187.py PASS: confirmed absence of NewConnectionId/RequestConnectionId/cid_spare symbols and CID-capable record support.

## Impact

The impact is limited to peers or deployments that exercise this specific protocol path. For CID-related findings, peers that require DTLS CID update messages cannot interoperate with this implementation path. For the empty ACK finding, loss recovery may wait for retransmission timeout instead of being shortened by an empty ACK.

## Fix Direction

Add an explicit implementation path for the missing protocol behavior, including parser/state-machine support, negative tests, and interop tests. Keep unsupported optional features rejected unless and until their negotiation and message handling are fully implemented.
