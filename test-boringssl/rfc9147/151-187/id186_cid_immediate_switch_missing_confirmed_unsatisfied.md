# cid_immediate CID Switching Is Missing

## Summary

BoringSSL ?? cid_immediate ????????? usage ??????? CID?

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Relevant section: `9 Connection ID Updates`

Relevant original English text from the standard:

```text
If usage is set to "cid_immediate", then one of the new CIDs MUST be used immediately for all future records.
```

????????? DTLS 1.3 ????????? CID ??????????/?? CID ???????????

## Relevant Source Code

ssl/dtls_record.cc:540

```c++
out[0] = 0x2c | (epoch & 0x3);
CRYPTO_store_u16_be(out + 1, write_epoch->next_record.sequence());
```

## Implementation Behavior

No CID selection or immediate-switch state exists. The sender writes C=0 and no Connection ID in every DTLS 1.3 encrypted record.

## Inconsistency Reason

Implemented part: The DTLS 1.3 record layer and handshake fragmentation machinery are implemented, but not CID update semantics.

Missing or conditional part: Confirmed unsatisfied: there is no mechanism to switch future records to a new CID immediately.

## Runtime Evidence

Test source: `test-boringssl/151-187/focused_static_id152_153_185_187.py`

focused_static_id152_153_185_187.py PASS: confirmed fixed C=0 header and no cid_immediate symbol/path.

## Impact

The impact is limited to peers or deployments that exercise this specific protocol path. For CID-related findings, peers that require DTLS CID update messages cannot interoperate with this implementation path. For the empty ACK finding, loss recovery may wait for retransmission timeout instead of being shortened by an empty ACK.

## Fix Direction

Add an explicit implementation path for the missing protocol behavior, including parser/state-machine support, negative tests, and interop tests. Keep unsupported optional features rejected unless and until their negotiation and message handling are fully implemented.
