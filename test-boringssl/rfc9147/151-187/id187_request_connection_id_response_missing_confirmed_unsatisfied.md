# RequestConnectionId Response Handling Is Missing

## Summary

BoringSSL ?? RequestConnectionId ?????????? cid_spare NewConnectionId?

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Relevant section: `9 Connection ID Updates`

Relevant original English text from the standard:

```text
Endpoints SHOULD respond to RequestConnectionId by sending a NewConnectionId with usage "cid_spare" containing num_cids CIDs as soon as possible.
```

????????? DTLS 1.3 ????????? CID ??????????/?? CID ???????????

## Relevant Source Code

ssl/d1_both.cc:784

```c++
if (!CBB_add_u8(&cbb, hdr.type) ||
    !CBB_add_u24(&cbb, hdr.msg_len) ||
    !CBB_add_u16(&cbb, hdr.seq) ||
```

## Implementation Behavior

No RequestConnectionId handshake type handling or NewConnectionId response generation exists in the DTLS handshake code.

## Inconsistency Reason

Implemented part: The DTLS 1.3 record layer and handshake fragmentation machinery are implemented, but not CID update semantics.

Missing or conditional part: Confirmed unsatisfied: RequestConnectionId cannot trigger a cid_spare NewConnectionId response.

## Runtime Evidence

Test source: `test-boringssl/151-187/focused_static_id152_153_185_187.py`

focused_static_id152_153_185_187.py PASS: confirmed absent request_connection_id/new_connection_id handling symbols.

## Impact

The impact is limited to peers or deployments that exercise this specific protocol path. For CID-related findings, peers that require DTLS CID update messages cannot interoperate with this implementation path. For the empty ACK finding, loss recovery may wait for retransmission timeout instead of being shortened by an empty ACK.

## Fix Direction

Add an explicit implementation path for the missing protocol behavior, including parser/state-machine support, negative tests, and interop tests. Keep unsupported optional features rejected unless and until their negotiation and message handling are fully implemented.
