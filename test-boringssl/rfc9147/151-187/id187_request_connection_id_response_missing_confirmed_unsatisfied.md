# RequestConnectionId Response Handling Is Missing

## Summary

RFC 9147 says endpoints should respond to `RequestConnectionId` with a `NewConnectionId` carrying usage `cid_spare`. BoringSSL's shipped DTLS code has no `RequestConnectionId` handler and no `NewConnectionId` response generator.

This confirms ID 187 as **not satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: `9 Connection ID Updates`

Original English requirement excerpt:

```text
Endpoints SHOULD respond to RequestConnectionId by sending a NewConnectionId with usage "cid_spare" containing num_cids CIDs as soon as possible.
```

## Code Behavior

The DTLS handshake path serializes ordinary handshake messages:

```cpp
if (!CBB_add_u8(&cbb, hdr.type) ||
    !CBB_add_u24(&cbb, hdr.msg_len) ||
    !CBB_add_u16(&cbb, hdr.seq) ||
```

No product `RequestConnectionId` type handler or `NewConnectionId` response path was found.

## Runner Coverage

The runner can model DTLS handshake sequencing, but it does not provide product `RequestConnectionId` or `NewConnectionId` support.

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
ID187 RequestConnectionId handling absent: PASS
```

## Inconsistency

| RFC 9147 requirement component | BoringSSL behavior |
|---|---|
| Handle `RequestConnectionId` | No product request handler exists |
| Generate `NewConnectionId` with usage `cid_spare` | No product response generation path exists |

## Root Cause

Root cause same as ID153: BoringSSL does not implement DTLS CID update semantics in shipped `libssl`.

## Impact

Peers that rely on RFC 9147 CID update signaling cannot interoperate with this product path.

## Suggested Fix

Add `RequestConnectionId` parsing and `NewConnectionId` generation to the DTLS handshake state machine.
