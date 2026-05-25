# `cid_spare` NewConnectionId Handling Is Missing

## Summary

RFC 9147 allows `NewConnectionId` to advertise usage `cid_spare`. BoringSSL's shipped DTLS code has no `NewConnectionId` parser and no CID usage state, so there is no product path that can generate or consume a `cid_spare` update.

This confirms ID 185 as **not satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: `9 Connection ID Updates`

Original English requirement excerpt:

```text
If it is set to "cid_spare", then either an existing or new CID MAY be used.
```

## Code Behavior

The product record layer rejects CID-bearing input when CID was not negotiated:

```cpp
if (out->type & 0x10) {
  // Connection ID bit set, which we didn't negotiate.
  return false;
}
```

The sender uses C=0 DTLS 1.3 headers:

```cpp
out[0] = 0x2c | (epoch & 0x3);
```

No product `NewConnectionId` parser or CID-usage state machine was found.

## Runner Coverage

The runner can model DTLS epochs and record headers for tests, but it does not provide product `NewConnectionId` support.

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
ID185 NewConnectionId/cid_spare handling absent: PASS
```

## Inconsistency

| RFC 9147 requirement component | BoringSSL behavior |
|---|---|
| Process `NewConnectionId` with usage `cid_spare` | No product parser or state machine exists |
| Track existing or new CID usage | No CID usage state exists |

## Root Cause

Root cause same as ID153: BoringSSL does not implement DTLS CID update semantics in the product code.

## Impact

Peers that rely on RFC 9147 CID update exchange cannot interoperate with this product path.

## Suggested Fix

Add `NewConnectionId` parsing and CID usage tracking to the DTLS handshake state machine.
