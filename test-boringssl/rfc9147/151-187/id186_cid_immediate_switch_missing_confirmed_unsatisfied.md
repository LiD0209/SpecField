# `cid_immediate` CID Switching Is Missing

## Summary

RFC 9147 allows `ConnectionIdUsage = cid_immediate` to switch future records to a new CID immediately. BoringSSL's shipped DTLS code has no CID selection state and no immediate-switch mechanism.

This confirms ID 186 as **not satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: `9 Connection ID Updates`

Original English requirement excerpt:

```text
If usage is set to "cid_immediate", then one of the new CIDs MUST be used immediately for all future records.
```

## Code Behavior

The DTLS 1.3 sender emits C=0:

```cpp
out[0] = 0x2c | (epoch & 0x3);
CRYPTO_store_u16_be(out + 1, write_epoch->next_record.sequence());
```

The receiver rejects a CID bit when CID was not negotiated:

```cpp
if (out->type & 0x10) {
  // Connection ID bit set, which we didn't negotiate.
  return false;
}
```

No product CID selection or immediate-switch state was found.

## Runner Coverage

The runner can exercise DTLS 1.3 record-header variants in tests, but it does not implement product CID switching semantics.

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
ID186 cid_immediate handling absent: PASS
```

## Inconsistency

| RFC 9147 requirement component | BoringSSL behavior |
|---|---|
| Use one of the new CIDs immediately for future records | No CID selection or switch state exists |
| Migrate record sending to the new CID | Sender fixes C=0 |

## Root Cause

Root cause same as ID153: BoringSSL does not implement DTLS CID update semantics in shipped `libssl`.

## Impact

Peers that expect RFC 9147 immediate CID migration cannot interoperate with this product path.

## Suggested Fix

Add CID usage state and a record-layer transition that can switch future records to the selected CID immediately.
