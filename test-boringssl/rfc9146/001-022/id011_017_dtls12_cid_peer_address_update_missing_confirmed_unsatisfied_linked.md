# DTLS 1.2 CID Records Do Not Trigger Peer Address Update

## Summary

RFC 9146 defines peer address update behavior for CID-bearing records. The update decision depends on receiving a record that is newer in both epoch and sequence number. BoringSSL's shipped `libssl` does not implement the RFC 9146 DTLS 1.2 CID record path at all, so there is no product CID record to trigger that update logic and no CID-specific address-update state machine to consult epoch/sequence freshness.

This confirms IDs 011 and 017 as **not satisfied**.

## Standard Requirement

RFC 9146 Section 6 describes peer address update for CID records.

Original English requirement excerpt:

> The received datagram is "newer" (in terms of both epoch and sequence number)

The RFC uses the freshness of the received CID-bearing datagram to decide when the peer address may be updated.

## Code Behavior

### Product CID Record Support Is Missing

In `ssl/dtls_record.cc`, BoringSSL does not implement the DTLS 1.2 CID record format. The DTLS 1.2 parser only reads the ordinary DTLS plaintext header:

```cpp
static bool parse_dtls12_record(SSL *ssl, CBS *in, ParsedDTLSRecord *out) {
  uint64_t epoch_and_seq;
  if (!CBS_get_u16(in, &out->version) ||  //
      !CBS_get_u64(in, &epoch_and_seq) ||
      !CBS_get_u16_length_prefixed(in, &out->body)) {
    return false;
  }
```

The DTLS 1.2 writer emits the ordinary DTLS header as well:

```cpp
} else {
  out[0] = type;
  CRYPTO_store_u16_be(out + 1, record_version);
  CRYPTO_store_u64_be(out + 3, record_number.combined());
  CRYPTO_store_u16_be(out + 11, ciphertext_len);
}
```

Because the product code never emits or parses RFC 9146 `tls12_cid(25)` records, there is no CID-bearing packet that can drive peer address update.

### No CID Address-Update State Machine

Searches in `ssl/`, `include/`, and `ssl/test/runner/` found no product CID address-update state machine, no `connection_id` negotiation path, and no peer-address migration logic tied to DTLS 1.2 CID records.

The record layer only tracks ordinary DTLS epochs and replay state:

```cpp
if (record.read_epoch == nullptr ||
    record.read_epoch->bitmap.ShouldDiscard(record.number.sequence())) {
  // Drop this record. It's from an unknown epoch or is a replay.
```

That replay check is not a CID address-update mechanism.

### Freshness Is Only Used for DTLS 1.3 Epoch Handling

BoringSSL does have DTLS 1.3 epoch bookkeeping:

```cpp
// Once we receive a record from the next epoch in DTLS 1.3, it becomes the
// current epoch. Also save the previous epoch.
if (record.read_epoch == ssl->d1->next_read_epoch.get()) {
```

This is a DTLS 1.3 key-update / epoch transition mechanism, not RFC 9146 CID peer address update.

## Runner Coverage

`ssl/test/runner` contains DTLS epoch and sequence-number simulation, including code that tracks epochs and record numbers for testing:

```go
func (hc *halfConn) readDTLS13RecordHeader(epoch *epochState, b []byte) ...
```

and DTLS 1.3 tests that exercise epoch transitions and ACK behavior.

However, the runner only models DTLS test-peer behavior. It does not add a shipped DTLS 1.2 CID record path, nor does it implement RFC 9146 peer address update for product `libssl`.

## Runtime Evidence

A linked probe used for the RFC 9146 CID audit confirmed that the product code lacks CID peer address update support.

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9146\001-022\repro_rfc9146_dtls12_cid_missing_linked_probe.log
```

Observed output excerpt:

```text
connection_id(54) extension is absent: PASS
tls12_cid(25) content type is absent: PASS
DTLS 1.2 parser has no CID field: PASS
DTLS 1.2 writer emits RFC 6347 header only: PASS
AEAD additional data has no RFC9146 CID construction: PASS
No CID peer address update state machine: PASS
```

## Inconsistency

| RFC 9146 requirement component | BoringSSL behavior |
|---|---|
| CID-bearing records can trigger peer address update | No DTLS 1.2 CID record path exists |
| Update decision depends on newer epoch and sequence number | No CID-specific update state machine exists |
| CID support should be present in the shipped record layer | Product `libssl` only has ordinary DTLS record handling |

## Root Cause

BoringSSL does not implement RFC 9146 DTLS 1.2 CID records in the shipped product code. Without CID record framing, there is no product path that can trigger or evaluate RFC 9146 peer address update decisions.

The runner can simulate epoch and sequence-number behavior for DTLS tests, but that is not equivalent to RFC 9146 CID peer address migration in product `libssl`.

## Impact

This is a DTLS 1.2 CID feature-completeness gap.

| Impact area | Description |
|---|---|
| Peer address update | No CID-bearing packet can trigger RFC 9146 update logic |
| Freshness checks | No CID-specific epoch/sequence freshness gate exists |
| Interoperability | Peer address migration behavior required by RFC 9146 is absent |

## Suggested Fix

To satisfy RFC 9146, BoringSSL would need to add DTLS 1.2 CID record support first, then layer peer address update logic on top of CID-bearing records, including freshness checks on epoch and sequence number.
