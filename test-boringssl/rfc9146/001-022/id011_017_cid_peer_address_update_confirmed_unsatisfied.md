# CID Peer Address Update Rules Are Missing

## Summary

BoringSSL has DTLS replay tracking, but no RFC 9146 CID-based peer address update state machine. The source address of a CID-authenticated record is therefore not handled under the Section 6 conditions.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146

Relevant section: Section 6, "Peer Address Update".

Short original excerpt:

```text
The received datagram is "newer"
```

Section 6 requires address replacement only after cryptographic verification, a newer epoch and sequence number, and an address-reachability strategy.

## Relevant Source Code

`ssl/dtls_record.cc:25`

```c
bool DTLSReplayBitmap::ShouldDiscard(uint64_t seq_num) const {
```

`ssl/dtls_record.cc:366`

```c
  record.read_epoch->bitmap.Record(record.number.sequence());
```

These lines implement record replay tracking, not peer address migration.

`ssl/dtls_record.cc:327`

```c
  if (!record.read_epoch->aead->Open(out, record.type, record.version,
                                     dtls_aead_sequence(ssl, record.number),
                                     record.header,
                                     cbs_to_writable_bytes(record.body))) {
```

The record is cryptographically verified, but no subsequent CID source-address update check exists.

## Implementation Behavior

The DTLS record layer authenticates records and updates replay state. It does not associate CID values with connections, does not detect CID-bearing datagrams from a new source address, and does not update the transport peer address.

## Inconsistency Reason

The standard's address update rule only applies to records with a CID. Because BoringSSL lacks RFC 9146 CID records and lacks the address update gate, the required epoch/sequence checks for address replacement are absent.

## Runtime Evidence

The focused audit test passed and verified that CID support is absent. Source review confirmed no CID peer-address update path in `ssl/dtls_record.cc`.

## Impact

RFC 9146 NAT rebinding support is unavailable. Applications cannot rely on BoringSSL to perform CID-authenticated DTLS peer address migration.

## Fix Direction

Implement CID-to-connection lookup and add a peer address update module that runs only after successful record authentication and compares the newest received epoch and sequence number before changing the send address.
