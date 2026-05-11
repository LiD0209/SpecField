# RFC 9146 CID MAC and AEAD Additional Data Are Missing

## Summary

BoringSSL does not implement the RFC 9146 modified MAC or AEAD additional data calculation for `tls12_cid` records.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146

Relevant sections: Section 5, "Record Payload Protection"; Section 5.1; Section 5.3.

Short original excerpts:

```text
seq_num_placeholder: 8 bytes of 0xff.
```

```text
additional_data = seq_num_placeholder + tls12_cid
```

The standard changes the MAC/AAD input for CID records so CID and non-CID records cannot collide.

## Relevant Source Code

`ssl/dtls_record.cc:327`

```c
  if (!record.read_epoch->aead->Open(out, record.type, record.version,
                                     dtls_aead_sequence(ssl, record.number),
                                     record.header,
                                     cbs_to_writable_bytes(record.body))) {
```

`ssl/dtls_record.cc:556`

```c
  if (!write_epoch->aead->SealScatter(
          out + record_header_len, out + prefix, out + prefix + in_len, type,
          record_version, dtls_aead_sequence(ssl, record_number), header, in,
          in_len, extra_in, extra_in_len)) {
```

Both read and write paths use the serialized record header as AEAD additional data.

## Implementation Behavior

No `seq_num_placeholder`, `cid_length`, `tls12_cid`, or negotiated CID value appears in the MAC/AAD construction.

## Inconsistency Reason

RFC 9146 requires CID records to use a modified protection input. BoringSSL only implements ordinary DTLS 1.2 and DTLS 1.3 record protection inputs, so CID records cannot be authenticated according to RFC 9146.

## Runtime Evidence

The focused audit test verified `cid_aad_algorithm_absent` and passed.

## Impact

Even if extension negotiation were added separately, records would not interoperate or authenticate correctly until the RFC 9146 protection input is implemented.

## Fix Direction

Add a CID-aware record protection branch for DTLS 1.2 records with outer type `tls12_cid`, including block cipher, encrypt-then-MAC, and AEAD calculations.
