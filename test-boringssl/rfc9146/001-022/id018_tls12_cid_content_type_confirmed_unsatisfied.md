# tls12_cid Content Type Is Not Supported

## Summary

BoringSSL does not define or process the `tls12_cid(25)` content type. Its DTLS 1.3 record parser rejects the CID bit because no DTLS 1.3 CID negotiation exists in this code path.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146

Relevant section: Section 10.3, "New Entry in the TLS ContentType Registry".

Short original excerpt:

```text
IANA has allocated tls12_cid(25)
```

The content type is specified for DTLS 1.2 CID records.

## Relevant Source Code

`ssl/dtls_record.cc:170`

```c
static bool parse_dtls13_record(SSL *ssl, CBS *in, ParsedDTLSRecord *out) {
  if (out->type & 0x10) {
    // Connection ID bit set, which we didn't negotiate.
    return false;
  }
```

`ssl/dtls_record.cc:548`

```c
  } else {
    out[0] = type;
```

The DTLS 1.2 writer does not substitute a CID content type.

## Implementation Behavior

Source search found no `tls12_cid`, `SSL3_RT_TLS12_CID`, or equivalent content-type constant.

## Inconsistency Reason

The standard defines a content type that signals CID-enhanced DTLS 1.2 records. BoringSSL cannot send or receive that content type.

## Runtime Evidence

The focused audit test verified `tls12_cid_content_type_absent` and `dtls13_cid_bit_rejected`.

## Impact

RFC 9146 records cannot be distinguished from ordinary DTLS records, so compliant peers cannot negotiate and exchange CID-protected traffic with BoringSSL.

## Fix Direction

Define the content type, restrict it to DTLS 1.2 CID records, reject it in non-DTLS or non-negotiated contexts, and connect it to the CID record parser and protection logic.
