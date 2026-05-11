# Heartbeat Demultiplexing Is Not Implemented

## Summary

BoringSSL ?? Heartbeat content type/???????? Heartbeat ????/????????????? RFC ? 5 ? Heartbeat demux ?????????

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Relevant section: `4.1 Demultiplexing DTLS Records`

Relevant original English text from the standard:

```text
OCT == 24   -+--> Heartbeat (DTLS <1.3)
```

????????? DTLS 1.3 ????????? CID ??????????/?? CID ???????????

## Relevant Source Code

ssl/d1_pkt.cc:219

```c++
if (type == SSL3_RT_ACK) {
  return dtls1_process_ack(ssl, out_alert, record_number, record);
}

if (type != SSL3_RT_APPLICATION_DATA) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_RECORD);
```

## Implementation Behavior

Static re-read found no SSL3_RT_HEARTBEAT or heartbeat handler. DTLS record parsing accepts the outer shape, but d1_both.cc and d1_pkt.cc only dispatch handshake, ACK, application data, alert, and CCS-specific paths.

## Inconsistency Reason

Implemented part: Regular DTLS record parsing and rejection of unsupported records are implemented.

Missing or conditional part: Confirmed partial: unsupported Heartbeat is safely rejected/not dispatched, but the implementation cannot process Heartbeat records if that feature were required by the deployment.

## Runtime Evidence

Test source: `test-boringssl/151-187/focused_static_id152_153_185_187.py`

focused_static_id152_153_185_187.py PASS: no heartbeat symbols were found and non-handshake dispatch paths do not route type 24 to a handler.

## Impact

The impact is limited to peers or deployments that exercise this specific protocol path. For CID-related findings, peers that require DTLS CID update messages cannot interoperate with this implementation path. For the empty ACK finding, loss recovery may wait for retransmission timeout instead of being shortened by an empty ACK.

## Fix Direction

Add an explicit implementation path for the missing protocol behavior, including parser/state-machine support, negative tests, and interop tests. Keep unsupported optional features rejected unless and until their negotiation and message handling are fully implemented.
