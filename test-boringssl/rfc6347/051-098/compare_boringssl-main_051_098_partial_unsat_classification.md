# Partial / Unsatisfied Classification 051-098

- Total reviewed: 7
- Status summary: 部分满足=3; 不满足=4

## DTLS 1.2 renegotiation not implemented
- 53 `message_seq`: 部分满足, risk=low. BoringSSL initializes and increments DTLS handshake message_seq for supported initial handshakes, but DTLS renegotiation is explicitly unsupported, so the HelloRequest rehandshake-specific message_seq=0 behavior is not implemented as an executable DTLS path.
  - standard_check: RFC 6347 Section 4.2.2 defines message_seq reset behavior for each handshake and gives rehandshake examples for HelloRequest=0 and ServerHello=1.
  - code_check: ssl/d1_both.cc implements general handshake sequence counters, but ssl/d1_pkt.cc treats post-handshake DTLS 1.2 handshake records as unsupported renegotiation.
  - test_check: repro_dtls12_hvr_static_probe.exe confirms d1_pkt.cc contains the unsupported-renegotiation path. Build and run succeeded with exit code 0.
  - decision: confirmed_partial. The generic mechanism or receive-side syntax exists, but the exact condition is unsupported or only partially implemented.
- 54 `message_seq`: 部分满足, risk=low. The general handshake_write_seq counter can produce increasing message numbers, but BoringSSL rejects DTLS renegotiation traffic, so the rehandshake ServerHello message_seq=1 case is not a supported runtime behavior.
  - standard_check: RFC 6347 Section 4.2.2 defines message_seq reset behavior for each handshake and gives rehandshake examples for HelloRequest=0 and ServerHello=1.
  - code_check: ssl/d1_both.cc implements general handshake sequence counters, but ssl/d1_pkt.cc treats post-handshake DTLS 1.2 handshake records as unsupported renegotiation.
  - test_check: repro_dtls12_hvr_static_probe.exe confirms d1_pkt.cc contains the unsupported-renegotiation path. Build and run succeeded with exit code 0.
  - decision: confirmed_partial. The generic mechanism or receive-side syntax exists, but the exact condition is unsupported or only partially implemented.

## HelloVerifyRequest receive-only syntax support
- 78 `server_version`: 部分满足, risk=low. BoringSSL parses HelloVerifyRequest as uint16 server_version plus uint8-length-prefixed cookie on the client side, but because the server never generates the message, syntax support is receive-only.
  - standard_check: RFC 6347 Section 4.2.1 defines HelloVerifyRequest, cookie retransmission, HVR record-sequence copying, and HVR server_version guidance.
  - code_check: handshake_client.cc parses HVR and retransmits ClientHello with the cookie; focused probe found no server-side DTLS1_MT_HELLO_VERIFY_REQUEST generation or SSL_OP_COOKIE_EXCHANGE-equivalent API.
  - test_check: repro_dtls12_hvr_static_probe.exe confirms client HVR handling is present, server HVR generation/API is absent, and DTLS 1.2 renegotiation is unsupported. Build and run succeeded with exit code 0.
  - decision: confirmed_partial. The generic mechanism or receive-side syntax exists, but the exact condition is unsupported or only partially implemented.

## HelloVerifyRequest server generation path missing
- 64 `sequence_number`: 不满足, risk=medium. BoringSSL implements client-side parsing of HelloVerifyRequest, but the server implementation contains no HelloVerifyRequest generation/cookie-exchange path, so it cannot copy the ClientHello record sequence number into an outgoing HelloVerifyRequest.
  - standard_check: RFC 6347 Section 4.2.1 defines HelloVerifyRequest, cookie retransmission, HVR record-sequence copying, and HVR server_version guidance.
  - code_check: handshake_client.cc parses HVR and retransmits ClientHello with the cookie; focused probe found no server-side DTLS1_MT_HELLO_VERIFY_REQUEST generation or SSL_OP_COOKIE_EXCHANGE-equivalent API.
  - test_check: repro_dtls12_hvr_static_probe.exe confirms client HVR handling is present, server HVR generation/API is absent, and DTLS 1.2 renegotiation is unsupported. Build and run succeeded with exit code 0.
  - decision: confirmed_unsatisfied. The required server-side behavior is absent from the implementation and the focused probe confirms the missing path.
- 72 `sequence_number`: 不满足, risk=medium. The RFC rule avoiding sequence-number duplication across multiple cookie exchanges depends on actually sending HelloVerifyRequest records. BoringSSL has no server-side HVR send path and only assigns normal fresh record numbers when sealing records.
  - standard_check: RFC 6347 Section 4.2.1 defines HelloVerifyRequest, cookie retransmission, HVR record-sequence copying, and HVR server_version guidance.
  - code_check: handshake_client.cc parses HVR and retransmits ClientHello with the cookie; focused probe found no server-side DTLS1_MT_HELLO_VERIFY_REQUEST generation or SSL_OP_COOKIE_EXCHANGE-equivalent API.
  - test_check: repro_dtls12_hvr_static_probe.exe confirms client HVR handling is present, server HVR generation/API is absent, and DTLS 1.2 renegotiation is unsupported. Build and run succeeded with exit code 0.
  - decision: confirmed_unsatisfied. The required server-side behavior is absent from the implementation and the focused probe confirms the missing path.
- 77 `server_version`: 不满足, risk=medium. The client can parse a HelloVerifyRequest.server_version field, but no BoringSSL DTLS server code emits HelloVerifyRequest, so the DTLS 1.2 server SHOULD-send-DTLS-1.0-HVR-version behavior is absent.
  - standard_check: RFC 6347 Section 4.2.1 defines HelloVerifyRequest, cookie retransmission, HVR record-sequence copying, and HVR server_version guidance.
  - code_check: handshake_client.cc parses HVR and retransmits ClientHello with the cookie; focused probe found no server-side DTLS1_MT_HELLO_VERIFY_REQUEST generation or SSL_OP_COOKIE_EXCHANGE-equivalent API.
  - test_check: repro_dtls12_hvr_static_probe.exe confirms client HVR handling is present, server HVR generation/API is absent, and DTLS 1.2 renegotiation is unsupported. Build and run succeeded with exit code 0.
  - decision: confirmed_unsatisfied. The required server-side behavior is absent from the implementation and the focused probe confirms the missing path.
- 80 `server_version`: 不满足, risk=medium. The requirement that a server use in HelloVerifyRequest the same version it would use in ServerHello cannot be exercised because BoringSSL does not implement server-side HelloVerifyRequest generation.
  - standard_check: RFC 6347 Section 4.2.1 defines HelloVerifyRequest, cookie retransmission, HVR record-sequence copying, and HVR server_version guidance.
  - code_check: handshake_client.cc parses HVR and retransmits ClientHello with the cookie; focused probe found no server-side DTLS1_MT_HELLO_VERIFY_REQUEST generation or SSL_OP_COOKIE_EXCHANGE-equivalent API.
  - test_check: repro_dtls12_hvr_static_probe.exe confirms client HVR handling is present, server HVR generation/API is absent, and DTLS 1.2 renegotiation is unsupported. Build and run succeeded with exit code 0.
  - decision: confirmed_unsatisfied. The required server-side behavior is absent from the implementation and the focused probe confirms the missing path.
