# wolfSSL DTLS 1.3 101-150 comparison results

- satisfied: 30
- partialsatisfied: 8
- [non-English text removed]satisfied: 2
- not applicable: 10

| ID | variable | action | status | [non-English text removed] |
|---:|---|---|---|---|
| 101 | legacy_cookie | may be accepted if verifiable with both secrets | partialsatisfied | wolfSSL [non-English text removed] DTLS 1.3 HRR cookie secret [non-English text removed]。 |
| 102 | legacy_cookie | invalid if value check fails; terminate handshake | satisfied | [non-English text removed] TlsCheckCookie/RestartHandshakeHashWithCookie [non-English text removed] HRR_COOKIE_ERROR，error[non-English text removed] illegal_parameter alert。 |
| 103 | legacy_cookie | invalidated by secret change | partialsatisfied | wolfSSL [non-English text removed] DTLS 1.3 HRR cookie secret [non-English text removed]。 |
| 104 | legacy_cookie | invalid if generated outside allowed time interval | partialsatisfied | wolfSSL [non-English text removed] DTLS 1.3 HRR cookie secret [non-English text removed]。 |
| 105 | legacy_cookie | must equal zero-length vector | satisfied | [non-English text removed] DTLS 1.3 ClientHello [non-English text removed] legacy_cookie length[non-English text removed] DTLS 1.2 downgrade cookie [non-English text removed] 0。 |
| 106 | legacy_cookie | must be validated | satisfied | [non-English text removed]logicvalidation。 |
| 107 | legacy_cookie | ignored | satisfied | DTLS 1.3 [non-English text removed] cookie extension mediumprocessing。 |
| 108 | legacy_cookie | invalid if value check fails | satisfied | DTLS 1.3 ClientHello medium legacy_cookie [non-English text removed] illegal_parameter。 |
| 109 | legacy_record_version | must be ignored | satisfied | DTLS 1.3 [non-English text removed] legacy_record_version [non-English text removed]。 |
| 110 | legacy_record_version | must equal | satisfied | DTLS 1.3 [non-English text removed] legacy_record_version [non-English text removed]。 |
| 111 | legacy_record_version | may also equal | satisfied | [non-English text removed]。 |
| 112 | legacy_session_id | must not echo | satisfied | DTLS 1.3 [non-English text removed] ClientHello/ServerHello legacy_version [non-English text removed]。 |
| 113 | legacy_session_id | set to constant | satisfied | DTLS 1.3 [non-English text removed] ClientHello/ServerHello legacy_version [non-English text removed]。 |
| 114 | legacy_session_id | set to cached value | partialsatisfied | [non-English text removed] pre-DTLS 1.3 cached session ID [non-English text removed]。 |
| 115 | legacy_version | set to constant | satisfied | DTLS 1.3 [non-English text removed] ClientHello/ServerHello legacy_version [non-English text removed]。 |
| 116 | legacy_version | set to constant | satisfied | DTLS 1.3 [non-English text removed] ClientHello/ServerHello legacy_version [non-English text removed]。 |
| 117 | length | validated range check | partialsatisfied | [non-English text removed]。 |
| 118 | length | derived/computed from another field | satisfied | [non-English text removed] 16-bit length。 |
| 119 | length | must be present / must be absent | satisfied | [non-English text removed]。 |
| 120 | length | invalid if value check fails | satisfied | [non-English text removed] 16-bit length。 |
| 121 | length | must be present | satisfied | [non-English text removed] 16-bit length。 |
| 122 | length | must be absent | satisfied | [non-English text removed] 16-bit length。 |
| 123 | length | must only be used for the last record in a datagram | partialsatisfied | [non-English text removed]。 |
| 124 | length | derived/computed from another field | satisfied | [non-English text removed] 16-bit length。 |
| 125 | length | validated range check | partialsatisfied | [non-English text removed]explicit `idx + recordLength <= inputSize` [non-English text removed]boundary。 |
| 126 | message_hash | computed according to referenced procedure | satisfied | HRR cookie/statelesspathuse synthetic message_hash，[non-English text removed] message_seq/fragment field。 |
| 127 | message_hash | set to synthetic message carrying hash value | satisfied | HRR cookie/statelesspathuse synthetic message_hash，[non-English text removed] message_seq/fragment field。 |
| 128 | message_seq | set to constant | not applicable | [non-English text removed]。 |
| 129 | message_seq | set to constant | not applicable | [non-English text removed]。 |
| 130 | message_seq | must be assigned a specific sequence number | not applicable | [non-English text removed]。 |
| 131 | message_seq | set to constant | not applicable | [non-English text removed]。 |
| 132 | message_seq | set to constant | not applicable | [non-English text removed]。 |
| 133 | message_seq | set to constant | not applicable | [non-English text removed]。 |
| 134 | message_seq | set to constant | not applicable | [non-English text removed]。 |
| 135 | message_seq | set to constant | not applicable | [non-English text removed]。 |
| 136 | message_seq | set to constant | not applicable | [non-English text removed]。 |
| 137 | message_seq | set to constant | not applicable | [non-English text removed]。 |
| 138 | message_seq | set to constant | satisfied | DTLS handshake sequence use dtls_handshake_number/expected_peer_handshake_number [non-English text removed]。 |
| 139 | message_seq | must not be reset | partialsatisfied | [non-English text removed]medium post-handshake ACK/KeyUpdate use[non-English text removed] DTLS 1.3 RTX/sequence [non-English text removed] message_seq。 |
| 140 | message_seq | must equal | satisfied | DTLS handshake sequence use dtls_handshake_number/expected_peer_handshake_number [non-English text removed]。 |
| 141 | message_seq | validated range check | satisfied | DTLS handshake sequence use dtls_handshake_number/expected_peer_handshake_number [non-English text removed]。 |
| 142 | message_seq | invalid if value check fails | satisfied | DTLS handshake sequence use dtls_handshake_number/expected_peer_handshake_number [non-English text removed]。 |
| 143 | message_seq | reuse old value / must not increment | satisfied | DTLS handshake sequence use dtls_handshake_number/expected_peer_handshake_number [non-English text removed]。 |
| 144 | message_seq | incremented by one | satisfied | DTLS handshake sequence use dtls_handshake_number/expected_peer_handshake_number [non-English text removed]。 |
| 145 | num_cids | validated upper-bound exception / may return fewer than requested | [non-English text removed] RFC 9146/DTLS CID extension [non-English text removed] DTLS 1.3 unified header CID bit，[non-English text removed] RFC 9147 RequestConnectionId/NewConnectionId handshake [non-English text removed] cid_spare processing。 |
| 146 | num_cids | copy from requested value | [non-English text removed] RFC 9146/DTLS CID extension [non-English text removed] DTLS 1.3 unified header CID bit，[non-English text removed] RFC 9147 RequestConnectionId/NewConnectionId handshake [non-English text removed] cid_spare processing。 |
| 147 | Outer Content Type | validated range check for encrypted_record demultiplexing | satisfied | [non-English text removed] content type 20/21/22 [non-English text removed] DTLS 1.3 unified header [non-English text removed]。 |
| 148 | Outer Content Type | must equal mapped constant for ChangeCipherSpec demultiplexing | satisfied | [non-English text removed] content type 20/21/22 [non-English text removed] DTLS 1.3 unified header [non-English text removed]。 |
| 149 | Outer Content Type | must equal mapped constant for Alert demultiplexing | satisfied | [non-English text removed] content type 20/21/22 [non-English text removed] DTLS 1.3 unified header [non-English text removed]。 |
| 150 | Outer Content Type | must equal mapped constant for DTLSHandshake demultiplexing | satisfied | [non-English text removed] content type 20/21/22 [non-English text removed] DTLS 1.3 unified header [non-English text removed]。 |
