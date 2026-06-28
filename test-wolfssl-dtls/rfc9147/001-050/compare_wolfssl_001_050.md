# wolfSSL DTLS 1.3 001-050 comparison results

- satisfied: 42
- partialsatisfied: 2
- [non-English text removed]satisfied: 3
- not applicable: 3
- [non-English text removed]: 0

[non-English text removed] `wolfssl-master`。

| ID | variable | action | status | [non-English text removed] |
|---:|---|---|---|---|
| 001 | ACK | must be present / must be sent as acknowledgement | satisfied | wolfSSL [non-English text removed]。 |
| 002 | ACK | set to constant | satisfied | wolfSSL [non-English text removed]。 |
| 003 | ACK | must be used to judge acknowledged messages or message fragments; acknowledged ones SHOULD be omitted from transmission | satisfied | wolfSSL [non-English text removed]。 |
| 004 | ACK | set to acknowledge record 2 | satisfied | wolfSSL [non-English text removed]。 |
| 005 | ACK | set to empty | satisfied | wolfSSL [non-English text removed]。 |
| 006 | ACK | validated value check: ACK must indicate a complete flight; cancels all retransmissions and either remains in WAITING, or, if the ACK was for the final flight, transitions to FINISHED | satisfied | wolfSSL [non-English text removed]。 |
| 007 | ACK | validated value check: ACK must indicate a partial flight; retransmit the unacknowledged portion of the flight | satisfied | wolfSSL [non-English text removed]。 |
| 008 | ACK | must be treated as acknowledging records that appear in it | satisfied | wolfSSL [non-English text removed]。 |
| 009 | ACK | set to retransmit of its ACK | satisfied | wolfSSL [non-English text removed]。 |
| 010 | ACK | must be sent | satisfied | wolfSSL [non-English text removed]。 |
| 011 | ACK | must only cover the current outstanding flight | satisfied | wolfSSL [non-English text removed]。 |
| 012 | ACK | must be ACKed | satisfied | wolfSSL [non-English text removed]。 |
| 013 | ACK | should not be sent unless the responding flight cannot be generated immediately | satisfied | wolfSSL [non-English text removed]。 |
| 014 | ACK | should be sent once | satisfied | wolfSSL [non-English text removed]。 |
| 015 | ACK | must not be sent | satisfied | wolfSSL [non-English text removed]。 |
| 016 | ACK | should favor including records which have not yet been acknowledged | partialsatisfied | ACK [non-English text removed]。 |
| 017 | ACK | must equal | satisfied | wolfSSL [non-English text removed]。 |
| 018 | ACK | should ACK as many received packets as can fit into the ACK record | satisfied | wolfSSL [non-English text removed]。 |
| 019 | ACK | may cover more than one flight | satisfied | wolfSSL [non-English text removed]。 |
| 020 | ACK | must not be sent for that record | satisfied | wolfSSL [non-English text removed]。 |
| 021 | ACK | may still be covered | satisfied | wolfSSL [non-English text removed]。 |
| 022 | ACK | must not be present | satisfied | wolfSSL [non-English text removed]。 |
| 023 | ACK | must not cover both because they are in different flights | satisfied | wolfSSL [non-English text removed]。 |
| 024 | ACK | previous flight(s) are implicitly acknowledged | satisfied | wolfSSL [non-English text removed]。 |
| 025 | ACK | clear covered ACK list | satisfied | wolfSSL [non-English text removed]。 |
| 026 | ACK | should generate an ACK covering the messages from that flight which it has received and processed so far | satisfied | wolfSSL [non-English text removed]。 |
| 027 | ACK | may acknowledge the records corresponding to each transmission of each flight or simply acknowledge the most recent one | satisfied | wolfSSL [non-English text removed]。 |
| 028 | body | selected from offered list | partialsatisfied | [non-English text removed] RFC 9147 DTLSHandshake medium[non-English text removed] request_connection_id [non-English text removed]。 |
| 029 | certificate_request | implicitly acknowledged by receipt of the next flight | satisfied | post-handshake CertificateRequest processing[non-English text removed] ACK。 |
| 030 | cids | invalid if value check fails | satisfied | wolfSSL [non-English text removed] DTLS 1.3 unified header medium[non-English text removed]validation C bit/CID；[non-English text removed]。 |
| 031 | cids | must be used immediately | [non-English text removed] NewConnectionId/usage=cid_immediate，[non-English text removed]path。 |
| 032 | cids | may discard extra CIDs | [non-English text removed]path。 |
| 033 | cids | selected in provided order | [non-English text removed] receiver-provided CID [non-English text removed]path。 |
| 034 | cids | must be present | satisfied | wolfSSL [non-English text removed] DTLS 1.3 unified header medium[non-English text removed]validation C bit/CID；[non-English text removed]。 |
| 035 | cids | must be present | satisfied | wolfSSL [non-English text removed] DTLS 1.3 unified header medium[non-English text removed]validation C bit/CID；[non-English text removed]。 |
| 036 | cids | invalid if value check fails | satisfied | wolfSSL [non-English text removed] DTLS 1.3 unified header medium[non-English text removed]validation C bit/CID；[non-English text removed]。 |
| 037 | cipher_suites | must be present / must be absent | not applicable | [non-English text removed] AES/ChaCha20 DTLS cipher suite [non-English text removed]。 |
| 038 | cipher_suites | must be selected from allowed set | satisfied | wolfSSL [non-English text removed]。 |
| 039 | CipherSuite | must define limits on use | satisfied | wolfSSL [non-English text removed]。 |
| 040 | client_hello | must send a new message with cookie added as an extension | satisfied | wolfSSL [non-English text removed]。 |
| 041 | Content Type | validated range check | not applicable | [non-English text removed]rejection。 |
| 042 | Decrypted Content Type | must equal mapped constant for Alert demultiplexing after decryption | satisfied | TLS 1.3 [non-English text removed] alert、handshake、application_data [non-English text removed] UNKNOWN_RECORD_TYPE。 |
| 043 | Decrypted Content Type | must equal mapped constant for DTLSHandshake demultiplexing after decryption | satisfied | TLS 1.3 [non-English text removed] alert、handshake、application_data [non-English text removed] UNKNOWN_RECORD_TYPE。 |
| 044 | Decrypted Content Type | must equal mapped constant for Application Data demultiplexing after decryption | satisfied | TLS 1.3 [non-English text removed] alert、handshake、application_data [non-English text removed] UNKNOWN_RECORD_TYPE。 |
| 045 | Decrypted Content Type | must equal mapped constant for Heartbeat demultiplexing after decryption | not applicable | wolfSSL [non-English text removed] Heartbeat content type processingpath；[non-English text removed]rejection。 |
| 046 | Decrypted Content Type | must equal mapped constant for ACK demultiplexing after decryption | satisfied | TLS 1.3 [non-English text removed] alert、handshake、application_data [non-English text removed] UNKNOWN_RECORD_TYPE。 |
| 047 | Decrypted Content Type | invalid if value check fails; error | satisfied | TLS 1.3 [non-English text removed] alert、handshake、application_data [non-English text removed] UNKNOWN_RECORD_TYPE。 |
| 048 | early_data | must be absent / skipped | satisfied | wolfSSL [non-English text removed] epoch。 |
| 049 | encrypted_extensions | cannot safely be acknowledged because it cannot be decrypted | satisfied | ServerHello [non-English text removed] unified/encrypted record [non-English text removed] EncryptedExtensions [non-English text removed] ACK。 |
| 050 | encrypted_record | derived/computed from another field | satisfied | BuildTls13Message [non-English text removed] unified ciphertext header。 |
