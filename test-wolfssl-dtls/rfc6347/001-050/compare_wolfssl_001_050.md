# wolfSSL DTLS 1.2 001-050 comparison results

- satisfied: 43
- partialsatisfied: 6
- [non-English text removed]satisfied: 0
- not applicable: 1

| ID | variable | action | status | [non-English text removed] |
|---:|---|---|---|---|
| 001 | body | selected from enumerated cases based on HandshakeType | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 002 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 003 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 004 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 005 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 006 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 007 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 008 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 009 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 010 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 011 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 012 | body | selected from offered list | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 013 | cipher_suites | must equal original ClientHello value | satisfied | clientreceives HelloVerifyRequest [non-English text removed] ClientHello；version/random/session_id/cipher_suites/compression_methods [non-English text removed]。 |
| 014 | cipher_suites | validated range check | satisfied | ClientHello [non-English text removed]length；DTLS 1.3 stateless [non-English text removed]。 |
| 015 | client_hello | must be absent | satisfied | [non-English text removed]；clientprocessing HelloVerifyRequest [non-English text removed] CertificateVerify/Finished transcript [non-English text removed] HelloVerifyRequest。 |
| 016 | compression_methods | must equal original ClientHello value | satisfied | clientreceives HelloVerifyRequest [non-English text removed] ClientHello；version/random/session_id/cipher_suites/compression_methods [non-English text removed]。 |
| 017 | compression_methods | validated range check | satisfied | ClientHello [non-English text removed] u8 compression_methods vector [non-English text removed]。 |
| 018 | cookie | set/added to retransmitted ClientHello | satisfied | ClientHello cookie use u8 length[non-English text removed] 0，DoHelloVerifyRequest [non-English text removed] ClientHello。 |
| 019 | cookie | set to constant | satisfied | ClientHello cookie use u8 length[non-English text removed] 0，DoHelloVerifyRequest [non-English text removed] ClientHello。 |
| 020 | cookie | validated range check | satisfied | ClientHello cookie use u8 length[non-English text removed] 0，DoHelloVerifyRequest [non-English text removed] ClientHello。 |
| 021 | cookie | invalid if value check fails | satisfied | server stateless ClientHello path[non-English text removed] CheckDtlsCookie；length[non-English text removed] HMAC cookie length，ConstantCompare [non-English text removed] HelloVerifyRequest。 |
| 022 | cookie | must be present | satisfied | server[non-English text removed]。SendHelloVerifyRequest rejection[non-English text removed] cookie。 |
| 023 | cookie | validated range check | partialsatisfied | [non-English text removed] opaque cookie<0..2^8-1> [non-English text removed] DTLS_COOKIE_SZ，client[non-English text removed] HelloVerifyRequest cookie [non-English text removed]。 |
| 024 | cookie | membership check | partialsatisfied | wolfSSL [non-English text removed] wolfSSL_DTLS_SetCookieSecret [non-English text removed] secret；CreateDtls12Cookie [non-English text removed]use ssl->buffers.dtlsCookieSecret [non-English text removed]。 |
| 025 | cookie | must be present as part of cookie exchange support | satisfied | server[non-English text removed]。SendHelloVerifyRequest rejection[non-English text removed] cookie。 |
| 026 | cookie | invalid if value check fails | satisfied | server stateless ClientHello path[non-English text removed] CheckDtlsCookie；length[non-English text removed] HMAC cookie length，ConstantCompare [non-English text removed] HelloVerifyRequest。 |
| 027 | cookie | validated range check | satisfied | ClientHello cookie use u8 length[non-English text removed] 0，DoHelloVerifyRequest [non-English text removed] ClientHello。 |
| 028 | cookie | validated range check | satisfied | ClientHello cookie use u8 length[non-English text removed] 0，DoHelloVerifyRequest [non-English text removed] ClientHello。 |
| 029 | cookie | derived/computed from another field | satisfied | server[non-English text removed]。SendHelloVerifyRequest rejection[non-English text removed] cookie。 |
| 030 | cookie | validity check | satisfied | server stateless ClientHello path[non-English text removed] CheckDtlsCookie；length[non-English text removed] HMAC cookie length，ConstantCompare [non-English text removed] HelloVerifyRequest。 |
| 031 | cookie | invalid if value check fails | partialsatisfied | wolfSSL [non-English text removed] wolfSSL_DTLS_SetCookieSecret [non-English text removed] secret；CreateDtls12Cookie [non-English text removed]use ssl->buffers.dtlsCookieSecret [non-English text removed]。 |
| 032 | epoch | increment | satisfied | DTLS [non-English text removed] epoch sequence；WriteSEQ [non-English text removed]。 |
| 033 | epoch | must not wrap | satisfied | wolfSSL use 16-bit dtls_epoch field[non-English text removed]path。 |
| 034 | epoch | set to constant | satisfied | DTLS [non-English text removed] epoch sequence；WriteSEQ [non-English text removed]。 |
| 035 | epoch | increment | satisfied | DTLS [non-English text removed] epoch sequence；WriteSEQ [non-English text removed]。 |
| 036 | epoch | invalid if value check fails | satisfied | GetRecordHeader [non-English text removed] replay window、application_data [non-English text removed]error。 |
| 037 | epoch | must equal / must not equal | satisfied | GetRecordHeader [non-English text removed] replay window、application_data [non-English text removed]error。 |
| 038 | epoch | must equal | not applicable | [non-English text removed]receives epoch 0 ClientHello [non-English text removed] association。wolfSSL record layer [non-English text removed]。 |
| 039 | epoch | derived/computed with sequence_number by concatenation | satisfied | DTLS [non-English text removed] epoch sequence；WriteSEQ [non-English text removed]。 |
| 040 | epoch | must accept old epoch packets until handshake completes | satisfied | wolfSSL [non-English text removed] flight；DtlsMsgPoolSend [non-English text removed] sequence，VerifyForTxDtlsMsgDelete [non-English text removed]。 |
| 041 | epoch | must not equal previously used epoch value | partialsatisfied | wolfSSL [non-English text removed]。 |
| 042 | fragment | must be fragmented | partialsatisfied | SendHandshakeMsg [non-English text removed] wolfssl_local_GetMaxPlaintextSize [non-English text removed]；wolfSSL_dtls_set_mtu [non-English text removed] repeated retransmissions no response [non-English text removed] DTLS 1.2 timeout pathmedium[non-English text removed]。 |
| 043 | fragment | must be fragmented | partialsatisfied | SendHandshakeMsg [non-English text removed] wolfssl_local_GetMaxPlaintextSize [non-English text removed]；wolfSSL_dtls_set_mtu [non-English text removed] repeated retransmissions no response [non-English text removed] DTLS 1.2 timeout pathmedium[non-English text removed]。 |
| 044 | fragment_length | must be present | satisfied | AddHandShakeHeader [non-English text removed] message_seq、fragment_offset、fragment_length；[non-English text removed] GetDtlsHandShakeHeader [non-English text removed] offset=0、fragment_length=total length [non-English text removed] transcript hash use。 |
| 045 | fragment_offset | must be present | satisfied | AddHandShakeHeader [non-English text removed] message_seq、fragment_offset、fragment_length；[non-English text removed] GetDtlsHandShakeHeader [non-English text removed] offset=0、fragment_length=total length [non-English text removed] transcript hash use。 |
| 046 | hello_verify_request | set to constant | satisfied | wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。 |
| 047 | hello_verify_request | must be absent | satisfied | [non-English text removed]；clientprocessing HelloVerifyRequest [non-English text removed] CertificateVerify/Finished transcript [non-English text removed] HelloVerifyRequest。 |
| 048 | length | validated range check | satisfied | GetDtlsRecordHeader [non-English text removed] DTLSPlaintext.length，GetRecordHeader [non-English text removed]。 |
| 049 | level | set to constant | satisfied | wolfSSL [non-English text removed] SendAlert use alert_fatal，bad MAC path[non-English text removed]。 |
| 050 | level | set to constant | satisfied | wolfSSL [non-English text removed] SendAlert use alert_fatal，bad MAC path[non-English text removed]。 |
