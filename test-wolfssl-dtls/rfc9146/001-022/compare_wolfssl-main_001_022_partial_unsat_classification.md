# partialsatisfied/[non-English text removed]satisfiedcategory 001-022

- [non-English text removed]：3
- status[non-English text removed]：{'partialsatisfied': 3}
- risk[non-English text removed]：{'medium': 3}

## CID [non-English text removed] newer(epoch, sequence) [non-English text removed]
- ID 011：partialsatisfied，risk medium
  - reason: wolfSSL [non-English text removed]。
  - standard_check: RFC 9146 [non-English text removed] Peer Address Update [non-English text removed]。
  - code_check: wolfSSL [non-English text removed] dtlsProcessPendingPeer(ssl, 1) [non-English text removed] previous window，dtlsProcessPendingPeer [non-English text removed]。
  - test_check: verify_wolfssl_dtls_cid_001_022.py::test_peer_update_lacks_strict_newer_gate [non-English text removed]。
  - decision_reason: [non-English text removed] strict newer(epoch, sequence) [non-English text removed] confirmed_partial。
- ID 017：partialsatisfied，risk medium
  - reason: wolfSSL [non-English text removed]。
  - standard_check: RFC 9146 [non-English text removed] Peer Address Update [non-English text removed]。
  - code_check: wolfSSL [non-English text removed] dtlsProcessPendingPeer(ssl, 1) [non-English text removed] previous window，dtlsProcessPendingPeer [non-English text removed]。
  - test_check: verify_wolfssl_dtls_cid_001_022.py::test_peer_update_lacks_strict_newer_gate [non-English text removed]。
  - decision_reason: [non-English text removed] strict newer(epoch, sequence) [non-English text removed] confirmed_partial。
## CMake [non-English text removed] DTLS 1.3
- ID 018：partialsatisfied，risk medium
  - reason: [non-English text removed] DTLS 1.2 tls12_cid(25) path，[non-English text removed] DTLS 1.2 CID。
  - standard_check: RFC 9146 [non-English text removed] DTLS 1.2 content type；DTLS 1.3 CID use[non-English text removed]。
  - code_check: [non-English text removed] FATAL_ERROR。
  - test_check: verify_wolfssl_dtls_cid_001_022.py::test_cmake_cid_requires_dtls13 [non-English text removed]；test_constants_and_record_paths [non-English text removed]。
  - decision_reason: [non-English text removed]，confirmed_partial。
