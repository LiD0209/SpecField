## Summary

The implementation does not fully enforce the TLS 1.3 requirement that, when the server is able to provide a certificate chain whose certificates are signed with algorithms advertised by the client, it should select and send such a compliant chain.  
Static analysis shows that the certificate selection logic only matches the client’s advertised **CertificateVerify** signature schemes and key type compatibility, but does not evaluate the signature hash algorithms used across the configured certificate chain. Runtime testing further confirms this gap: even when both a SHA-1-signed chain and a SHA-256-signed chain are simultaneously available, the server may still select the SHA-1-signed chain despite the client advertising only SHA-2 signature schemes.  
This creates a reproducible standards-conformance issue with practical interoperability, observability, and weak-chain exposure implications.

## 1. Requirement (RFC 8446 / TLS1.3.txt)

Specification file: `D:\project\conditionFuzzing\document\TLS1.3.txt`

Relevant original text:

```text
3726:    All certificates provided by the server MUST be signed by a signature
3727:    algorithm advertised by the client if it is able to provide such a
3728:    chain (see Section 4.2.3).  Certificates that are self-signed or
3729:    certificates that are expected to be trust anchors are not validated
3730:    as part of the chain and therefore MAY be signed with any algorithm.
3731:
3732:    If the server cannot produce a certificate chain that is signed only
3733:    via the indicated supported algorithms, then it SHOULD continue the
3734:    handshake by sending the client a certificate chain of its choice
3735:    that may include algorithms that are not known to be supported by the
3736:    client.  This fallback chain SHOULD NOT use the deprecated SHA-1 hash
3737:    algorithm in general, but MAY do so if the client's advertisement
3738:    permits it, and MUST NOT do so otherwise.
```

Core requirement:

- If the server **is able** to provide a compliant chain, all sent certificates should match the client-advertised algorithms.

## 2. Code Path Analysis

### 2.1 Certificate Selection Logic (Server)

File: `mbedtls-development/library/ssl_tls13_server.c`

- Function: `ssl_tls13_pick_key_cert()`
- Key lines:
  - `1123-1129`: iterates over client signature algorithms (`received_sig_algs`) and checks whether they are offered / usable for `CertificateVerify`.
  - `1132-1177`: iterates over configured key-cert pairs and selects the first pair whose key matches the chosen signature scheme.
  - `1160-1165`: checks only key/signature scheme compatibility (`mbedtls_ssl_tls13_check_sig_alg_cert_key_match`, `mbedtls_pk_can_do_psa`).

Critical observation:

- The selection path does **not** evaluate the signature hash algorithm of each certificate in the chain (for example, SHA-1 vs SHA-256 in certificate signatures).

### 2.2 Certificate Message Writing Path

File: `mbedtls-development/library/ssl_tls13_generic.c`

- Function: `ssl_tls13_write_certificate_body()`
- Key lines:
  - `775-791`: writes full chain entries (`while (crt != NULL)`) directly from the configured certificate chain.

Critical observation:

- The writing path serializes whichever chain was selected; it does not apply additional filtering based on certificate-signature algorithms.

### 2.3 Multiple-Certificate Ordering Behavior

File: `mbedtls-development/library/ssl_tls.c`

- `mbedtls_ssl_conf_own_cert()` -> `ssl_append_key_cert()`
- Key lines:
  - `1627-1660`: append behavior preserves insertion order.

Implication:

- When multiple certificates are configured and all pass key/signature-scheme checks, earlier entries can be selected even if their certificate-signature algorithms are weaker.

## 3. Runtime Validation

### 3.1 Existing Weak-Hash Runtime Evidence (Single Certificate)

Observed:

- The client advertised RSA SHA-2 schemes (for example, `rsa_pkcs1_sha256`) and no SHA-1 scheme.
- The server still used a certificate signed with SHA-1.
- The handshake failed during client certificate verification.

This confirms a behavioral inconsistency in practical deployment, but a single-certificate setup alone cannot prove the **"if able"** branch.

### 3.2 Dual-Certificate Runtime Test (Proves the "if able" Condition)

Test design:

- One CA signs two server leaf certificates:
  - Certificate `#1`: `sha1WithRSAEncryption`
  - Certificate `#2`: `sha256WithRSAEncryption`
- Both certificates are loaded simultaneously into `ssl_server2` (`crt_file` and `crt_file2`).
- The client advertises only SHA-2 signature schemes (default TLS 1.3 set as shown in mbedTLS test client logs).

Key results (`result.txt`):

```text
client_rc=1
sha1_cert_sig=... Signature Algorithm: sha1WithRSAEncryption
sha256_cert_sig=... Signature Algorithm: sha256WithRSAEncryption
...
593: ... selected signature algorithm rsa_pss_rsae_sha512 [0806]
594: ... selected certificate (chain) #1:
601: ... signed using      : RSA with SHA1
...
683: ... mbedtls_ssl_handshake returned -0x2700
691: ... Certificate verification failed
```

Interpretation:

- The server had an available SHA-256 certificate chain but still selected the SHA-1 chain.
- Therefore, even in a scenario where a compliant choice exists, the implementation does not enforce the requirement.

## 4. Inconsistency Conclusion

Conclusion:

- This is a real and reproducible inconsistency.
- The implementation matches the client-offered **CertificateVerify** algorithms and key type, but does not enforce certificate-signature algorithm constraints across the sent certificate chain.
- Under dual-certificate availability, observed behavior confirms non-compliant selection with respect to the **"if able"** requirement.

## 5. Security Impact Assessment

Risk type:

- Policy-conformance security risk with practical interoperability and observability impact.

Potential impacts:

### 5.1 Increased Handshake Failure Rate (Availability Impact)

Clients with strict verification profiles reject weak-hash chains, causing avoidable handshake failures even when a compliant chain is available.

### 5.2 Behavior Fingerprinting Surface

Distinct failures caused by weak-signed chain selection can reveal aspects of the server-side certificate-selection strategy.

### 5.3 Weak-Chain Usage Exposure in Permissive Clients

If client policy is lax, weak-signed chains may be accepted, weakening the overall security posture.

Current practical severity:

- Medium.

## 6. Boundary Conditions and Notes

- The RFC explicitly allows exceptions for self-signed certificates and trust anchors.
- This analysis avoids that ambiguity by using a controlled dual-certificate setup and proving that a stronger alternative was actually available.
- Runtime evidence and static path analysis are consistent.

## 7. Mitigation Direction (Without Modifying mbedTLS Source)

If the source code must remain unchanged:

1. Do not configure SHA-1/MD5-signed server certificates or chains in deployment.
2. Keep only SHA-256+ chains in `crt_file` / `crt_file2` candidates.
3. Treat certificate inventory hygiene as a mandatory CI/CD gate.

Note:

- Existing profile controls (for example, verification-side certificate profile settings) mainly affect peer certificate validation and do not fully solve the server-side chain selection semantics discussed here.