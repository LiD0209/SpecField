# mbedTLS TLS 1.3 certificate chain signature algorithm policy gap

## 1. Summary

The core issue is not that mbedTLS ignores the client's advertised `signature_algorithms` entirely. Rather:

- mbedTLS **does** use the client's advertised `signature_algorithms` to select the leaf certificate and the algorithm for `CertificateVerify`.
- But there is **no explicit per-certificate walk** of the full chain to enforce that every intermediate certificate's signing algorithm is also in the client's advertised set.

Therefore this item is classified as **Partially Satisfied**, not Fully Satisfied.

---

## 2. RFC 8446 Source Text

### 2.1 Server certificate selection rule

From [RFC 8446 (TLS 1.3), Section 4.4.2.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2.2):

```text
All certificates provided by the server MUST be signed by a
signature algorithm advertised by the client if it is able to provide
such a chain (see Section 4.2.3).  Certificates that are self-signed
or certificates that are expected to be trust anchors are not
validated as part of the chain and therefore MAY be signed with any
algorithm.
```

Key semantics:

- The constraint applies to **all certificates provided by the server** — the entire chain.
- The requirement level is **MUST**.
- There is a precondition: **if it is able to provide such a chain**.
- Exception: self-signed certificates and trust anchors are exempt.

### 2.2 Fallback rule when a fully matching chain cannot be provided

From [RFC 8446, Section 4.4.2.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2.2):

```text
If the server cannot produce a certificate chain that is signed only
via the indicated supported algorithms, then it SHOULD continue the
handshake by sending the client a certificate chain of its choice
that may include algorithms that are not known to be supported by the
client.  This fallback chain SHOULD NOT use the deprecated SHA-1 hash
algorithm in general, but MAY do so if the client's advertisement
permits it, and MUST NOT do so otherwise.
```

That is:

- The standard first requires the server to provide a fully compliant chain **when it is able to do so**.
- Only when it cannot is fallback behavior permitted.

---

## 3. Code Description (mbedTLS)

### 3.1 Server selects certificate based on client-advertised algorithms

From `ssl_tls13_pick_key_cert()` in `library/ssl_tls13_server.c`:

```c
/*
 * Pick best ( private key, certificate chain ) pair based on the signature
 * algorithms supported by the client.
 */
static int ssl_tls13_pick_key_cert(mbedtls_ssl_context *ssl)
```

The design intent is to select a certificate/key pair based on the client's supported algorithms.

### 3.2 Explicit checks focus on the leaf certificate's public key and usage

```c
if (mbedtls_x509_crt_check_key_usage(
        key_cert->cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) != 0 ||
    mbedtls_x509_crt_check_extended_key_usage(
        key_cert->cert, MBEDTLS_OID_SERVER_AUTH,
        MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) != 0) {
    ...
    continue;
}
```

This checks whether the candidate leaf certificate `key_cert->cert` is suitable for server authentication.

### 3.3 Algorithm matching also focuses on the leaf certificate's public key

```c
if (mbedtls_ssl_tls13_check_sig_alg_cert_key_match(
        *sig_alg, &key_cert->cert->pk)
    && psa_alg != PSA_ALG_NONE &&
    mbedtls_pk_can_do_psa(&key_cert->cert->pk, psa_alg,
                          PSA_KEY_USAGE_VERIFY_HASH) == 1
    ) {
    ssl->handshake->key_cert = key_cert;
    ...
    return 0;
}
```

The explicit constraint target is `key_cert->cert->pk` — the leaf certificate's public key.

### 3.4 No explicit full-chain walk against client-advertised algorithms

From the function above:

- The code iterates over `key_cert_list` candidates.
- Once a candidate is selected, checks are concentrated on `key_cert->cert` itself.
- There is no continuation to walk `key_cert->cert->next` and verify that each intermediate certificate's signing algorithm is also in the client's advertised set.

In other words, the current function checks:

- "Can this leaf certificate be used with the client's advertised algorithm?"

But not:

- "Are all signing algorithms used across this chain within the client's advertised set?"

---

## 4. Root Cause of the Gap

### 4.1 The standard requires full-chain coverage

RFC 8446 uses:

```text
All certificates provided by the server MUST ...
```

The subject is the **entire server-provided certificate chain**.

### 4.2 The implementation enforces this only at the leaf level

What mbedTLS explicitly enforces:

- Selects candidates based on client-advertised `signature_algorithms`.
- Checks leaf certificate key usage.
- Checks leaf certificate public key / algorithm compatibility.
- Selects a certificate/key pair usable for `CertificateVerify`.

What is missing:

- Walking intermediate CA certificates one by one.
- Comparing each intermediate certificate's signing algorithm against the client's advertised set.
- Preferring or requiring a chain where all intermediate signing algorithms are in the client's set.

---

## 5. Runtime Test Evidence

Test environment: WSL2 Ubuntu 24.04, mbedTLS development build.

Test setup:

- Server certificate: `server5-rsa-signed.crt` — EC public key, signed by RSA CA with SHA-256
- Server key: `server5.key` — EC private key
- CA certificate: `test-ca.crt` — RSA, self-signed with SHA-1
- Client advertised `sig_algs`: `ecdsa_secp256r1_sha256` only (no RSA)

Expected per RFC 8446 §4.4.2.2: server should not send this chain (leaf is RSA-signed, not in client's list), or client should reject it.

Actual result:

```
[ecdsa_only_client__rsa_signed_leaf] client_rc=0   ← handshake succeeded
```

Client debug log confirms:

```
ssl_tls.c:8290: |3| got signature scheme [403] ecdsa_secp256r1_sha256
ssl_tls.c:8299: |3| sent signature scheme [403] ecdsa_secp256r1_sha256
...
ssl_tls13_generic.c:0593: |3| signed using      : RSA with SHA-256   ← leaf cert
signed using      : RSA with SHA1                                      ← intermediate CA
signed using      : RSA with SHA-256                                   ← root CA
ssl_tls.c:8875: |3| Certificate verification flags clear               ← accepted
```

The client advertised only ECDSA, the server sent a fully RSA-signed chain, and the client accepted it without error.

Baseline cases for comparison:

| Case | Client sig_algs | Server cert chain | Result |
|------|----------------|-------------------|--------|
| A (key case) | `ecdsa_secp256r1_sha256` only | leaf: RSA-SHA256, CA: RSA-SHA1 | **success** — should have failed |
| B (baseline) | ECDSA + RSA | leaf: RSA-SHA256 | success — expected |
| C (baseline) | `ecdsa_secp256r1_sha256` only | leaf: ECDSA-SHA256 | success — expected |

---

## 6. Conclusion

- mbedTLS does constrain leaf certificate and `CertificateVerify` algorithm selection based on client-advertised algorithms.
- But there is no explicit full-chain enforcement: intermediate CA signing algorithms are not checked against the client's advertised set.
- Runtime test confirms: a client advertising only ECDSA accepts a fully RSA-signed chain from the server without error.
- This is a leaf-level satisfaction with a full-chain enforcement gap, directly contradicting the RFC 8446 §4.4.2.2 `MUST` requirement.
