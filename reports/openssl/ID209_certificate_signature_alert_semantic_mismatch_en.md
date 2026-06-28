# Explanation of the Alert Semantic Difference in the Certificate Signature Failure Scenario

## Conclusion

In the "certificate signature verification failure" scenario, the TLS 1.3 normative semantics are not consistent with OpenSSL's alert mapping:

- RFC 8446 classifies "signatures in the certificate could not be verified correctly" as `bad_certificate`
- OpenSSL maps `X509_V_ERR_CERT_SIGNATURE_FAILURE` to `SSL_AD_DECRYPT_ERROR`
- In the actual reproduction, the client also receives `fatal decrypt_error`

Therefore, the difference here is an inconsistency in alert semantics rather than in the handshake result: the connection is still terminated correctly, and the security boundary is not weakened.

## Normative Basis

RFC 8446 defines `bad_certificate` as follows:

```text
bad_certificate:  A certificate was corrupt, contained signatures
   that did not verify correctly, etc.
```

The phrase `contained signatures that did not verify correctly` directly covers the "certificate signature verification failure" scenario. Therefore, according to the normative text semantics, this kind of error should fall under `bad_certificate`.

## OpenSSL Mapping Basis

In `ssl/statem/statem_lib.c`, OpenSSL defines the mapping from X.509 verification errors to TLS alerts in `x509table[]`. The relevant entries are:

```c
{ X509_V_ERR_CERT_SIGNATURE_FAILURE, SSL_AD_DECRYPT_ERROR },
{ X509_V_ERR_CRL_SIGNATURE_FAILURE,  SSL_AD_DECRYPT_ERROR },
```

That is, `X509_V_ERR_CERT_SIGNATURE_FAILURE` is not mapped to `SSL_AD_BAD_CERTIFICATE`; instead, it is mapped to `SSL_AD_DECRYPT_ERROR`.

In `ssl/statem/statem_srvr.c`, after server-side certificate verification fails, the following code is executed:

```c
SSLfatal(s, ssl_x509err2alert(s->verify_result),
    SSL_R_CERTIFICATE_VERIFY_FAILED);
```

Therefore, as long as `verify_result` is `X509_V_ERR_CERT_SIGNATURE_FAILURE`, the alert ultimately sent is `decrypt_error`.

## Runtime Reproduction Result

The certificate verification log shows:

```text
error 7 at 0 depth lookup: certificate signature failure
```

The handshake log shows:

```text
<<< TLS 1.3, Alert [length 0002], fatal decrypt_error
SSL3 alert read:fatal:decrypt error
... SSL alert number 51
```

This shows that in the same failure:

- The X.509 verification layer has already explicitly identified it as `certificate signature failure`
- The TLS layer ultimately sends the alert `fatal decrypt_error`

## Final Explanation

Based on this, it can be confirmed that there is a verifiable semantic difference here:

- Normative semantics: it should fall under `bad_certificate`
- OpenSSL implementation: it actually sends `decrypt_error`

This kind of difference mainly affects alert semantics, log classification, and standards comparison analysis. It does not affect the result that the handshake fails, nor does it allow certificate verification to be bypassed.
