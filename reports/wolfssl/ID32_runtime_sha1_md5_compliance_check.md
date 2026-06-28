# SHA1/MD5 RFC-8446 Compliance Check (Runtime)

## Tested scope
- Path: server certificate validation by client (wolfSSL example client/server).
- Builds:
  - `WOLFSSL_OPENSSLEXTRA=no, WOLFSSL_MD5=no` (generated `NO_MD5=on`)
  - `WOLFSSL_OPENSSLEXTRA=yes, WOLFSSL_MD5=yes` (generated `NO_MD5=off`)
- Protocols: TLS1.2 and TLS1.3.

## RFC clauses checked
- `TLS1.3.txt:3800`: MD5 cert signatures that must be validated -> endpoint MUST abort.
- `TLS1.3.txt:3801-3804`: SHA-1 is deprecated; abort is RECOMMENDED (not MUST).
- `TLS1.3.txt:3806`: self-signed/trust-anchor exception.
- `TLS1.3.txt:2427`: TLS1.3 server MUST NOT offer SHA-1 cert unless no valid non-SHA1 chain.

## Certificate context used in tests
- runtime sha256/sha1/md5 certs are self-signed: True, True, True.
- This matters because RFC explicitly allows weak algorithms for self-signed/trust-anchor certificates.

## Runtime results
- `WOLFSSL_OPENSSLEXTRA=no, WOLFSSL_MD5=no` / tls12: sha1 success=True, md5 success=False (md5 err: wolfSSL_connect error -232, Hash type not enabled/available)
- `WOLFSSL_OPENSSLEXTRA=no, WOLFSSL_MD5=no` / tls13: sha1 success=True, md5 success=False (md5 err: wolfSSL_connect error -232, Hash type not enabled/available)
- `WOLFSSL_OPENSSLEXTRA=yes, WOLFSSL_MD5=yes` / tls12: sha1 success=True, md5 success=True (md5 err: none)
- `WOLFSSL_OPENSSLEXTRA=yes, WOLFSSL_MD5=yes` / tls13: sha1 success=True, md5 success=True (md5 err: none)

## Clause-by-clause verdict
1. MD5 MUST abort when certificate needs MD5 validation (`3800`)
   - `WOLFSSL_OPENSSLEXTRA=no, WOLFSSL_MD5=no`: md5 is rejected (PASS in tested path).
   - `WOLFSSL_OPENSSLEXTRA=yes, WOLFSSL_MD5=yes`: md5 accepted for self-signed certificate; RFC exception may allow this (`3806`).
   - Verdict: PARTIAL / needs non-self-signed MD5 chain test to conclusively determine strict RFC behavior.
2. SHA-1 abort is RECOMMENDED (`3801-3804`)
   - sha1 accepted in both builds and both protocol versions.
   - Since this is RECOMMENDED not MUST, this is hardening gap, not strict MUST violation.
3. TLS1.3 server MUST NOT offer SHA-1 cert unless no better chain (`2427`)
   - Library does not enforce policy automatically in tested examples; if app configures SHA1 cert, it is offered.
   - Verdict: policy not enforced by default at library boundary; report as secure-default/policy-risk issue.

## Coverage gap
- weak-sign certs found in local cert corpus: 6, non-self-signed weak-sign certs: 0
- Therefore a strict `MD5 MUST abort on non-self-signed chain` proof is pending chain material generation.

## Evidence files
- repro_sha1_md5_issue/out/runtime_hash_policy_server_only.json
- output/cert_subject_issuer_decode.json
- output/certs_sha1_md5_detailed_scan.json
