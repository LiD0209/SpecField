# wolfSSL DTLS 1.2 001-050 partialsatisfied/[non-English text removed]satisfiedcategory

## DTLS 1.2 cookie length[non-English text removed]length

- 023 partialsatisfied cookie: [non-English text removed] opaque cookie<0..2^8-1> [non-English text removed] DTLS_COOKIE_SZ，client[non-English text removed] HelloVerifyRequest cookie [non-English text removed]。

## cookie secret [non-English text removed] secret

- 024 partialsatisfied cookie: wolfSSL [non-English text removed] wolfSSL_DTLS_SetCookieSecret [non-English text removed] secret；CreateDtls12Cookie [non-English text removed]use ssl->buffers.dtlsCookieSecret [non-English text removed]。
- 031 partialsatisfied cookie: wolfSSL [non-English text removed] wolfSSL_DTLS_SetCookieSecret [non-English text removed] secret；CreateDtls12Cookie [non-English text removed]use ssl->buffers.dtlsCookieSecret [non-English text removed]。

## epoch [non-English text removed]

- 041 partialsatisfied epoch: wolfSSL [non-English text removed]。

## PMTU [non-English text removed]

- 042 partialsatisfied fragment: SendHandshakeMsg [non-English text removed] wolfssl_local_GetMaxPlaintextSize [non-English text removed]；wolfSSL_dtls_set_mtu [non-English text removed] repeated retransmissions no response [non-English text removed] DTLS 1.2 timeout pathmedium[non-English text removed]。
- 043 partialsatisfied fragment: SendHandshakeMsg [non-English text removed] wolfssl_local_GetMaxPlaintextSize [non-English text removed]；wolfSSL_dtls_set_mtu [non-English text removed] repeated retransmissions no response [non-English text removed] DTLS 1.2 timeout pathmedium[non-English text removed]。
