# DTLS 1.3 server HelloRetryRequest cookie validation is missing

## Summary
The DTLS 1.3 client path stores a HelloRetryRequest cookie and adds it to the next ClientHello. The BoringSSL server path contains comments that it could request a cookie but does not implement a DTLS 1.3 HRR cookie issuance/verification path.

## Standard Requirement
- Official standard: https://www.rfc-editor.org/rfc/rfc9147#section-5.1
- Section: RFC 9147 Section 5.1, Denial-of-Service Countermeasures

```text
The server then verifies the cookie and proceeds with the handshake only if it is valid ... cookies are only valid for the existing handshake and cannot be stored for future handshakes.
```
该要求的核心是将 DTLS 1.3 的协议状态与线上的压缩字段区分开：wire header 可以只携带低位，但实现仍需要按标准语义处理完整状态、错误路径和 ACK/KeyUpdate 反馈。

## Relevant Source Code
ssl/tls13_client.cc:255

```c++
255:   SSLExtension cookie(TLSEXT_TYPE_cookie),
256:       // If offering PAKE, we won't send key_share extensions and we should
257:       // reject key_share from the peer. Otherwise, it is valid to have sent an
258:       // empty key_share extension, and expect the HelloRetryRequest to contain
259:       // a key_share.
260:       key_share(TLSEXT_TYPE_key_share, !hs->pake_prover),
261:       supported_versions(TLSEXT_TYPE_supported_versions),
262:       ech_unused(TLSEXT_TYPE_encrypted_client_hello,
263:                  hs->selected_ech_config || hs->config->ech_grease_enabled);
264:   if (!ssl_parse_extensions(
265:           &server_hello.extensions, &alert,
266:           {&cookie, &key_share, &supported_versions, &ech_unused},
267:           /*ignore_unknown=*/false)) {
268:     ssl_send_alert(ssl, SSL3_AL_FATAL, alert);
269:     return ssl_hs_error;
270:   }
271: 
272:   if (!cookie.present && !key_share.present) {
273:     OPENSSL_PUT_ERROR(SSL, SSL_R_EMPTY_HELLO_RETRY_REQUEST);
274:     ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
275:     return ssl_hs_error;
276:   }
277:   if (cookie.present) {
278:     CBS cookie_value;
279:     if (!CBS_get_u16_length_prefixed(&cookie.data, &cookie_value) ||  //
280:         CBS_len(&cookie_value) == 0 ||                                //
281:         CBS_len(&cookie.data) != 0) {
282:       OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
283:       ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
284:       return ssl_hs_error;
285:     }
286: 
287:     if (!hs->cookie.CopyFrom(cookie_value)) {
288:       return ssl_hs_error;
289:     }
```

ssl/extensions.cc:2673

```c++
2673: static bool ext_cookie_add_clienthello(const SSL_HANDSHAKE *hs, CBB *out,
2674:                                        CBB *out_compressible,
2675:                                        ssl_client_hello_type_t type) {
2676:   if (hs->cookie.empty()) {
2677:     return true;
2678:   }
2679: 
2680:   CBB contents, cookie;
2681:   if (!CBB_add_u16(out_compressible, TLSEXT_TYPE_cookie) ||
2682:       !CBB_add_u16_length_prefixed(out_compressible, &contents) ||
2683:       !CBB_add_u16_length_prefixed(&contents, &cookie) ||
2684:       !CBB_add_bytes(&cookie, hs->cookie.data(), hs->cookie.size()) ||
2685:       !CBB_flush(out_compressible)) {
```

ssl/tls13_server.cc:820

```c++
820:   SSL *const ssl = hs->ssl;
821:   if (hs->hints_requested) {
822:     return ssl_hs_hints_ready;
823:   }
824: 
825:   // Although a server could HelloRetryRequest with PAKEs to request a cookie,
826:   // we never do so.
827:   assert(hs->pake_verifier == nullptr);
828:   ScopedCBB cbb;
829:   CBB body, session_id, extensions;
830:   if (!ssl->method->init_message(ssl, cbb.get(), &body, SSL3_MT_SERVER_HELLO) ||
831:       !CBB_add_u16(&body,
832:                    SSL_is_dtls(ssl) ? DTLS1_2_VERSION : TLS1_2_VERSION) ||
833:       !CBB_add_bytes(&body, kHelloRetryRequest, SSL3_RANDOM_SIZE) ||
834:       !CBB_add_u8_length_prefixed(&body, &session_id) ||
835:       !CBB_add_bytes(&session_id, hs->session_id.data(),
```

## Implementation Behavior
复核代码证据 ssl/tls13_client.cc:255, ssl/tls13_client.cc:277, ssl/extensions.cc:2673, ssl/tls13_server.cc:825, ssl/tls13_server.cc:968。该路径显示：The DTLS 1.3 client path stores a HelloRetryRequest cookie and adds it to the next ClientHello. The BoringSSL server path contains comments that it could request a cookie but does not implement a DTLS 1.3 HRR cookie issuance/verification path.

## Inconsistency Reason
The DTLS 1.3 client path stores a HelloRetryRequest cookie and adds it to the next ClientHello. The BoringSSL server path contains comments that it could request a cookie but does not implement a DTLS 1.3 HRR cookie issuance/verification path.

## Runtime Evidence
Focused source-level checks were executed with `python focused_static_checks.py` and passed. Native BoringSSL runtime execution was blocked because this machine has no `cmake`, `ninja`, `go`, or prebuilt `ssl_test.exe`; see `runtime_blocker.log`.

## Impact
The impact is interoperability and robustness risk in DTLS 1.3 edge cases: long-lived rekeying, ACK/epoch reconstruction, server-side cookie retry behavior, or lossy-path PMTU recovery can diverge from RFC 9147 expectations.

## Fix Direction
Align the implementation state machine with the RFC requirement, then add BoringSSL runner coverage for the confirmed edge case. Where BoringSSL intentionally does not support the broader RFC feature, document the limit and fail in the protocol-appropriate way.
