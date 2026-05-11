# DTLS KeyUpdate limit handling aborts instead of ignoring update_requested

## Summary
BoringSSL avoids sending beyond its epoch limit, but the failure path is a too-many-key-updates error from next_epoch rather than ignoring update_requested while continuing the connection as RFC 9147 specifies near the sending limit.

## Standard Requirement
- Official standard: https://www.rfc-editor.org/rfc/rfc9147#section-8
- Section: RFC 9147 Section 8, Key Updates

```text
KeyUpdates MUST be acknowledged ... implementations MUST NOT send records with the new keys or send a new KeyUpdate until the previous KeyUpdate has been acknowledged ... sending implementations MUST NOT allow the epoch to exceed 2^48-1.
```
该要求的核心是将 DTLS 1.3 的协议状态与线上的压缩字段区分开：wire header 可以只携带低位，但实现仍需要按标准语义处理完整状态、错误路径和 ACK/KeyUpdate 反馈。

## Relevant Source Code
ssl/tls13_both.cc:678

```c++
678: bool tls13_add_key_update(SSL *ssl, int request_type) {
679:   if (ssl->s3->key_update_pending) {
680:     return true;
681:   }
682: 
683:   // We do not support multiple parallel outgoing flights. If there is an
684:   // outgoing flight pending, queue the KeyUpdate for later.
685:   if (SSL_is_dtls(ssl) && !ssl->d1->outgoing_messages.empty()) {
686:     ssl->d1->queued_key_update = request_type == SSL_KEY_UPDATE_REQUESTED
687:                                      ? QueuedKeyUpdate::kUpdateRequested
688:                                      : QueuedKeyUpdate::kUpdateNotRequested;
689:     return true;
690:   }
691: 
692:   ScopedCBB cbb;
693:   CBB body_cbb;
694:   if (!ssl->method->init_message(ssl, cbb.get(), &body_cbb,
695:                                  SSL3_MT_KEY_UPDATE) ||
696:       !CBB_add_u8(&body_cbb, request_type) ||
697:       !ssl_add_message_cbb(ssl, cbb.get())) {
698:     return false;
699:   }
700: 
701:   // In DTLS, the actual key update is deferred until KeyUpdate is ACKed.
702:   if (!SSL_is_dtls(ssl) && !tls13_rotate_traffic_key(ssl, evp_aead_seal)) {
703:     return false;
704:   }
705: 
706:   // Suppress KeyUpdate acknowledgments until this change is written to the
707:   // wire. This prevents us from accumulating write obligations when read and
708:   // write progress at different rates. See RFC 8446, section 4.6.3.
709:   ssl->s3->key_update_pending = true;
710:   ssl->method->finish_flight(ssl);
```

ssl/tls13_both.cc:714

```c++
714: static bool tls13_receive_key_update(SSL *ssl, const SSLMessage &msg) {
715:   CBS body = msg.body;
716:   uint8_t key_update_request;
717:   if (!CBS_get_u8(&body, &key_update_request) ||              //
718:       CBS_len(&body) != 0 ||                                  //
719:       (key_update_request != SSL_KEY_UPDATE_NOT_REQUESTED &&  //
720:        key_update_request != SSL_KEY_UPDATE_REQUESTED)) {
721:     OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
722:     ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
723:     return false;
724:   }
725: 
726:   if (!tls13_rotate_traffic_key(ssl, evp_aead_open)) {
727:     return false;
728:   }
729: 
730:   // Acknowledge the KeyUpdate
731:   if (key_update_request == SSL_KEY_UPDATE_REQUESTED &&
732:       !tls13_add_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED)) {
733:     return false;
```

ssl/dtls_method.cc:52

```c++
52:     case ssl_encryption_application:
53:       if (prev < ssl_encryption_application &&
54:           ssl_protocol_version(ssl) >= TLS1_3_VERSION) {
55:         *out = static_cast<uint16_t>(level);
56:         return true;
57:       }
58: 
59:       if (prev == 0xffff) {
60:         OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_KEY_UPDATES);
61:         return false;
62:       }
63:       *out = prev + 1;
64:       return true;
```

## Implementation Behavior
复核代码证据 ssl/tls13_both.cc:678, ssl/tls13_both.cc:701, ssl/d1_pkt.cc:122, ssl/d1_pkt.cc:130, ssl/dtls_method.cc:59。该路径显示：BoringSSL avoids sending beyond its epoch limit, but the failure path is a too-many-key-updates error from next_epoch rather than ignoring update_requested while continuing the connection as RFC 9147 specifies near the sending limit.

## Inconsistency Reason
BoringSSL avoids sending beyond its epoch limit, but the failure path is a too-many-key-updates error from next_epoch rather than ignoring update_requested while continuing the connection as RFC 9147 specifies near the sending limit.

## Runtime Evidence
Focused source-level checks were executed with `python focused_static_checks.py` and passed. Native BoringSSL runtime execution was blocked because this machine has no `cmake`, `ninja`, `go`, or prebuilt `ssl_test.exe`; see `runtime_blocker.log`.

## Impact
The impact is interoperability and robustness risk in DTLS 1.3 edge cases: long-lived rekeying, ACK/epoch reconstruction, server-side cookie retry behavior, or lossy-path PMTU recovery can diverge from RFC 9147 expectations.

## Fix Direction
Align the implementation state machine with the RFC requirement, then add BoringSSL runner coverage for the confirmed edge case. Where BoringSSL intentionally does not support the broader RFC feature, document the limit and fail in the protocol-appropriate way.
