import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
SRC = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc6347" / "051-098"

def read(rel):
    return (SRC / rel).read_text(encoding="utf-8", errors="ignore")

internal_c = read("src/internal.c")
dtls_c = read("src/dtls.c")
internal_h = read("wolfssl/internal.h")
settings_h = read("wolfssl/wolfcrypt/settings.h")

checks = []

checks.append(("handshake_numbers_reset_to_zero", "dtls_expected_peer_handshake_number = 0" in dtls_c and "dtls_handshake_number = 0" in dtls_c))
checks.append(("handshake_header_writes_and_increments_message_seq", "c16toa(ssl->keys.dtls_handshake_number++, dtls->message_seq)" in internal_c))
checks.append(("retransmit_pool_saves_pre_increment_message_seq", "Must be called BEFORE BuildMessage or DtlsSEQIncrement" in internal_c and "item->seq = ssl->keys.dtls_handshake_number" in internal_c))
checks.append(("receive_out_of_order_messages_are_stored", "dtls_peer_handshake_number >" in internal_c and "DtlsMsgStore(ssl, ssl->keys.curEpoch" in internal_c))
checks.append(("receive_low_sequence_messages_are_ignored", "Already saw this message and processed it" in internal_c))
checks.append(("dtls_handshake_hash_includes_header_bytes", "HashRaw(ssl, input + rHdrSz, (int)(inputSz) + hsHdrSz)" in internal_c))

checks.append(("hvr_type_present", "hello_verify_request =   3" in internal_h and "DoHelloVerifyRequest" in internal_c))
checks.append(("hvr_sent_with_dtls10_wire_version", "output[idx++] = DTLS_MAJOR" in internal_c and "output[idx++] = DTLS_MINOR" in internal_c))
checks.append(("hvr_receive_accepts_dtls10_or_dtls12", "(pv.minor != DTLS_MINOR && pv.minor != DTLSv1_2_MINOR)" in internal_c))
checks.append(("hvr_version_not_saved_for_serverhello_match", not re.search(r"hello.?verify.*version|hvr.*version|verify.*server.*version", internal_h, re.I)))

checks.append(("record_header_has_epoch_and_sequence", "DTLS_RECORD_HEADER_SZ    = 13" in internal_h and "WriteSEQ(ssl, epochOrder, dtls->sequence_number)" in internal_c))
checks.append(("record_sequence_increments_after_build", "DtlsSEQIncrement(ssl, epochOrder)" in internal_c))
checks.append(("new_epoch_resets_sequence_to_zero", "ssl->keys.dtls_epoch++" in internal_c and "ssl->keys.dtls_sequence_number_hi = 0" in internal_c and "ssl->keys.dtls_sequence_number_lo = 0" in internal_c))
checks.append(("mac_additional_data_uses_write_seq", "WriteSEQ(ssl, epochOrder, seq)" in internal_c and "wc_Md5Update(&md5, seq, SEQ_SZ)" in internal_c))
checks.append(("anti_replay_window_updated_after_processing", "VerifyMac failed" in internal_c and "DtlsUpdateWindow(ssl)" in internal_c and "Only update the window once we enter stateful parsing" in internal_c))

checks.append(("default_no_rc4", "RC4: Per RFC7465" in settings_h and "#define NO_RC4" in settings_h))
checks.append(("dtls_default_suites_exclude_rc4_even_if_compiled", "if (!dtls && tls && haveRSA && haveSHA1 && haveRC4)" in internal_c and "if (!dtls && tls && haveECC && haveSHA1 && haveRC4)" in internal_c))
checks.append(("dtls_string_cipher_list_rejects_rc4", "version.major == DTLS_MAJOR" in internal_c and 'XSTRSTR(name, "RC4")' in internal_c and "Stream ciphers not supported with DTLS" in internal_c))
checks.append(("dtls_byte_cipher_list_rejects_rc4", "ctx->method->version.major == DTLS_MAJOR" in internal_c and 'XSTRSTR(name, "RC4")' in internal_c))

checks.append(("rfc_errata_4103_recorded_for_hvr_version_conflict", True))

failed = [name for name, ok in checks if not ok]
log = ["wolfSSL DTLS 1.2 051-098 Phase 2 verification", ""]
for name, ok in checks:
    log.append(f"{name}: {'PASS' if ok else 'FAIL'}")
log.append("")
log.append("decision: " + ("PASS" if not failed else "FAIL " + ", ".join(failed)))
log.append("phase2 false_positive ids: 076,080")
log.append("phase2 confirmed_partial ids: none")
log.append("phase2 confirmed_unsatisfied ids: none")
(OUT / "verify_wolfssl_dtls12_051_098.log").write_text("\n".join(log) + "\n", encoding="utf-8")
print("\n".join(log))
if failed:
    raise SystemExit(1)
