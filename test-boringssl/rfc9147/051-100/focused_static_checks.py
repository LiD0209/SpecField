import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing\boringssl-main")

def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")

checks = []

dtls_record = read("ssl/dtls_record.cc")
dtls_method = read("ssl/dtls_method.cc")
d1_both = read("ssl/d1_both.cc")
d1_pkt = read("ssl/d1_pkt.cc")
tls13_both = read("ssl/tls13_both.cc")
tls13_server = read("ssl/tls13_server.cc")

checks.append(("dtls13_header_uses_low_2_epoch_bits", "out[0] = 0x2c | (epoch & 0x3)" in dtls_record))
checks.append(("aead_sequence_excludes_epoch_for_dtls13", "? num.sequence()" in dtls_record and ": num.combined()" in dtls_record))
checks.append(("receive_epoch_state_is_uint16", "uint16_t max_epoch" in dtls_record and "static uint16_t reconstruct_epoch" in dtls_record))
checks.append(("ack_rejects_epoch_over_uint16", "epoch > UINT16_MAX" in d1_pkt))
checks.append(("write_epoch_limit_is_0xffff", "if (prev == 0xffff)" in dtls_method))
checks.append(("recordnumber_is_narrower_than_rfc", "static constexpr uint64_t kMaxSequence = (uint64_t{1} << 48) - 1" in read("ssl/internal.h")))
checks.append(("keyupdate_rotation_deferred_until_ack", "key_update_pending" in d1_pkt and "tls13_rotate_traffic_key(ssl, evp_aead_seal)" in d1_pkt))
checks.append(("no_pmtu_backoff_to_smaller_mtu_found", "timeout_duration_ms * 2" in d1_both and "mtu =" not in d1_both[d1_both.find("dtls1_flush"):]))
checks.append(("server_cookie_path_missing", "could HelloRetryRequest with PAKEs to request a cookie" in tls13_server and "SendHelloRetryRequestCookie" not in tls13_server))

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(f"{name}: {'PASS' if ok else 'FAIL'}")
if failed:
    raise SystemExit("failed checks: " + ", ".join(failed))
