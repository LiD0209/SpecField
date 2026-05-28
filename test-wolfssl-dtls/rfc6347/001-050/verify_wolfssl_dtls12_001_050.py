import json
import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
SRC = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc6347" / "001-050"

checks = []

def text(rel):
    return (SRC / rel).read_text(encoding="utf-8", errors="ignore")

internal_h = text("wolfssl/internal.h")
dtls_c = text("src/dtls.c")
internal_c = text("src/internal.c")
ssl_c = text("src/ssl.c")

checks.append(("id023_max_cookie_len_32", "MAX_COOKIE_LEN = 32" in internal_h))
checks.append(("id023_hvr_copy_guard", "cookieSz <= MAX_COOKIE_LEN" in internal_c and "ssl->arrays->cookieSz = cookieSz" in internal_c))
checks.append(("id023_fixed_cookie_size_check", "ch->cookie.size != DTLS_COOKIE_SZ" in dtls_c))

checks.append(("id024_current_secret_only_setter", "ssl->buffers.dtlsCookieSecret.buffer" in ssl_c and "ForceZero(ssl->buffers.dtlsCookieSecret.buffer" in ssl_c))
checks.append(("id024_hmac_uses_current_secret", "wc_HmacSetKey(&cookieHmac, DTLS_COOKIE_TYPE" in dtls_c and "ssl->buffers.dtlsCookieSecret.buffer" in dtls_c))
checks.append(("id024_no_previous_secret_symbol", not re.search(r"prev(ious)?[A-Za-z_]*CookieSecret|old[A-Za-z_]*CookieSecret", dtls_c + ssl_c + internal_h, re.I)))

checks.append(("id041_epoch_increment_present", "ssl->keys.dtls_epoch++" in internal_c))
checks.append(("id041_no_msl_timer", not re.search(r"maximum segment lifetime|segment lifetime|\b2MSL\b|\bMSL\b", internal_c + ssl_c + dtls_c, re.I)))

checks.append(("id042_fragmentation_uses_max_plaintext", "wolfssl_local_GetMaxPlaintextSize" in internal_c and "while (ssl->fragOffset < inputSz)" in internal_c))
checks.append(("id042_timeout_retransmits_pool", "DtlsMsgPoolTimeout" in ssl_c and "DtlsMsgPoolSend(ssl, 0)" in ssl_c))
timeout_body = re.search(r"int DtlsMsgPoolTimeout\(WOLFSSL\* ssl\)(.*?)return result;", internal_c, re.S)
checks.append(("id042_timeout_does_not_adjust_mtu", timeout_body is not None and "dtlsMtuSz" not in timeout_body.group(1) and "frag" not in timeout_body.group(1).lower()))

failed = [name for name, ok in checks if not ok]
log = ["wolfSSL DTLS 1.2 001-050 Phase 2 verification", ""]
for name, ok in checks:
    log.append(f"{name}: {'PASS' if ok else 'FAIL'}")
log.append("")
log.append("decision: " + ("PASS" if not failed else "FAIL " + ", ".join(failed)))
(OUT / "verify_wolfssl_dtls12_001_050.log").write_text("\n".join(log) + "\n", encoding="utf-8")
print("\n".join(log))
if failed:
    raise SystemExit(1)
