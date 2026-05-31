#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
REPO = ROOT / "wolfssl-master"


def read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8", errors="replace")


def check(name: str, condition: bool) -> bool:
    print(f"{name}: {'PASS' if condition else 'FAIL'}")
    return condition


def block(text: str, start_marker: str, end_marker: str) -> str:
    start = text.find(start_marker)
    if start < 0:
        return ""
    end = text.find(end_marker, start + len(start_marker))
    if end < 0:
        return text[start:]
    return text[start:end]


def w64_increment(hi: int, lo: int) -> tuple[int, int]:
    lo = (lo + 1) & 0xffffffff
    if lo == 0:
        hi = (hi + 1) & 0xffffffff
    return hi, lo


def is_zero(hi: int, lo: int) -> bool:
    return hi == 0 and lo == 0


def main() -> int:
    required = [
        REPO / "src" / "dtls13.c",
        REPO / "src" / "tls13.c",
        REPO / "wolfcrypt" / "src" / "misc.c",
        REPO / "wolfssl" / "wolfcrypt" / "types.h",
        REPO / "wolfssl" / "internal.h",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        print("Missing required files:")
        for path in missing:
            print(path)
        return 2

    dtls13 = read("src/dtls13.c")
    tls13 = read("src/tls13.c")
    misc = read("wolfcrypt/src/misc.c")
    types = read("wolfssl/wolfcrypt/types.h")
    internal = read("wolfssl/internal.h")
    protocol_source = "\n".join([dtls13, tls13, internal])

    key_update_ack = block(
        dtls13,
        "static int Dtls13KeyUpdateAckReceived",
        "#ifdef WOLFSSL_DEBUG_TLS",
    )
    send_key_update = block(
        tls13,
        "int SendTls13KeyUpdate",
        "/* handle processing TLS v1.3 key_update",
    )
    do_key_update = block(
        tls13,
        "static int DoTls13KeyUpdate",
        "#ifdef WOLFSSL_EARLY_DATA",
    )
    response_region = block(
        do_key_update,
        "if (ssl->keys.keyUpdateRespond)",
        "WOLFSSL_LEAVE(\"DoTls13KeyUpdate\"",
    )

    limit_terms = [
        "2^48",
        "2**48",
        "281474976710655",
        "0x0000ffffffffffff",
        "0xffffffffffff",
        "1ULL << 48",
        "W64_MAX_48",
        "DTLS13_EPOCH_MAX",
        "MAX_EPOCH",
        "EPOCH_LIMIT",
    ]

    max48_hi, max48_lo = 0x0000ffff, 0xffffffff
    after_hi, after_lo = w64_increment(max48_hi, max48_lo)
    max64_hi, max64_lo = 0xffffffff, 0xffffffff
    wrap_hi, wrap_lo = w64_increment(max64_hi, max64_lo)

    ok = True
    ok &= check("w64wrapper is a 64-bit wrapper",
        "typedef struct w64wrapper" in types and
        ("word64 n;" in types or "word32 n[2];" in types))
    ok &= check("w64Increment wraps only after full 64-bit range",
        "void w64Increment" in misc and
        ("n->n[1]++" in misc or "n->n++" in misc))
    ok &= check("Incrementing 2^48-1 does not produce zero",
        (after_hi, after_lo) == (0x00010000, 0x00000000) and
        not is_zero(after_hi, after_lo))
    ok &= check("Incrementing 2^64-1 produces zero",
        (wrap_hi, wrap_lo) == (0, 0) and is_zero(wrap_hi, wrap_lo))
    ok &= check("DTLS KeyUpdate ACK advances sending epoch",
        "w64Increment(&ssl->dtls13Epoch)" in key_update_ack)
    ok &= check("DTLS sending epoch gate is only wrap-to-zero",
        "if (w64IsZero(ssl->dtls13Epoch))" in key_update_ack and
        "return BAD_STATE_E" in key_update_ack)
    ok &= check("No explicit 2^48-1 epoch limit appears in DTLS/TLS protocol source",
        not any(term in protocol_source for term in limit_terms))
    ok &= check("SendTls13KeyUpdate has no 2^48-1 pre-send gate",
        "Dtls13HandshakeSend" in send_key_update and
        not any(term in send_key_update for term in limit_terms))
    ok &= check("DoTls13KeyUpdate parses update_requested",
        "case update_requested:" in do_key_update and
        "ssl->keys.keyUpdateRespond = 1" in do_key_update)
    ok &= check("update_requested response path calls or schedules KeyUpdate",
        "return SendTls13KeyUpdate(ssl)" in response_region or
        "ssl->options.sendKeyUpdate = 1" in response_region or
        "ssl->dupWrite->keyUpdateRespond = 1" in response_region)
    ok &= check("update_requested response path lacks 2^48-1 gate",
        not any(term in response_region for term in limit_terms))
    ok &= check("DTLS concurrent KeyUpdate ACK gate exists",
        "ssl->options.dtls && ssl->dtls13WaitKeyUpdateAck" in do_key_update)

    if ok:
        print("RESULT: confirmed partial satisfaction: wolfSSL prevents 64-bit epoch wrap but lacks the RFC9147 sending epoch <= 2^48-1 gate and lacks that gate for update_requested responses")
        return 0

    print("RESULT: probe found unexpected implementation differences")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
