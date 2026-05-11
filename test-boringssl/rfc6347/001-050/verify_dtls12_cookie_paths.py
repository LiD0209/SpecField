import json
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
TARGET = ROOT / "boringssl-main"
OUT = ROOT / "test-boringssl" / "rfc6347" / "001-050"


def read(rel):
    return (TARGET / rel).read_text(encoding="utf-8", errors="replace")


def contains(rel, needle):
    return needle in read(rel)


def rg_like(paths, needles):
    hits = []
    for rel in paths:
        text = read(rel)
        for n in needles:
            if n in text:
                hits.append({"file": rel, "needle": n})
    return hits


def main():
    checks = []

    hc = read("ssl/handshake_client.cc")
    checks.append({
        "name": "client parses HelloVerifyRequest and copies cookie",
        "passed": all(s in hc for s in [
            "msg.type == DTLS1_MT_HELLO_VERIFY_REQUEST",
            "CBS_get_u8_length_prefixed(&hello_verify_request, &cookie)",
            "hs->dtls_cookie.CopyFrom(cookie)",
            "hs->transcript.Init()",
            "return ssl_add_client_hello(hs)",
        ]),
    })

    ext = read("ssl/extensions.cc")
    checks.append({
        "name": "ClientHello parser enforces DTLS cookie/cipher/compression vector ranges",
        "passed": all(s in ext for s in [
            "CBS_get_u8_length_prefixed(cbs, &cookie)",
            "CBS_get_u16_length_prefixed(cbs, &cipher_suites)",
            "CBS_len(&cipher_suites) < 2",
            "CBS_get_u8_length_prefixed(cbs, &compression_methods)",
            "CBS_len(&compression_methods) < 1",
        ]),
    })

    runner_msg = read("ssl/test/runner/handshake_messages.go")
    checks.append({
        "name": "runner still rejects HelloVerifyRequest cookies above 32 bytes",
        "passed": "cookieLen > 32" in runner_msg and "len(data) != 7+cookieLen" in runner_msg,
    })

    product_paths = [
        "ssl/handshake_server.cc",
        "ssl/handshake.cc",
        "ssl/extensions.cc",
        "ssl/d1_both.cc",
        "ssl/d1_pkt.cc",
        "ssl/dtls_record.cc",
        "include/openssl/ssl.h",
    ]
    product_hits = rg_like(product_paths, [
        "DTLSv1_listen",
        "SSL_CTX_set_cookie",
        "generate_cookie",
        "verify_cookie",
        "HelloVerifyRequest",
        "DTLS1_MT_HELLO_VERIFY_REQUEST",
    ])
    only_client_hvr = [h for h in product_hits if h["file"] != "ssl/handshake_client.cc"]
    checks.append({
        "name": "no production server HelloVerifyRequest cookie API/generation/verification path found",
        "passed": not any(h["needle"] in {"DTLSv1_listen", "SSL_CTX_set_cookie", "generate_cookie", "verify_cookie", "DTLS1_MT_HELLO_VERIFY_REQUEST"} for h in product_hits),
        "hits": product_hits,
        "note": "handshake_client.cc intentionally excluded; this check is about product server-side paths.",
    })

    dtls_method = read("ssl/dtls_method.cc")
    dtls_record = read("ssl/dtls_record.cc")
    checks.append({
        "name": "DTLS 1.2 read epoch is replaced instead of retained",
        "passed": "ssl->d1->read_epoch = std::move(new_epoch);" in dtls_method
        and "ssl->d1->next_read_epoch = MakeUnique<DTLSReadEpoch>" in dtls_method
        and "In DTLS 1.2, we only need to consider one" in dtls_record,
    })

    d1 = read("ssl/d1_both.cc")
    checks.append({
        "name": "handshake fragmentation and transcript header paths present",
        "passed": all(s in d1 for s in [
            "CBB_add_u16(cbb, ssl->d1->handshake_write_seq)",
            "ssl->s3->hs->transcript.Update(data)",
            "CBB_add_u24(&cbb, range.start)",
            "dtls_seal_record",
        ]),
    })

    passed = all(c["passed"] for c in checks)
    result = {
        "passed": passed,
        "checks": checks,
        "runtime_note": "No prebuilt boringssl-main build, ssl_test.exe, or bssl.exe was present under the target tree. This verification is an executable source-level focused test over the audited files.",
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "verify_dtls12_cookie_paths.log").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
