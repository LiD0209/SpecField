import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
REPO = ROOT / "boringssl-main"
OUT_DIR = ROOT / "test-boringssl" / "rfc9146" / "001-022"
LOG_DIR = OUT_DIR / "logs"


def read_rel(path):
    return (REPO / path).read_text(encoding="utf-8")


def require(name, condition, details):
    return {
        "name": name,
        "passed": bool(condition),
        "details": details,
    }


def main():
    ssl_dir = REPO / "ssl"
    include_dir = REPO / "include"
    dtls = read_rel("ssl/dtls_record.cc")
    ext = read_rel("ssl/extensions.cc")
    internal = read_rel("ssl/internal.h")
    ssl_h = read_rel("include/openssl/ssl.h")

    ssl_include_text = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for base in (ssl_dir, include_dir)
        for p in base.rglob("*")
        if p.is_file() and p.suffix in {".cc", ".h", ".inc"}
    )

    extensions_table = ext[ext.index("static const struct tls_extension kExtensions[]"):
                           ext.index("#define kNumExtensions")]

    tests = [
        require(
            "connection_id_extension_codepoint_absent",
            "TLSEXT_TYPE_connection_id" not in ssl_include_text
            and "connection_id" not in extensions_table
            and "0x0036" not in extensions_table,
            "The supported extension table has no connection_id(54) entry and no connection_id handlers.",
        ),
        require(
            "tls12_cid_content_type_absent",
            "SSL3_RT_TLS12_CID" not in ssl_include_text
            and not re.search(r"\btls12_cid\b", ssl_include_text)
            and not re.search(r"\b25\b.*cid", ssl_include_text, re.IGNORECASE),
            "No public or internal TLS content-type constant/path for tls12_cid(25) was found.",
        ),
        require(
            "dtls12_parser_has_no_cid_field",
            "parse_dtls12_record" in dtls
            and "CBS_get_u64(in, &epoch_and_seq)" in dtls
            and "CBS_get_u16_length_prefixed(in, &out->body)" in dtls
            and "cid_length" not in dtls
            and "out->cid" not in dtls,
            "DTLS 1.2 records are parsed as type, version, epoch+sequence, length, body only.",
        ),
        require(
            "dtls13_cid_bit_rejected",
            "if (out->type & 0x10)" in dtls
            and "Connection ID bit set, which we didn't negotiate" in dtls
            and "return false;" in dtls,
            "The only CID-bit handling is a DTLS 1.3 rejection path.",
        ),
        require(
            "dtls_writer_never_sends_cid",
            "never send Connection\n  // ID" in dtls
            and re.search(r"out\[0\]\s*=\s*0x2c\s*\|\s*\(epoch\s*&\s*0x3\);", dtls)
            and "out[0] = type;" in dtls,
            "DTLS 1.3 writer sets C=0; DTLS 1.2 writer emits the caller record type directly.",
        ),
        require(
            "cid_aad_algorithm_absent",
            "seq_num_placeholder" not in ssl_include_text
            and "cid_length" not in ssl_include_text
            and "record.header" in dtls
            and "SealScatter(" in dtls
            and "Open(out, record.type, record.version" in dtls,
            "AEAD additional data uses the parsed record header, not the RFC 9146 CID AAD construction.",
        ),
        require(
            "dtls_inner_plaintext_only_dtls13",
            "DTLS 1.3 hides the record type inside the encrypted data" in dtls
            and "ssl_protocol_version(ssl) >= TLS1_3_VERSION" in dtls
            and "while (record.type == 0)" in dtls,
            "Inner content type and zero padding exist only on the DTLS 1.3 encrypted-record path.",
        ),
        require(
            "plaintext_limit_present_but_not_cid_specific",
            "SSL3_RT_MAX_PLAIN_LENGTH + (has_padding ? 1 : 0)" in dtls
            and "#define DTLS_PLAINTEXT_RECORD_HEADER_LENGTH 13" in internal
            and "connection_id" not in ssl_h,
            "BoringSSL enforces generic plaintext limits but has no RFC 9146 CID-specific plaintext length field.",
        ),
    ]

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    result = {
        "test_program": str(Path(__file__).relative_to(ROOT)),
        "target_repo": str(REPO),
        "passed": all(t["passed"] for t in tests),
        "tests": tests,
    }
    out_path = LOG_DIR / "verify_rfc9146_cid_support.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    for t in tests:
        print(f"{'PASS' if t['passed'] else 'FAIL'} {t['name']}: {t['details']}")
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
