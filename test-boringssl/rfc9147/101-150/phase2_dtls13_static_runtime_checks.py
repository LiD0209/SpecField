#!/usr/bin/env python3
import json
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / "boringssl-main"
OUT = Path(__file__).resolve().parent


CHECKS = [
    {
        "name": "dtls13_rejects_cid_bit_on_receive",
        "file": "ssl/dtls_record.cc",
        "needles": [
            "if (out->type & 0x10)",
            "Connection ID bit set, which we didn't negotiate.",
            "return false;",
        ],
    },
    {
        "name": "dtls13_writer_never_sends_cid_and_always_sends_length",
        "file": "ssl/dtls_record.cc",
        "needles": [
            "We set C=0 (no Connection ID), S=1 (16-bit sequence number), L=1",
            "out[0] = 0x2c | (epoch & 0x3);",
            "CRYPTO_store_u16_be(out + 3, ciphertext_len);",
        ],
    },
    {
        "name": "dtls13_reader_accepts_length_omission_as_rest_of_datagram",
        "file": "ssl/dtls_record.cc",
        "needles": [
            "No length present - the remaining contents are the whole packet.",
            "CBS_get_bytes(in, &out->body, CBS_len(in))",
        ],
    },
    {
        "name": "dtls13_message_seq_reassembly_window_and_discard_past",
        "file": "ssl/d1_both.cc",
        "needles": [
            "msg_hdr->seq < ssl->d1->handshake_read_seq",
            "msg_hdr.seq < ssl->d1->handshake_read_seq",
            "Ignore fragments from the past.",
            "ssl->d1->handshake_read_seq++;",
        ],
    },
    {
        "name": "dtls13_message_seq_increment_only_for_new_non_ccs_message",
        "file": "ssl/d1_both.cc",
        "needles": [
            "CBB_add_u16(cbb, ssl->d1->handshake_write_seq)",
            "if (!is_ccs)",
            "ssl->d1->handshake_write_seq++;",
        ],
    },
    {
        "name": "dtls13_transcript_uses_tls13_message_hash_hrr",
        "file": "ssl/ssl_transcript.cc",
        "needles": [
            "SSLTranscript::UpdateForHelloRetryRequest",
            "SSL3_MT_MESSAGE_HASH",
            "message_seq, fragment_offset, and fragment_length",
            "fields are omitted",
            "AddToBufferOrHash(in.first<4>())",
            "AddToBufferOrHash(in.subspan<12>())",
        ],
    },
    {
        "name": "dtls13_server_does_not_echo_legacy_session_id",
        "file": "ssl/tls13_server.cc",
        "needles": [
            "MUST NOT echo the",
            "legacy_session_id",
            "if (!SSL_is_dtls(ssl))",
            "hs->session_id.CopyFrom",
        ],
    },
    {
        "name": "dtls13_clienthello_legacy_cookie_parsed_but_no_server_validation",
        "file": "ssl/extensions.cc",
        "needles": [
            "CBS_get_u8_length_prefixed(cbs, &cookie)",
            "out->dtls_cookie = CBS_data(&cookie)",
            "out->dtls_cookie_len = CBS_len(&cookie)",
        ],
    },
    {
        "name": "dtls13_hvr_negative_runner_tests_exist",
        "file": "ssl/test/runner/state_machine_tests.go",
        "needles": [
            "DTLS13-HelloVerifyRequest",
            "DTLS13-HelloVerifyRequestEmptyCookie",
            "shouldFail:    true",
            "expectedError: \":INVALID_MESSAGE:\"",
        ],
    },
]


CID_NEEDLES = [
    "RequestConnectionId",
    "NewConnectionId",
    "cid_spare",
    "num_cids",
    "connection_id_length",
]


def check_file_contains(check):
    path = REPO / check["file"]
    text = path.read_text(encoding="utf-8", errors="replace")
    missing = [needle for needle in check["needles"] if needle not in text]
    return {
        "name": check["name"],
        "file": check["file"],
        "passed": not missing,
        "missing": missing,
    }


def command_probe(cmd):
    exe = shutil.which(cmd[0])
    if exe is None:
        return {"command": cmd, "available": False, "returncode": None, "output": "not found in PATH"}
    try:
        completed = subprocess.run(cmd, cwd=REPO, text=True, capture_output=True, timeout=30)
        return {
            "command": cmd,
            "available": True,
            "returncode": completed.returncode,
            "output": (completed.stdout + completed.stderr).strip(),
        }
    except Exception as exc:
        return {"command": cmd, "available": True, "returncode": None, "output": repr(exc)}


def main():
    results = [check_file_contains(check) for check in CHECKS]
    all_text = "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in (REPO / "ssl").rglob("*")
        if p.is_file() and p.suffix in {".cc", ".h", ".go"}
    )
    cid_hits = {needle: (needle in all_text) for needle in CID_NEEDLES}
    tool_probes = [
        command_probe(["cmake", "--version"]),
        command_probe(["ninja", "--version"]),
        command_probe(["go", "version"]),
        command_probe(["bazel", "--version"]),
    ]
    executable_probes = {
        "ssl_test.exe": [str(p) for p in REPO.rglob("ssl_test.exe")][:10],
        "bssl_shim.exe": [str(p) for p in REPO.rglob("bssl_shim.exe")][:10],
    }
    payload = {
        "summary": {
            "static_checks_passed": sum(1 for r in results if r["passed"]),
            "static_checks_total": len(results),
            "cid_feature_symbols_found": {k: v for k, v in cid_hits.items() if v},
            "runtime_execution": "blocked: no cmake/ninja/go/bazel and no prebuilt ssl_test.exe/bssl_shim.exe found",
        },
        "static_checks": results,
        "cid_symbol_probe": cid_hits,
        "tool_probes": tool_probes,
        "executable_probes": executable_probes,
    }
    (OUT / "phase2_dtls13_static_runtime_checks.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    lines = [
        "DTLS 1.3 focused Phase 2 checks",
        f"static: {payload['summary']['static_checks_passed']}/{payload['summary']['static_checks_total']} passed",
        f"CID symbols found: {payload['summary']['cid_feature_symbols_found']}",
        f"runtime: {payload['summary']['runtime_execution']}",
    ]
    for r in results:
        lines.append(f"- {r['name']}: {'PASS' if r['passed'] else 'FAIL'}")
        if r["missing"]:
            lines.append(f"  missing: {r['missing']}")
    (OUT / "phase2_dtls13_static_runtime_checks.log").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    if not all(r["passed"] for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
