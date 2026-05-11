#!/usr/bin/env python3
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / "boringssl-main"


def read(rel):
    return (REPO / rel).read_text(encoding="utf-8")


checks = []

dtls_record = read("ssl/dtls_record.cc")
d1_pkt = read("ssl/d1_pkt.cc")
d1_both = read("ssl/d1_both.cc")
ssl3 = read("include/openssl/ssl3.h")
tls13_client = read("ssl/tls13_client.cc")
extensions = read("ssl/extensions.cc")
runner_basic = read("ssl/test/runner/basic_tests.go")
ssl_tree = "\n".join(
    p.read_text(encoding="utf-8", errors="ignore")
    for p in (REPO / "ssl").rglob("*")
    if p.is_file() and p.suffix in {".cc", ".h", ".c", ".go"}
)
include_tree = "\n".join(
    p.read_text(encoding="utf-8", errors="ignore")
    for p in (REPO / "include" / "openssl").rglob("*")
    if p.is_file() and p.suffix in {".h"}
)


def add(name, passed, detail):
    checks.append({"name": name, "passed": bool(passed), "detail": detail})


add(
    "ack_content_type_constant_26",
    "#define SSL3_RT_ACK 26" in ssl3,
    "include/openssl/ssl3.h defines SSL3_RT_ACK as 26.",
)
add(
    "ack_parsed_only_dtls13",
    "ACKs are only allowed in DTLS 1.3" in d1_pkt
    and "ssl_protocol_version(ssl) < TLS1_3_VERSION" in d1_pkt,
    "ssl/d1_pkt.cc rejects ACK records after a non-DTLS-1.3 version is negotiated.",
)
add(
    "ack_marks_sent_record_ranges",
    "MarkRange" in d1_pkt and "sent_records" in d1_pkt and "IsFullyAcked" in d1_pkt,
    "ssl/d1_pkt.cc matches ACKed record numbers to sent records and marks covered message ranges.",
)
add(
    "partial_ack_no_immediate_retransmit",
    "Schedule a retransmit" in d1_pkt
    and "partial ACK suggests packet loss" in d1_pkt
    and "TODO" in d1_pkt,
    "ssl/d1_pkt.cc records partial ACK support as a TODO rather than immediately scheduling retransmission.",
)
add(
    "records_to_ack_only_processed_or_buffered",
    "records_to_ack.PushBack(record_number)" in d1_both
    and "skipped_fragments" in d1_both
    and "if (!skipped_fragments)" in d1_both,
    "ssl/d1_both.cc adds ACK candidates after successful fragment parsing and skips too-far-future fragments.",
)
add(
    "send_ack_sorts_and_fits",
    "std::sort(sorted.begin(), sorted.end())" in d1_both
    and "max_plaintext" in d1_both
    and "records_to_ack.size()" in d1_both,
    "ssl/d1_both.cc limits ACK contents to MTU-fit records and sorts them.",
)
add(
    "cid_not_negotiated_rejected",
    "Connection ID bit set, which we didn't negotiate" in dtls_record
    and "out->type & 0x10" in dtls_record,
    "ssl/dtls_record.cc rejects DTLS 1.3 records with the CID bit set.",
)
add(
    "no_cid_send_path",
    "We never send Connection" in dtls_record
    and "ID, we always send 16-bit sequence numbers" in dtls_record
    and "out[0] = 0x2c | (epoch & 0x3)" in dtls_record,
    "ssl/dtls_record.cc always writes C=0 in DTLS 1.3 record headers.",
)
add(
    "no_dtls_cid_extension_or_new_connection_id",
    not re.search(r"TLSEXT_TYPE_(connection_id|ConnectionId|cid)", ssl_tree)
    and "NewConnectionId" not in ssl_tree
    and "cid_immediate" not in ssl_tree
    and "TLS Connection ID" not in include_tree,
    "The ssl/include trees contain no DTLS CID extension, NewConnectionId, or cid_immediate implementation; record layer comments state CID is never sent.",
)
add(
    "cookie_hrr_copied_to_second_clienthello",
    "hs->cookie.CopyFrom(cookie_value)" in tls13_client
    and "ext_cookie_add_clienthello" in extensions
    and "CBB_add_bytes(&cookie, hs->cookie.data(), hs->cookie.size())" in extensions,
    "tls13_client.cc stores non-empty HRR cookie and extensions.cc emits it in the next ClientHello cookie extension.",
)
add(
    "dtls13_decrypted_content_type_tail_scan",
    "record.type = out->back()" in dtls_record
    and "while (record.type == 0)" in dtls_record,
    "ssl/dtls_record.cc scans the decrypted plaintext from the end by stripping zero padding and reading the content type byte.",
)
add(
    "dtls13_cid_bit_runner_test_exists",
    "DTLS13RecordHeader-CIDBit" in runner_basic
    and "expectMessageDropped: true" in runner_basic,
    "ssl/test/runner/basic_tests.go includes a DTLS 1.3 CID-bit record drop test.",
)

failed = [c for c in checks if not c["passed"]]
print(json.dumps({"checks": checks, "failed": failed}, ensure_ascii=False, indent=2))
raise SystemExit(1 if failed else 0)
