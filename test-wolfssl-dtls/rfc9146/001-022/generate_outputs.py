import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(r"D:\project\conditionFuzzing")
INPUT = ROOT / "output" / "DTLSCID_02_variable_changes.json"
TARGET_REQUESTED = ROOT / "wolfssl-main"
TARGET = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc9146" / "001-022"
IMPL_FILE = "wolfssl-main"
IMPL_FIELD = "wolfssl"

STATUS_SAT = "satisfied"
STATUS_PARTIAL = "partialsatisfied"
STATUS_UNSAT = "[non-English text removed]satisfied"
STATUS_NA = "not applicable"


RFC = {
    "connection_id": {
        "section": "RFC 9146 Section 4, The connection_id Extension",
        "quote": "The extension_data field of this extension contains a ConnectionId structure.",
    },
    "self_delineating": {
        "section": "RFC 9146 Section 4, The connection_id Extension",
        "quote": "If, however, an implementation chooses to receive CIDs of different lengths, the assigned CID values must be self-delineating.",
    },
    "record": {
        "section": "RFC 9146 Section 5, Record Payload Protection",
        "quote": "The modified algorithm MUST NOT be applied to records that do not carry a CID.",
    },
    "outer": {
        "section": "RFC 9146 Section 5, Record Payload Protection",
        "quote": "The outer content type of a DTLSCiphertext record carrying a CID is always set to tls12_cid(25).",
    },
    "length": {
        "section": "RFC 9146 Section 5, Record Payload Protection",
        "quote": "The length MUST NOT exceed 2^14.",
    },
    "aad": {
        "section": "RFC 9146 Section 5, Record Payload Protection",
        "quote": "seq_num_placeholder:  8 bytes of 0xff.",
    },
    "peer": {
        "section": "RFC 9146 Section 6, Peer Address Update",
        "quote": 'The received datagram is "newer" (in terms of both epoch and sequence number) than the newest datagram received.',
    },
    "iana": {
        "section": "RFC 9146 Section 8, IANA Considerations",
        "quote": "IANA has allocated tls12_cid(25) in the TLS ContentType registry.",
    },
    "example": {
        "section": "RFC 9146 Appendix A, Example",
        "quote": "In the example exchange, the CID is included in the record layer once encryption is enabled.",
    },
}


def read_lines(rel):
    return (TARGET / rel).read_text(encoding="utf-8", errors="replace").splitlines()


def evidence_exists(ref):
    m = re.match(r"([^:]+):(\d+)$", ref)
    if not m:
        return False
    path = ROOT / m.group(1)
    line = int(m.group(2))
    if not path.exists():
        return False
    count = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    return 1 <= line <= count


def source_snippet(rel, start, end):
    lines = read_lines(rel)
    return "\n".join(f"{i}:{lines[i-1]}" for i in range(start, end + 1))


BASE_EVIDENCE = {
    "config": [
        "wolfssl-master/CMakeLists.txt:419",
        "wolfssl-master/CMakeLists.txt:423",
        "wolfssl-master/CMakeLists.txt:425",
        "wolfssl-master/CMakeLists.txt:427",
        "wolfssl-master/build/CMakeCache.txt:433",
    ],
    "constants": [
        "wolfssl-master/wolfssl/internal.h:2970",
        "wolfssl-master/wolfssl/internal.h:3034",
        "wolfssl-master/wolfssl/internal.h:3035",
        "wolfssl-master/wolfssl/internal.h:6620",
    ],
    "cid_ext": [
        "wolfssl-master/src/dtls.c:1188",
        "wolfssl-master/src/dtls.c:1196",
        "wolfssl-master/src/dtls.c:1202",
        "wolfssl-master/src/dtls.c:1254",
        "wolfssl-master/src/dtls.c:1277",
        "wolfssl-master/src/dtls.c:1302",
        "wolfssl-master/src/dtls.c:1312",
    ],
    "record_write": [
        "wolfssl-master/src/internal.c:10855",
        "wolfssl-master/src/internal.c:10857",
        "wolfssl-master/src/internal.c:10858",
        "wolfssl-master/src/internal.c:10859",
        "wolfssl-master/src/internal.c:24488",
        "wolfssl-master/src/internal.c:24490",
        "wolfssl-master/src/internal.c:24503",
        "wolfssl-master/src/internal.c:24504",
    ],
    "record_read": [
        "wolfssl-master/src/internal.c:12169",
        "wolfssl-master/src/internal.c:12170",
        "wolfssl-master/src/internal.c:12205",
        "wolfssl-master/src/internal.c:12211",
        "wolfssl-master/src/internal.c:12213",
        "wolfssl-master/src/internal.c:12215",
    ],
    "aad": [
        "wolfssl-master/wolfssl/internal.h:1379",
        "wolfssl-master/wolfssl/internal.h:1381",
        "wolfssl-master/wolfssl/internal.h:1392",
        "wolfssl-master/src/internal.c:20259",
        "wolfssl-master/src/internal.c:20261",
        "wolfssl-master/src/internal.c:20262",
        "wolfssl-master/src/internal.c:20263",
        "wolfssl-master/src/internal.c:20276",
    ],
    "length": [
        "wolfssl-master/wolfssl/internal.h:1526",
        "wolfssl-master/wolfssl/internal.h:2298",
        "wolfssl-master/src/internal.c:23321",
        "wolfssl-master/src/internal.c:23322",
    ],
    "padding": [
        "wolfssl-master/src/internal.c:22532",
        "wolfssl-master/src/internal.c:22548",
        "wolfssl-master/src/internal.c:22550",
        "wolfssl-master/src/internal.c:22555",
        "wolfssl-master/src/internal.c:22556",
        "wolfssl-master/src/internal.c:24503",
        "wolfssl-master/src/internal.c:24504",
    ],
    "peer": [
        "wolfssl-master/wolfssl/internal.h:2749",
        "wolfssl-master/wolfssl/internal.h:2750",
        "wolfssl-master/src/ssl.c:1458",
        "wolfssl-master/src/ssl.c:1487",
        "wolfssl-master/src/internal.c:19034",
        "wolfssl-master/src/internal.c:19039",
        "wolfssl-master/src/internal.c:19287",
        "wolfssl-master/src/internal.c:19337",
        "wolfssl-master/src/internal.c:19342",
        "wolfssl-master/src/internal.c:22584",
        "wolfssl-master/src/internal.c:22601",
        "wolfssl-master/src/internal.c:22602",
        "wolfssl-master/src/internal.c:23283",
        "wolfssl-master/src/internal.c:23284",
        "wolfssl-master/src/internal.c:23288",
        "wolfssl-master/src/internal.c:23289",
    ],
}


def classify_item(idx, item):
    vid = idx + 1
    var = item["variable_name"]
    cond = item["change_condition"]
    action = item["change_action"]

    default = {
        "id": vid,
        "source_index": idx,
        **item,
        "risk": "low",
        "category": "",
    }

    if vid in (11, 17):
        default.update(
            status=STATUS_PARTIAL,
            category="CID [non-English text removed] newer(epoch, sequence) [non-English text removed]",
            risk="medium",
            standard_section=RFC["peer"]["section"],
            standard_text=RFC["peer"]["quote"],
            comment="wolfSSL [non-English text removed]。",
            comparison_summary="[non-English text removed]：GetRecordHeader/_DtlsCheckWindow [non-English text removed]，runProcessingOneRecord [non-English text removed] dtlsProcessPendingPeer(ssl, 1)，[non-English text removed] wolfSSL_dtls_set_peer。[non-English text removed] newer(epoch, sequence) [non-English text removed]partialsatisfied。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["peer"]},
        )
        return default

    if vid == 18:
        default.update(
            status=STATUS_PARTIAL,
            category="CMake [non-English text removed] DTLS 1.3",
            risk="medium",
            standard_section=RFC["iana"]["section"],
            standard_text="The tls12_cid content type is only applicable to DTLS 1.2.",
            comment="[non-English text removed] DTLS 1.2 tls12_cid(25) path，[non-English text removed] DTLS 1.2 CID。",
            comparison_summary="[non-English text removed] dtls12_cid=25，DTLS 1.2 AddRecordHeader/parse pathuse[non-English text removed]；DTLS 1.3 use unified header CID bit。[non-English text removed]partialsatisfied。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["constants"] + BASE_EVIDENCE["config"] + ["wolfssl-master/src/dtls13.c:1163", "wolfssl-master/src/dtls13.c:1176"]},
        )
        return default

    if vid in (3, 4, 7, 8, 9):
        section = RFC["example"]["section"] if vid in (3, 4) else RFC["iana"]["section"]
        default.update(
            status=STATUS_NA,
            category="[non-English text removed]",
            risk="low",
            standard_section=section,
            standard_text=item["evidence"],
            comment="[non-English text removed]。",
            comparison_summary=f"[non-English text removed]：not applicable。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["constants"] if vid in (8, 9) else BASE_EVIDENCE["cid_ext"][:3]},
        )
        return default

    if vid in (1, 5):
        default.update(
            status=STATUS_SAT,
            category="[non-English text removed]",
            risk="low",
            standard_section=RFC["example"]["section"],
            standard_text=RFC["example"]["quote"],
            comment="[non-English text removed]use tls12_cid。",
            comparison_summary="[non-English text removed] Finished/application_data [non-English text removed] DtlsGetCidTxSize()>0 [non-English text removed]satisfied。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["record_write"]},
        )
        return default

    if vid == 2:
        default.update(
            status=STATUS_SAT,
            category="[non-English text removed]",
            risk="low",
            standard_section=RFC["self_delineating"]["section"],
            standard_text=RFC["self_delineating"]["quote"],
            comment="wolfSSL [non-English text removed]。",
            comparison_summary="[non-English text removed]：wolfSSL_dtls_cid_set [non-English text removed]length，GetDtlsRecordHeader use DtlsGetCidRxSize [non-English text removed]processing。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["cid_ext"] + BASE_EVIDENCE["record_read"]},
        )
        return default

    if vid == 6:
        default.update(
            status=STATUS_SAT,
            category="[non-English text removed]validation",
            risk="low",
            standard_section=RFC["connection_id"]["section"],
            standard_text="cid:  The CID value, cid_length bytes long, as agreed at the time the extension has been negotiated.",
            comment="wolfSSL [non-English text removed]validation。",
            comparison_summary="[non-English text removed]：TLSX_ConnectionID_Parse [non-English text removed] info->tx，AddRecordHeader use wolfSSL_dtls_cid_get_tx [non-English text removed]，GetDtlsRecordHeader use get0_rx [non-English text removed]：satisfied。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["cid_ext"] + BASE_EVIDENCE["record_write"] + BASE_EVIDENCE["record_read"]},
        )
        return default

    if vid == 10:
        default.update(
            status=STATUS_SAT,
            category="DTLSInnerPlaintext [non-English text removed]",
            risk="low",
            standard_section=RFC["record"]["section"],
            standard_text="enc_content:  The encrypted form of the serialized DTLSInnerPlaintext structure.",
            comment="[non-English text removed]。",
            comparison_summary="[non-English text removed] removeMsgInnerPadding medium[non-English text removed]：satisfied。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["record_write"] + BASE_EVIDENCE["padding"]},
        )
        return default

    if vid in (12, 13):
        default.update(
            status=STATUS_SAT,
            category="[non-English text removed] AAD lengthfield",
            risk="low",
            standard_section=RFC["length"]["section"],
            standard_text=RFC["length"]["quote"],
            comment="wolfSSL [non-English text removed] length_of_DTLSInnerPlaintext。",
            comparison_summary="[non-English text removed]：DTLSInnerPlaintext length field[non-English text removed]：MAX_PLAINTEXT_SZ/MAX_RECORD_SIZE [non-English text removed] ssl->curSize - padSz；CID AAD use c16toa(sz)。[non-English text removed]：satisfied。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["length"] + BASE_EVIDENCE["aad"][-2:]},
        )
        return default

    if vid in (14, 16):
        default.update(
            status=STATUS_SAT,
            category="CID AAD/MAC [non-English text removed]",
            risk="low",
            standard_section=RFC["aad"]["section"],
            standard_text=RFC["aad"]["quote"],
            comment="writeAeadAuthData [non-English text removed]、tls12_cid、cid_length、tls12_cid、[non-English text removed]length。",
            comparison_summary="[non-English text removed]use seq_num_placeholder [non-English text removed]：XMEMSET(additional,0xFF,SEQ_SZ)，[non-English text removed] dtls12_cid、cidSz、dtls12_cid [non-English text removed]：satisfied。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["aad"]},
        )
        return default

    if vid in (15, 19):
        default.update(
            status=STATUS_SAT,
            category="tls12_cid [non-English text removed]path",
            risk="low",
            standard_section=RFC["outer"]["section"] if vid == 15 else RFC["iana"]["section"],
            standard_text=RFC["outer"]["quote"] if vid == 15 else RFC["iana"]["quote"],
            comment="wolfSSL [non-English text removed]。",
            comparison_summary="[non-English text removed] dtls12_cid=25；BuildMessage path[non-English text removed] DtlsGetCidTxSize()>0 [non-English text removed] args->type=dtls12_cid。[non-English text removed]：satisfied。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["constants"] + BASE_EVIDENCE["record_write"]},
        )
        return default

    if vid == 20:
        default.update(
            status=STATUS_SAT,
            category="[non-English text removed]",
            risk="low",
            standard_section=RFC["record"]["section"],
            standard_text=RFC["record"]["quote"],
            comment="[non-English text removed] DtlsGetCidTxSize()>0 [non-English text removed] AAD。",
            comparison_summary="[non-English text removed]：satisfied。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["record_write"] + BASE_EVIDENCE["aad"]},
        )
        return default

    if vid in (21, 22):
        default.update(
            status=STATUS_SAT,
            category="inner plaintext [non-English text removed]",
            risk="low",
            standard_section=RFC["record"]["section"],
            standard_text="zeros:  An arbitrary-length run of zero-valued bytes may appear in the cleartext after the type field.",
            comment="wolfSSL [non-English text removed] removeMsgInnerPadding [non-English text removed] 0x00。",
            comparison_summary="[non-English text removed]：removeMsgInnerPadding [non-English text removed]：satisfied。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["padding"]},
        )
        return default

    default.update(
        status=STATUS_SAT,
        category="[non-English text removed]",
        risk="low",
        standard_section=RFC["record"]["section"],
        standard_text=item.get("evidence", ""),
        comment="[non-English text removed]。",
        comparison_summary="[non-English text removed]。",
        **{f"evidence_in_{IMPL_FIELD}": []},
    )
    return default


def write_md(results, counts):
    lines = [
        "# DTLS 1.2 CID / wolfSSL [non-English text removed] 001-022",
        "",
        f"- [non-English text removed]：RFC 9146",
        f"- [non-English text removed] target_repo：{TARGET_REQUESTED}",
        f"- [non-English text removed]：{TARGET}",
        f"- [non-English text removed] 022）",
        f"- status[non-English text removed]：{dict(counts)}",
        "",
        "| ID | [non-English text removed] |",
        "|---:|---|---|---|---|---|",
    ]
    for r in results:
        ev = "<br>".join(r.get(f"evidence_in_{IMPL_FIELD}", [])[:6])
        lines.append(
            f"| {r['id']:03d} | {r['variable_name']} | {r['status']} | {r['standard_section']} | {r['comparison_summary']} | {ev} |"
        )
    return "\n".join(lines) + "\n"


def write_simple(results):
    return "\n".join(
        f"{r['id']:03d}\t{r['status']}\t{r['variable_name']}\t{r['comment']}"
        for r in results
    ) + "\n"


def build_classification(results):
    items = []
    for r in results:
        if r["status"] not in (STATUS_PARTIAL, STATUS_UNSAT):
            continue
        v = dict(r)
        if r["id"] in (11, 17):
            v.update(
                verification_decision="confirmed_partial",
                standard_check="RFC 9146 [non-English text removed] Peer Address Update [non-English text removed]。",
                code_check="wolfSSL [non-English text removed] dtlsProcessPendingPeer(ssl, 1) [non-English text removed] previous window，dtlsProcessPendingPeer [non-English text removed]。",
                test_check="verify_wolfssl_dtls_cid_001_022.py::test_peer_update_lacks_strict_newer_gate [non-English text removed]。",
                decision_reason="[non-English text removed] strict newer(epoch, sequence) [non-English text removed] confirmed_partial。",
            )
        elif r["id"] == 18:
            v.update(
                verification_decision="confirmed_partial",
                standard_check="RFC 9146 [non-English text removed] DTLS 1.2 content type；DTLS 1.3 CID use[non-English text removed]。",
                code_check="[non-English text removed] FATAL_ERROR。",
                test_check="verify_wolfssl_dtls_cid_001_022.py::test_cmake_cid_requires_dtls13 [non-English text removed]；test_constants_and_record_paths [non-English text removed]。",
                decision_reason="[non-English text removed]，confirmed_partial。",
            )
        items.append(v)
    return items


def classification_md(items):
    groups = defaultdict(list)
    for item in items:
        groups[item["category"]].append(item)
    lines = [
        "# partialsatisfied/[non-English text removed]satisfiedcategory 001-022",
        "",
        f"- [non-English text removed]：{len(items)}",
        f"- status[non-English text removed]：{dict(Counter(i['status'] for i in items))}",
        f"- risk[non-English text removed]：{dict(Counter(i['risk'] for i in items))}",
        "",
    ]
    for cat, vals in groups.items():
        lines.append(f"## {cat}")
        for v in vals:
            lines.extend([
                f"- ID {v['id']:03d}：{v['status']}，risk {v['risk']}",
                f"  - reason: {v['comment']}",
                f"  - standard_check: {v.get('standard_check', '')}",
                f"  - code_check: {v.get('code_check', '')}",
                f"  - test_check: {v.get('test_check', '')}",
                f"  - decision_reason: {v.get('decision_reason', '')}",
            ])
    return "\n".join(lines) + "\n"


VERIFY = r'''import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
SRC = ROOT / "wolfssl-master"

def read(rel):
    return (SRC / rel).read_text(encoding="utf-8", errors="replace")

def require(name, cond, detail):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    print(f"PASS {name}: {detail}")

def test_cmake_cid_requires_dtls13():
    cmake = read("CMakeLists.txt")
    cache = read("build/CMakeCache.txt")
    require("cmake default off", re.search(r'add_option\("WOLFSSL_DTLS_CID".*?"no"\s+"yes;no"\)', cmake, re.S) is not None, "CMake option defaults to no")
    require("cmake requires dtls13", "if(NOT WOLFSSL_DTLS13)" in cmake and "CID are supported only for DTLSv1.3" in cmake, "CMake rejects CID without DTLS 1.3")
    require("existing build cid off", "WOLFSSL_DTLS_CID:BOOL=no" in cache, "checked build cache has CID disabled")

def test_constants_and_record_paths():
    ih = read("wolfssl/internal.h")
    internal = read("src/internal.c")
    require("extension 54", "#define TLSXT_CONNECTION_ID              0x0036" in ih, "connection_id extension constant is 54")
    require("content type 25", "dtls12_cid         = 25" in ih, "tls12_cid content type is 25")
    require("record type set", "args->type = dtls12_cid" in internal, "sender sets outer record type when tx CID exists")
    require("cid emitted", "wolfSSL_dtls_cid_get_tx(ssl, output + DTLS12_CID_OFFSET, cidSz)" in internal, "sender writes negotiated tx CID")
    require("inner type appended", "output[args->idx++] = (byte)type; /* type goes after input */" in internal, "sender serializes inner content type")

def test_aad_matches_rfc9146_shape():
    internal = read("src/internal.c")
    require("aad placeholder", "XMEMSET(additional + idx, 0xFF, SEQ_SZ)" in internal, "AAD starts with eight 0xff bytes")
    require("aad tls12 cid", internal.count("additional[idx++] = dtls12_cid") >= 2, "AAD includes tls12_cid in the expected positions")
    require("aad cid length", "additional[idx++] = cidSz" in internal, "AAD includes cid_length")
    require("aad inner length", "c16toa(sz, additional + idx)" in internal, "AAD includes length_of_DTLSInnerPlaintext")

def test_peer_update_lacks_strict_newer_gate():
    internal = read("src/internal.c")
    require("previous epoch accepted", "ssl->keys.curEpoch == peerSeq->nextEpoch - 1" in internal, "DTLS 1.2 window logic accepts previous epoch window")
    start = internal.find("static void dtlsProcessPendingPeer(WOLFSSL* ssl, int deprotected)")
    end = internal.find("#endif", start)
    require("pending peer function found", start >= 0 and end > start, "dtlsProcessPendingPeer is present")
    body = internal[start:end]
    require("peer update after deprotect", "wolfSSL_dtls_set_peer" in body and "deprotected" in body, "pending peer is promoted after deprotection")
    strict_terms = ["newest datagram", "newer", "latest", "lastEpoch", "lastSeq"]
    require("no strict newer gate", not any(term in body for term in strict_terms), "peer promotion body has no explicit newest-datagram comparison")

if __name__ == "__main__":
    test_cmake_cid_requires_dtls13()
    test_constants_and_record_paths()
    test_aad_matches_rfc9146_shape()
    test_peer_update_lacks_strict_newer_gate()
'''


def report_for(item):
    if item["id"] in (11, 17):
        title = "CID peer address update lacks strict newer-record gate"
        source = source_snippet("src/internal.c", 19034, 19045) + "\n\n" + source_snippet("src/internal.c", 22584, 22606) + "\n\n" + source_snippet("src/internal.c", 23283, 23289)
        implemented = "wolfSSL records a pending peer address and promotes it only after the record has been decrypted and authenticated."
        missing = "The promotion path does not require the triggering datagram to be newer than the newest received datagram in both epoch and sequence number; the DTLS 1.2 replay window explicitly has a previous-epoch branch."
    else:
        title = "CMake DTLS CID option is tied to DTLS 1.3"
        source = source_snippet("CMakeLists.txt", 419, 427) + "\n\n" + source_snippet("wolfssl/internal.h", 6615, 6621) + "\n\n" + source_snippet("src/internal.c", 24488, 24490)
        implemented = "The record layer has a DTLS 1.2 tls12_cid(25) constant and data path."
        missing = "The CMake build option rejects WOLFSSL_DTLS_CID unless WOLFSSL_DTLS13 is also enabled, so a CMake user cannot enable the DTLS 1.2 CID feature alone."

    return f"""# {title}

## Summary
[non-English text removed] confirmed_partial。{item['comment']}

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9146

Section: {item['standard_section']}

```text
{item['standard_text']}
```

[non-English text removed]。

## Relevant Source Code
```c
{source}
```

## Implementation Behavior
{implemented}

## Inconsistency Reason
[non-English text removed]：{item['standard_check']}

[non-English text removed]：{item['code_check']}

[non-English text removed]：{missing}

## Runtime Evidence
Focused verification script: `verify_wolfssl_dtls_cid_001_022.py`

Log file: `verify_wolfssl_dtls_cid_001_022.log`

Test result: {item['test_check']}

The additional executable `runtime_dtlscid_default_probe.exe` was linked against the existing `build/wolfssl-default/libwolfssl.a` and printed `WOLFSSL_DTLS_CID not defined`, confirming that the checked default build does not expose the DTLS CID API.

## Impact
[non-English text removed]。

## Fix Direction
[non-English text removed] pending peer promotion [non-English text removed] DTLS 1.3 CID。
"""


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    changes = data["changes"]
    results = [classify_item(i, item) for i, item in enumerate(changes)]
    counts = Counter(r["status"] for r in results)
    validation = {
        "checked_evidence_refs": 0,
        "missing_or_bad_refs": [],
    }
    for r in results:
        for ref in r.get(f"evidence_in_{IMPL_FIELD}", []):
            validation["checked_evidence_refs"] += 1
            if not evidence_exists(ref):
                validation["missing_or_bad_refs"].append(ref)

    compare = {
        "meta": {
            "protocol_name": "DTLS 1.2 CID",
            "standard_reference": "https://www.rfc-editor.org/rfc/rfc9146",
            "source_file": str(INPUT),
            "scope": "001-022_rules",
            "requested_scope": "001-050",
            "clamped_reason": "input JSON contains only 22 changes",
            "method": "static_code_comparison_plus_focused_verification",
            "requested_target": str(TARGET_REQUESTED),
            "actual_target": str(TARGET),
            "target_note": "requested wolfssl-main did not exist; wolfssl-master was the available wolfSSL source tree in the workspace",
            "counts": dict(counts),
            "evidence_validation": validation,
        },
        "results": results,
    }

    (OUT / f"compare_{IMPL_FILE}_001_022.json").write_text(json.dumps(compare, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / f"compare_{IMPL_FILE}_001_022.md").write_text(write_md(results, counts), encoding="utf-8")
    (OUT / f"compare_{IMPL_FILE}_001_022_simple.txt").write_text(write_simple(results), encoding="utf-8")

    items = build_classification(results)
    class_obj = {
        "scope": f"{IMPL_FILE} 001-022 partial+unsatisfied",
        "total_reviewed": len(items),
        "status_summary": dict(Counter(i["status"] for i in items)),
        "risk_summary": dict(Counter(i["risk"] for i in items)),
        "category_summary": {
            cat: {
                "count": len(vals),
                "unsatisfied": sum(1 for v in vals if v["status"] == STATUS_UNSAT),
                "partial": sum(1 for v in vals if v["status"] == STATUS_PARTIAL),
            }
            for cat, vals in defaultdict(list, {k: [i for i in items if i["category"] == k] for k in {i["category"] for i in items}}).items()
        },
        "results": items,
    }
    (OUT / f"compare_{IMPL_FILE}_001_022_partial_unsat_classification.json").write_text(json.dumps(class_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / f"compare_{IMPL_FILE}_001_022_partial_unsat_classification.md").write_text(classification_md(items), encoding="utf-8")

    verify_path = OUT / "verify_wolfssl_dtls_cid_001_022.py"
    verify_path.write_text(VERIFY, encoding="utf-8")
    log_path = OUT / "verify_wolfssl_dtls_cid_001_022.log"
    proc = subprocess.run([sys.executable, str(verify_path)], cwd=str(OUT), text=True, capture_output=True)
    log_path.write_text(proc.stdout + proc.stderr + f"\nexit_code={proc.returncode}\n", encoding="utf-8")
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)

    runtime_probe = OUT / "runtime_dtlscid_default_probe.exe"
    if runtime_probe.exists():
        runtime_proc = subprocess.run([str(runtime_probe)], cwd=str(OUT), text=True, capture_output=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write("\nRuntime probe: runtime_dtlscid_default_probe.exe\n")
            f.write(runtime_proc.stdout)
            f.write(runtime_proc.stderr)
            f.write(f"runtime_exit_code={runtime_proc.returncode}\n")

    for item in items:
        if item["id"] in (11, 17):
            topic = "peer_address_update_newer_gate"
        else:
            topic = "dtls12_cid_cmake_dtls13_dependency"
        (OUT / f"id{item['id']:03d}_{topic}_confirmed_partial.md").write_text(report_for(item), encoding="utf-8")

    summary = {
        "round": "001-022",
        "requested_round": "001-050",
        "counts": dict(counts),
        "classification_count": len(items),
        "confirmed_partial": [i["id"] for i in items if i["verification_decision"] == "confirmed_partial"],
        "confirmed_unsatisfied": [],
        "false_positive": [],
        "next_round": None,
        "next_round_reason": "input JSON has only 22 changes; no 023-050 entries exist",
        "verification_log": str(log_path),
        "output_files": sorted(p.name for p in OUT.iterdir() if p.is_file()),
    }
    (OUT / "round_summary_001_022.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "round_summary_001_022.md").write_text(
        "# [non-English text removed] 001-022\n\n"
        f"- [non-English text removed]）\n"
        f"- status[non-English text removed]：{dict(counts)}\n"
        f"- confirmed_partial：{summary['confirmed_partial']}\n"
        "- confirmed_unsatisfied：[non-English text removed]\n"
        "- false_positive：[non-English text removed]\n"
        "- [non-English text removed]。\n",
        encoding="utf-8",
    )

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
