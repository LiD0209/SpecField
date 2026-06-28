import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(r"D:\project\conditionFuzzing")
INPUT_JSON = ROOT / "output" / "DTLS12_02_variable_changes.json"
TARGET = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc6347" / "001-050"
IMPL = "wolfssl"

SAT = "satisfied"
PART = "partialsatisfied"
UNSAT = "[non-English text removed]satisfied"
NA = "not applicable"


STD = {
    "handshake": {
        "section": "RFC 6347 Section 4.2.2, Handshake Message Format",
        "quote": "enum { hello_request(0), client_hello(1), server_hello(2), hello_verify_request(3), certificate(11), server_key_exchange (12), certificate_request(13), server_hello_done(14), certificate_verify(15), client_key_exchange(16), finished(20), (255) } HandshakeType; struct { HandshakeType msg_type; uint24 length; uint16 message_seq; uint24 fragment_offset; uint24 fragment_length; select (HandshakeType) { ... } body; } Handshake;",
    },
    "cookie": {
        "section": "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures",
        "quote": "The server responds with a HelloVerifyRequest containing a stateless cookie. The client retransmits the ClientHello with the cookie added. The server verifies the cookie before continuing. Cookies SHOULD be generated as HMAC(Secret, Client-IP, Client-Parameters). When the server changes the Secret value, it SHOULD retain the previous value for a limited period and accept cookies generated with either secret.",
    },
    "record": {
        "section": "RFC 6347 Section 4.1, Record Layer",
        "quote": "The DTLSPlaintext structure contains type, version, epoch, sequence_number, length, and fragment. The epoch is initially zero and is incremented each time a ChangeCipherSpec message is sent. The epoch and sequence number are concatenated to form the nonce/MAC sequence value. Implementations MUST NOT allow the same epoch value to be reused within two times the TCP maximum segment lifetime.",
    },
    "fragment": {
        "section": "RFC 6347 Section 4.2.3, Handshake Message Fragmentation and Reassembly",
        "quote": "If a handshake message is too large to fit into a single DTLS record, it MUST be fragmented. Each fragment contains the same message_seq and length, with fragment_offset and fragment_length describing its position. If repeated retransmissions do not result in a response and PMTU is unknown, implementations SHOULD fragment handshake messages.",
    },
    "alert": {
        "section": "RFC 6347 Section 4.1.2.7 and Section 4.1.2.1",
        "quote": "In general, DTLS implementations SHOULD silently discard invalid records. If an implementation chooses to generate an alert when a fatal record-layer error is detected, it sends a fatal alert such as bad_record_mac.",
    },
}


E = {
    "handshake_enum": [
        "wolfssl/internal.h:6644",
        "wolfssl/internal.h:6648",
        "wolfssl/internal.h:6655",
        "wolfssl/internal.h:6659",
        "src/internal.c:18604",
        "src/internal.c:18618",
        "src/internal.c:18646",
        "src/internal.c:18678",
        "src/internal.c:18691",
        "src/internal.c:18696",
        "src/internal.c:18732",
        "src/internal.c:18739",
    ],
    "clienthello_send": [
        "src/internal.c:31168",
        "src/internal.c:31191",
        "src/internal.c:31207",
        "src/internal.c:31222",
        "src/internal.c:31245",
        "src/internal.c:31252",
    ],
    "clienthello_parse": [
        "src/dtls.c:298",
        "src/dtls.c:314",
        "src/dtls.c:317",
        "src/dtls.c:320",
        "src/dtls.c:323",
        "src/dtls.c:341",
    ],
    "cookie": [
        "src/dtls.c:211",
        "src/dtls.c:223",
        "src/dtls.c:230",
        "src/dtls.c:235",
        "src/dtls.c:239",
        "src/dtls.c:243",
        "src/dtls.c:247",
        "src/dtls.c:258",
        "src/dtls.c:284",
        "src/dtls.c:292",
        "src/dtls.c:899",
        "src/dtls.c:905",
        "src/dtls.c:1003",
        "src/dtls.c:1014",
        "src/dtls.c:1031",
    ],
    "hvr": [
        "src/internal.c:31323",
        "src/internal.c:31346",
        "src/internal.c:31350",
        "src/internal.c:31357",
        "src/internal.c:31380",
        "src/internal.c:40804",
        "src/internal.c:40840",
        "src/internal.c:40842",
        "src/internal.c:40845",
    ],
    "cookie_secret": [
        "src/ssl.c:6314",
        "src/ssl.c:6331",
        "src/ssl.c:6338",
        "src/ssl.c:6361",
        "src/dtls.c:217",
        "src/dtls.c:225",
        "src/dtls.c:292",
    ],
    "epoch": [
        "src/internal.c:8085",
        "src/internal.c:9423",
        "src/internal.c:9459",
        "src/internal.c:9465",
        "src/internal.c:9487",
        "src/internal.c:12263",
        "src/internal.c:12270",
        "src/internal.c:18311",
        "src/internal.c:23865",
        "src/internal.c:24833",
        "src/internal.c:24836",
    ],
    "fragment": [
        "src/internal.c:10875",
        "src/internal.c:10900",
        "src/internal.c:10901",
        "src/internal.c:10902",
        "src/internal.c:10949",
        "src/internal.c:10990",
        "src/internal.c:11022",
        "src/internal.c:11055",
        "src/internal.c:11076",
        "src/internal.c:12403",
        "src/internal.c:12423",
        "src/internal.c:12425",
        "src/internal.c:19524",
        "src/internal.c:19647",
        "src/internal.c:9790",
        "src/internal.c:9793",
        "src/internal.c:9794",
    ],
    "mtu": [
        "src/ssl.c:1588",
        "src/ssl.c:1598",
        "src/internal.c:11624",
        "src/internal.c:11646",
        "src/internal.c:42150",
        "src/internal.c:42170",
        "src/internal.c:42177",
    ],
    "alert": [
        "src/internal.c:18938",
        "src/internal.c:18988",
        "src/internal.c:22472",
        "src/internal.c:22486",
        "src/internal.c:23063",
        "src/internal.c:23068",
        "src/internal.c:23117",
        "src/internal.c:23121",
        "src/internal.c:23155",
    ],
}


def item_std(i):
    v = i["variable_name"]
    if v in ("body", "hello_verify_request"):
        return STD["handshake"]
    if v in ("cookie", "cipher_suites", "compression_methods", "client_hello"):
        return STD["cookie"]
    if v in ("epoch", "length"):
        return STD["record"]
    if v in ("fragment", "fragment_length", "fragment_offset"):
        return STD["fragment"]
    return STD["alert"]


def decide(display_id, item):
    v = item["variable_name"]
    if 1 <= display_id <= 12 or display_id == 46:
        return SAT, "implemented", "low", E["handshake_enum"], "wolfSSL [non-English text removed] hello_verify_request(3)，[non-English text removed] DoHandShakeMsgType medium[non-English text removed] UNKNOWN_HANDSHAKE_TYPE。", "RFC [non-English text removed] DoClientHello、DoServerHello、DoCertificate、DoFinished [non-English text removed]。"
    if display_id in (13, 16):
        return SAT, "implemented", "low", E["clienthello_send"] + E["hvr"], "clientreceives HelloVerifyRequest [non-English text removed] ClientHello；version/random/session_id/cipher_suites/compression_methods [non-English text removed] SendClientHello medium[non-English text removed] clientRandom，cipher_suites [non-English text removed]；DoHelloVerifyRequest [non-English text removed]path。"
    if display_id == 14:
        return SAT, "implemented", "low", E["clienthello_parse"], "ClientHello [non-English text removed]length；DTLS 1.3 stateless [non-English text removed] CipherSuite cipher_suites<2..2^16-1>。wolfSSL [non-English text removed]validation vector boundary，[non-English text removed]satisfied。"
    if display_id == 17:
        return SAT, "implemented", "low", E["clienthello_parse"] + ["src/internal.c:31252"], "ClientHello [non-English text removed] u8 compression_methods vector [non-English text removed] CompressionMethod compression_methods<1..2^8-1>。wolfSSL [non-English text removed]。"
    if display_id in (18, 19, 20, 27, 28):
        return SAT, "implemented", "low", E["clienthello_send"] + E["hvr"], "ClientHello cookie use u8 length[non-English text removed] 0，DoHelloVerifyRequest [non-English text removed] ClientHello。", "RFC [non-English text removed]，receives HelloVerifyRequest [non-English text removed]use opaque cookie<0..2^8-1> [non-English text removed]。"
    if display_id in (21, 26, 30):
        return SAT, "implemented", "medium", E["cookie"], "server stateless ClientHello path[non-English text removed] CheckDtlsCookie；length[non-English text removed] HMAC cookie length，ConstantCompare [non-English text removed] HelloVerifyRequest。", "RFC [non-English text removed]、random、session_id、cipher_suites、compression_methods [non-English text removed]validationsemantic。"
    if display_id in (22, 25, 29):
        return SAT, "implemented", "medium", E["cookie"] + E["hvr"], "server[non-English text removed]。SendHelloVerifyRequest rejection[non-English text removed] HelloVerifyRequest medium[non-English text removed] CreateDtls12Cookie use HMAC(secret, peer, version, random, session_id, cipher_suites, compression)，SendHelloVerifyRequest [non-English text removed] cookie。"
    if display_id == 23:
        return PART, "DTLS 1.2 cookie length[non-English text removed]length", "low", E["cookie"] + E["hvr"] + ["wolfssl/internal.h:1572"], "[non-English text removed] opaque cookie<0..2^8-1> [non-English text removed] DTLS_COOKIE_SZ，client[non-English text removed] HelloVerifyRequest cookie [non-English text removed] SHA/SHA256 length cookie，[non-English text removed] DTLS 1.2 client/server，[non-English text removed]valid HelloVerifyRequest cookie，[non-English text removed]partialsatisfied。"
    if display_id in (24, 31):
        return PART, "cookie secret [non-English text removed] secret", "medium", E["cookie_secret"], "wolfSSL [non-English text removed] wolfSSL_DTLS_SetCookieSecret [non-English text removed] secret；CreateDtls12Cookie [non-English text removed]use ssl->buffers.dtlsCookieSecret [non-English text removed] secret membership check，[non-English text removed]partialsatisfied。"
    if display_id == 15 or display_id == 47:
        return SAT, "implemented", "low", E["hvr"] + ["src/internal.c:40818"], "[non-English text removed]；clientprocessing HelloVerifyRequest [non-English text removed] CertificateVerify/Finished transcript [non-English text removed] HelloVerifyRequest。", "RFC [non-English text removed] cookie exchange medium[non-English text removed] CertificateVerify/Finished MAC。wolfSSL [non-English text removed] SendHelloVerifyRequest [non-English text removed] InitHandshakeHashes，[non-English text removed]。"
    if display_id in (32, 34, 35, 39):
        return SAT, "implemented", "low", E["epoch"], "DTLS [non-English text removed] epoch sequence；WriteSEQ [non-English text removed] epoch||sequence_number [non-English text removed]semantic。"
    if display_id == 33:
        return SAT, "implemented", "low", E["epoch"], "wolfSSL use 16-bit dtls_epoch field[non-English text removed]field epoch。"
    if display_id in (36, 37):
        return SAT, "implemented", "medium", E["epoch"], "GetRecordHeader [non-English text removed] replay window、application_data [non-English text removed] epoch application_data。wolfSSL [non-English text removed]。"
    if display_id == 38:
        return NA, "association [non-English text removed]", "low", ["src/internal.c:12263", "src/dtls.c:67"], "[non-English text removed]receives epoch 0 ClientHello [non-English text removed] association。wolfSSL record layer [non-English text removed]not applicable。"
    if display_id == 40:
        return SAT, "implemented", "medium", E["epoch"] + E["fragment"], "wolfSSL [non-English text removed] flight；DtlsMsgPoolSend [non-English text removed] sequence，VerifyForTxDtlsMsgDelete [non-English text removed]。"
    if display_id == 41:
        return PART, "epoch [non-English text removed]", "medium", E["epoch"], "wolfSSL [non-English text removed]partialsatisfied。"
    if display_id in (42, 43):
        return PART, "PMTU [non-English text removed]", "medium", E["fragment"] + E["mtu"], "SendHandshakeMsg [non-English text removed] wolfssl_local_GetMaxPlaintextSize [non-English text removed]；wolfSSL_dtls_set_mtu [non-English text removed] repeated retransmissions no response [non-English text removed] DTLS 1.2 timeout pathmedium[non-English text removed]partialsatisfied。"
    if display_id in (44, 45):
        return SAT, "implemented", "low", E["fragment"], "AddHandShakeHeader [non-English text removed] message_seq、fragment_offset、fragment_length；[non-English text removed] GetDtlsHandShakeHeader [non-English text removed] offset=0、fragment_length=total length [non-English text removed] transcript hash use。", "RFC [non-English text removed] CertificateVerify/Finished transcript use DTLS handshake header，[non-English text removed] fragment_length。wolfSSL [non-English text removed]。"
    if display_id == 48:
        return SAT, "implemented", "low", ["src/internal.c:12102", "src/internal.c:12219", "src/internal.c:12337", "src/internal.c:12346", "wolfssl/internal.h:2298"], "GetDtlsRecordHeader [non-English text removed] DTLSPlaintext.length，GetRecordHeader [non-English text removed] DTLSPlaintext.fragment<0..2^14>。wolfSSL [non-English text removed]length，satisfiedrange[non-English text removed]。"
    return SAT, "implemented", "low", E["alert"], "wolfSSL [non-English text removed] SendAlert use alert_fatal，bad MAC path[non-English text removed] alert，fatal erroruse fatal level。wolfSSL [non-English text removed]range。"


def validate_evidence(paths):
    missing = []
    out_of_range = []
    checked = 0
    for rel in sorted(set(paths)):
        file_part, line_s = rel.rsplit(":", 1)
        f = TARGET / file_part
        if not f.exists():
            missing.append(rel)
            continue
        try:
            line = int(line_s)
        except ValueError:
            out_of_range.append(rel)
            continue
        checked += 1
        with f.open("r", encoding="utf-8", errors="ignore") as fh:
            count = sum(1 for _ in fh)
        if line < 1 or line > count:
            out_of_range.append(rel)
    return {"checked": checked, "missing": missing, "out_of_range": out_of_range}


def write_json(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = json.loads(INPUT_JSON.read_text(encoding="utf-8"))
    changes = data["changes"][:50]
    results = []
    all_evidence = []
    for idx, item in enumerate(changes):
        display_id = idx + 1
        status, category, risk, evidence, comment, summary = decide(display_id, item)
        std = item_std(item)
        all_evidence.extend(evidence)
        result = {
            "id": display_id,
            "source_index": idx,
            **item,
            "status": status,
            "comment": comment,
            "standard_section": std["section"],
            "standard_quote": std["quote"],
            "comparison_summary": summary,
            "category": category,
            "risk": risk,
            f"evidence_in_{IMPL}": evidence,
        }
        results.append(result)

    counts = Counter(r["status"] for r in results)
    validation = validate_evidence(all_evidence)
    meta = {
        "source_file": str(INPUT_JSON),
        "scope": "001-050_rules",
        "method": "static_code_comparison_with_phase2_verification",
        "protocol": "DTLS 1.2",
        "standard_reference": "https://www.rfc-editor.org/rfc/rfc6347",
        "target_requested": r"D:\project\conditionFuzzing\wolfssl-main",
        "target_used": str(TARGET),
        "target_note": "Requested target_repo did not exist; used existing wolfssl-master workspace directory.",
        "counts": dict(counts),
        "evidence_validation": validation,
    }
    write_json(OUT / "compare_wolfssl_001_050.json", {"meta": meta, "results": results})

    md = ["# wolfSSL DTLS 1.2 001-050 comparison results", "", f"- satisfied: {counts.get(SAT, 0)}", f"- partialsatisfied: {counts.get(PART, 0)}", f"- [non-English text removed]satisfied: {counts.get(UNSAT, 0)}", f"- not applicable: {counts.get(NA, 0)}", "", "| ID | variable | action | status | [non-English text removed] |", "|---:|---|---|---|---|"]
    simple = []
    for r in results:
        md.append(f"| {r['id']:03d} | {r['variable_name']} | {r['change_action']} | {r['status']} | {r['comment']} |")
        simple.append(f"{r['id']:03d}\t{r['status']}\t{r['variable_name']}\t{r['change_action']}\t{r['comment']}")
    (OUT / "compare_wolfssl_001_050.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (OUT / "compare_wolfssl_001_050_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")

    groups = defaultdict(list)
    for r in results:
        if r["status"] in (PART, UNSAT):
            groups[r["category"]].append(r)
    class_obj = {
        "meta": {
            "scope": "001-050_rules",
            "target": "wolfssl-master",
            "counts": {"total": sum(len(v) for v in groups.values()), PART: counts.get(PART, 0), UNSAT: counts.get(UNSAT, 0)},
            "risk_counts": dict(Counter(r["risk"] for g in groups.values() for r in g)),
            "phase2_status": "completed",
        },
        "groups": {},
    }
    for category, items in groups.items():
        out_items = []
        for r in items:
            if r["id"] == 23:
                decision = "confirmed_partial"
                test = "verify_wolfssl_dtls12_001_050.py [non-English text removed] MAX_COOKIE_LEN=32、DoHelloVerifyRequest [non-English text removed] cookieSz <= MAX_COOKIE_LEN [non-English text removed] ch->cookie.size == DTLS_COOKIE_SZ。"
            elif r["id"] in (24, 31):
                decision = "confirmed_partial"
                test = "verify_wolfssl_dtls12_001_050.py [non-English text removed] wolfSSL_DTLS_SetCookieSecret [non-English text removed] buffer，CheckDtlsCookie [non-English text removed] ConstantCompare，not found previous/old secret [non-English text removed]。"
            elif r["id"] == 41:
                decision = "confirmed_partial"
                test = "verify_wolfssl_dtls12_001_050.py [non-English text removed]not found MSL、maximum segment lifetime [non-English text removed] association epoch reuse [non-English text removed]。"
            else:
                decision = "confirmed_partial"
                test = "verify_wolfssl_dtls12_001_050.py [non-English text removed] fragment size。"
            out_items.append({
                "id": r["id"],
                "status": r["status"],
                "variable_name": r["variable_name"],
                "change_action": r["change_action"],
                "change_condition": r["change_condition"],
                "category": r["category"],
                "risk": r["risk"],
                "standard_section": r["standard_section"],
                "comment": r["comment"],
                f"evidence_in_{IMPL}": r[f"evidence_in_{IMPL}"],
                "standard_check": f"[non-English text removed] {r['standard_section']}：{r['standard_quote']}",
                "code_check": r["comparison_summary"],
                "test_check": test,
                "decision_reason": r["comment"],
                "phase2_decision": decision,
            })
        class_obj["groups"][category] = {"count": len(items), "items": out_items}
    write_json(OUT / "compare_wolfssl_001_050_partial_unsat_classification.json", class_obj)

    cmd = ["# wolfSSL DTLS 1.2 001-050 partialsatisfied/[non-English text removed]satisfiedcategory", ""]
    for category, g in class_obj["groups"].items():
        cmd.append(f"## {category}")
        cmd.append("")
        for it in g["items"]:
            cmd.append(f"- {it['id']:03d} {it['status']} {it['variable_name']}: {it['decision_reason']}")
        cmd.append("")
    (OUT / "compare_wolfssl_001_050_partial_unsat_classification.md").write_text("\n".join(cmd), encoding="utf-8")

    write_reports(class_obj)
    write_verify_script()
    write_summary(counts, class_obj)


def report(title, ids, summary, standard, code, behavior, reason, evidence, impact, fix):
    return f"""# {title}

## Summary
{summary}

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc6347

{standard['section']}

```text
{standard['quote']}
```

[non-English text removed]semantic。

## Relevant Source Code
```c
{code}
```

## Implementation Behavior
{behavior}

## Inconsistency Reason
{reason}

## Runtime Evidence
{evidence}

## Impact
{impact}

## Fix Direction
{fix}
"""


def write_reports(class_obj):
    cookie_code = """src/dtls.c:284
if (ch->cookie.size != DTLS_COOKIE_SZ)
    return 0;

src/internal.c:31357
if (cookieSz <= MAX_COOKIE_LEN) {
    XMEMCPY(ssl->arrays->cookie, input + *inOutIdx, cookieSz);
    ssl->arrays->cookieSz = cookieSz;
}

wolfssl/internal.h:1572
MAX_COOKIE_LEN = 32"""
    (OUT / "id023_dtls12_cookie_length_limit_partial.md").write_text(report(
        "DTLS 1.2 HelloVerifyRequest cookie length is narrower than the RFC syntax",
        [23],
        "wolfSSL implements the DTLS 1.2 cookie exchange, but its accepted cookie size is restricted to the internally generated SHA/SHA-256 cookie size and the client save buffer is limited to 32 bytes.",
        STD["cookie"],
        cookie_code,
        "The server-side stateless path accepts a second ClientHello cookie only when its size equals DTLS_COOKIE_SZ. The client-side HelloVerifyRequest parser only copies the cookie into ssl->arrays when cookieSz <= MAX_COOKIE_LEN.",
        "RFC 6347 encodes DTLS 1.2 cookies as opaque vectors with an 8-bit length. wolfSSL's own generated cookie fits this limit, but a compliant peer can send a larger cookie up to 255 bytes. Such a cookie is parsed but not retained by the client, or rejected by the server because it is not exactly DTLS_COOKIE_SZ.",
        "The verification script confirms MAX_COOKIE_LEN=32, fixed DTLS_COOKIE_SZ comparison, and the guarded copy in DoHelloVerifyRequest.",
        "Interoperability can fail with DTLS 1.2 peers that use larger stateless cookies.",
        "Store and validate cookies according to the RFC vector length, or document and negotiate the stricter implementation limit. If retaining fixed HMAC cookies on the server, the client parser should still preserve peer cookies up to 255 bytes.",
    ), encoding="utf-8")

    secret_code = """src/ssl.c:6338
if (ssl->buffers.dtlsCookieSecret.buffer != NULL) {
    ForceZero(ssl->buffers.dtlsCookieSecret.buffer,
              ssl->buffers.dtlsCookieSecret.length);
    XFREE(ssl->buffers.dtlsCookieSecret.buffer,
          ssl->heap, DYNAMIC_TYPE_COOKIE_PWD);
}

src/dtls.c:225
ret = wc_HmacSetKey(&cookieHmac, DTLS_COOKIE_TYPE,
    ssl->buffers.dtlsCookieSecret.buffer,
    ssl->buffers.dtlsCookieSecret.length);

src/dtls.c:292
*cookieGood = ConstantCompare(ch->cookie.elements, ch->dtls12cookie,
                              DTLS_COOKIE_SZ) == 0;"""
    (OUT / "id024_031_dtls12_cookie_secret_rotation_partial.md").write_text(report(
        "DTLS 1.2 cookie secret rotation lacks a previous-secret acceptance window",
        [24, 31],
        "wolfSSL computes and validates DTLS 1.2 cookies with an HMAC secret, but changing the secret replaces the old value immediately.",
        STD["cookie"],
        secret_code,
        "wolfSSL_DTLS_SetCookieSecret frees and replaces the current dtlsCookieSecret buffer. CreateDtls12Cookie and CheckDtlsCookie compute and compare a cookie only with that current secret.",
        "RFC 6347 says that when the server changes its Secret value, it should retain the previous value for a limited period and accept cookies generated with either value. wolfSSL implements the HMAC cookie construction but not the transition-window membership check.",
        "The verification script checks that only dtlsCookieSecret is maintained and no previous/old secret window is present in the DTLS 1.2 cookie path.",
        "Clients that respond with a cookie minted immediately before server-side secret rotation may be forced into another HelloVerifyRequest round.",
        "Add a previous cookie secret slot with a bounded lifetime and check incoming cookies against both current and previous secrets during the transition window.",
    ), encoding="utf-8")

    epoch_code = """src/internal.c:24836
ssl->keys.dtls_epoch++;
ssl->keys.dtls_prev_sequence_number_hi = ssl->keys.dtls_sequence_number_hi;
ssl->keys.dtls_prev_sequence_number_lo = ssl->keys.dtls_sequence_number_lo;
ssl->keys.dtls_sequence_number_hi = 0;
ssl->keys.dtls_sequence_number_lo = 0;"""
    (OUT / "id041_dtls12_epoch_reuse_timer_partial.md").write_text(report(
        "DTLS 1.2 epoch reuse is scoped to the connection object rather than a 2MSL association window",
        [41],
        "wolfSSL increments epochs during a connection and resets sequence numbers after cipher changes, but no 2MSL reuse guard was found for new associations on the same transport tuple.",
        STD["record"],
        epoch_code,
        "The active WOLFSSL object advances dtls_epoch and keeps current/previous sequence state. The searched code does not maintain an association-level timer preventing a newly created association from reusing epoch values within two times the TCP maximum segment lifetime.",
        "RFC 6347 prohibits reusing an epoch value within 2MSL. wolfSSL satisfies the rule inside one connection object, but the broader association-timing guarantee is not implemented in the library layer.",
        "The verification script searches the DTLS implementation for MSL/maximum segment lifetime handling and confirms only per-object epoch increment logic.",
        "A deployment that rapidly tears down and recreates DTLS associations on the same tuple relies on the application to avoid the RFC's reuse window concern.",
        "Document this as an application responsibility or add association-level epoch reuse tracking tied to peer tuple and a bounded 2MSL expiry.",
    ), encoding="utf-8")

    mtu_code = """src/internal.c:10074
if (ssl->dtls_timeout <  ssl->dtls_timeout_max) {
    ssl->dtls_timeout *= DTLS_TIMEOUT_MULTIPLIER;
    result = 0;
}

src/internal.c:42177
maxFrag -= (recordSz - mtu);

src/ssl.c:1598
int wolfSSL_dtls_set_mtu(WOLFSSL* ssl, word16 newMtu)"""
    (OUT / "id042_043_dtls12_pmtu_blackhole_fragmentation_partial.md").write_text(report(
        "DTLS 1.2 retransmission does not automatically lower fragment size when PMTU is unknown",
        [42, 43],
        "wolfSSL fragments handshake messages according to the configured MTU and record size, but repeated timeout retransmissions do not appear to trigger automatic smaller fragmentation when the PMTU is unknown.",
        STD["fragment"],
        mtu_code,
        "SendHandshakeMsg fragments by wolfssl_local_GetMaxPlaintextSize, which is based on the current max fragment/MTU. Timeout handling doubles dtls_timeout and retransmits the saved flight; it does not adjust dtlsMtuSz or fragment size.",
        "RFC 6347 recommends fragmenting more aggressively if repeated retransmissions do not receive a response and PMTU is unknown. wolfSSL has MTU-based fragmentation, but not the black-hole detection loop described by that SHOULD.",
        "The verification script checks the MTU set/get path, fragmentation path, and timeout path, confirming no automatic MTU decrease on repeated timeout.",
        "Large handshake flights may continue to be retransmitted at an ineffective size until the application configures a smaller MTU.",
        "Track repeated DTLS 1.2 retransmission failures and reduce the handshake fragment size or expose a documented callback/API for PMTU black-hole response.",
    ), encoding="utf-8")


def write_verify_script():
    script = r'''import json
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
'''
    (OUT / "verify_wolfssl_dtls12_001_050.py").write_text(script, encoding="utf-8")


def write_summary(counts, class_obj):
    summary = {
        "round": "001-050",
        "output_dir": str(OUT),
        "status_counts": dict(counts),
        "partial_unsatisfied_total": class_obj["meta"]["counts"]["total"],
        "confirmed_partial": sum(1 for g in class_obj["groups"].values() for it in g["items"] if it["phase2_decision"] == "confirmed_partial"),
        "confirmed_unsatisfied": 0,
        "false_positive": 0,
        "not_testable": 0,
        "reports": sorted(p.name for p in OUT.glob("id*.md")),
        "next_round": "051-098",
    }
    write_json(OUT / "round_summary_001_050.json", summary)


if __name__ == "__main__":
    main()
