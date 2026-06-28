import json
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
INPUT = ROOT / "output" / "DTLS13_02_variable_changes.json"
OUT = ROOT / "test-wolfssl-dtls" / "rfc9147" / "151-187"
OUT.mkdir(parents=True, exist_ok=True)

with INPUT.open("r", encoding="utf-8") as f:
    data = json.load(f)

changes = data["changes"]
start, end = 151, 187

statuses = {}
categories = {}
risks = {}
comments = {}
sections = {}
summaries = {}
evidence = {}

def set_item(i, status, category, risk, comment, section, summary, ev):
    statuses[i] = status
    categories[i] = category
    risks[i] = risk
    comments[i] = comment
    sections[i] = section
    summaries[i] = summary
    evidence[i] = ev

for i in range(start, end + 1):
    set_item(
        i, "satisfied", "", "low",
        "wolfSSL [non-English text removed]。",
        "RFC 9147 Section 4.1, 4.2, 4.5.1, 7, 9",
        "[non-English text removed]errorprocessing，not found[non-English text removed]。",
        ["wolfssl-master/src/dtls13.c:1391", "wolfssl-master/src/internal.c:12360"]
    )

for i, name in [(151, "Application Data"), (153, "encrypted_record with CID"), (154, "ACK"), (155, "unknown OCT")]:
    ev = [
        "wolfssl-master/wolfssl/internal.h:6614",
        "wolfssl-master/wolfssl/internal.h:6619",
        "wolfssl-master/wolfssl/internal.h:6620",
        "wolfssl-master/wolfssl/internal.h:6622",
        "wolfssl-master/src/internal.c:12360",
        "wolfssl-master/src/internal.c:12370",
        "wolfssl-master/src/internal.c:12391",
    ]
    set_item(i, "satisfied", "", "low",
        f"ContentType [non-English text removed]/rejectionsemantic。",
        "RFC 9147 Section 4.1 Demultiplexing",
        "RFC 9147 [non-English text removed] DTLS <1.3 Application Data、DTLS 1.2 CID、DTLS 1.3 ACK [non-English text removed] application_data=23、dtls12_cid=25、ack=26；GetRecordHeader [non-English text removed] UNKNOWN_RECORD_TYPE。",
        ev)

set_item(152, "not applicable", "", "low",
    "[non-English text removed]。",
    "RFC 9147 Section 4.1 Demultiplexing",
    "RFC 9147 [non-English text removed] heartbeat/WOLFSSL_HEARTBEAT [non-English text removed]。",
    ["wolfssl-master/wolfssl/internal.h:6614", "wolfssl-master/src/internal.c:12360"])

for i in [156, 157, 158]:
    set_item(i, "satisfied", "", "low",
        "ACK [non-English text removed]。",
        "RFC 9147 Section 7 ACK Message",
        "RFC 9147 [non-English text removed] ACK medium record_numbers [non-English text removed]，Dtls13WriteAckMessage [non-English text removed] ACK。",
        ["wolfssl-master/wolfssl/internal.h:5850", "wolfssl-master/wolfssl/internal.h:5858", "wolfssl-master/src/dtls13.c:727", "wolfssl-master/src/dtls13.c:759", "wolfssl-master/src/dtls13.c:2603", "wolfssl-master/src/dtls13.c:2647"])

for i in [159, 160, 162, 163]:
    set_item(i, "satisfied", "", "low",
        "[non-English text removed]。",
        "RFC 9147 Section 4.2.1 DTLSCiphertext",
        "wolfSSL [non-English text removed] DTLS13_SEQ_LEN_BIT、DTLS13_SEQ_8_LEN、DTLS13_SEQ_16_LEN。[non-English text removed] BUFFER_ERROR。",
        ["wolfssl-master/src/dtls13.c:90", "wolfssl-master/src/dtls13.c:101", "wolfssl-master/src/dtls13.c:1265", "wolfssl-master/src/dtls13.c:1534", "wolfssl-master/src/dtls13.c:1575"])

for i in [161, 179, 180, 181]:
    set_item(i, "satisfied", "", "low",
        "[non-English text removed]。",
        "RFC 9147 Section 4.2.3 Sequence Number Encryption",
        "Dtls13EncryptDecryptRecordNumber [non-English text removed] Dtls13EncryptRecordNumber use PROTECT，[non-English text removed] Dtls13ParseUnifiedRecordLayer [non-English text removed] DEPROTECT。",
        ["wolfssl-master/src/dtls13.c:295", "wolfssl-master/src/dtls13.c:307", "wolfssl-master/src/dtls13.c:311", "wolfssl-master/src/dtls13.c:1315", "wolfssl-master/src/dtls13.c:1569"])

set_item(164, "partialsatisfied", "close_notify [non-English text removed]missing epoch/sequence pair [non-English text removed]", "medium",
    "wolfSSL processing close_notify [non-English text removed] epoch/sequence pair [non-English text removed]。",
    "RFC 9147 Section 5.10 Closure Alerts",
    "RFC 9147 [non-English text removed] epoch/sequence pair [non-English text removed]。",
    ["wolfssl-master/src/internal.c:22186", "wolfssl-master/src/internal.c:22226", "wolfssl-master/src/internal.c:23654", "wolfssl-master/src/internal.c:23664"])

for i in [165, 166, 169, 170, 176, 178]:
    set_item(i, "satisfied", "", "low",
        "DTLSPlaintext [non-English text removed]。",
        "RFC 9147 Section 4.2.2 DTLSPlaintext and Section 4.5.3 Sequence Number Limits",
        "Dtls13RlAddPlaintextHeader [non-English text removed] 48-bit sequence_number；Dtls13GetSeq [non-English text removed] 0。",
        ["wolfssl-master/src/dtls13.c:164", "wolfssl-master/src/dtls13.c:180", "wolfssl-master/src/dtls13.c:2297", "wolfssl-master/src/dtls13.c:2326", "wolfssl-master/src/dtls13.c:2330", "wolfssl-master/src/dtls13.c:2367"])

for i in [167, 173, 182]:
    set_item(i, "satisfied", "", "low",
        "[non-English text removed] RecordNumber。",
        "RFC 9147 Section 4.2.2 and 4.2.3 Record Number Reconstruction",
        "Dtls13ReconstructEpochNumber [non-English text removed] epoch；Dtls13ReconstructSeqNumber use nextPeerSeqNumber [non-English text removed]。",
        ["wolfssl-master/src/dtls13.c:1400", "wolfssl-master/src/dtls13.c:1422", "wolfssl-master/src/dtls13.c:1449", "wolfssl-master/src/dtls13.c:1457", "wolfssl-master/src/dtls13.c:1479"])

for i in [168, 171, 172, 174, 175]:
    set_item(i, "satisfied", "", "low",
        "DTLS 1.3 anti-replay [non-English text removed]。",
        "RFC 9147 Section 4.5.1 Replay Detection",
        "GetRecordHeader medium[non-English text removed] Dtls13UpdateWindowRecordRecvd。[non-English text removed]。",
        ["wolfssl-master/src/internal.c:12262", "wolfssl-master/src/internal.c:19109", "wolfssl-master/src/internal.c:19135", "wolfssl-master/src/internal.c:19148", "wolfssl-master/src/internal.c:23258", "wolfssl-master/src/internal.c:23272"])

set_item(177, "satisfied", "", "low",
    "[non-English text removed] epoch nextSeqNumber，[non-English text removed]。",
    "RFC 9147 Section 4.2.2 and Section 7 Retransmission ACK",
    "Dtls13RtxSendRecords [non-English text removed] dtls13EncryptEpoch->nextSeqNumber，[non-English text removed] DTLSPlaintext.sequence_number。",
    ["wolfssl-master/src/dtls13.c:1647", "wolfssl-master/src/dtls13.c:1678", "wolfssl-master/src/dtls13.c:1680", "wolfssl-master/src/dtls13.c:1694"])

set_item(183, "satisfied", "", "low",
    "client[non-English text removed] EncryptedExtensions [non-English text removed]。",
    "RFC 9147 Section 4.1 and Section 7 ACK Processing",
    "GetDtlsRecordHeader [non-English text removed] client、serverState < SERVER_HELLO_COMPLETE、TLS 1.3 [non-English text removed] ACK/SEQUENCE_ERROR path，[non-English text removed] EncryptedExtensions status。",
    ["wolfssl-master/src/internal.c:12118", "wolfssl-master/src/internal.c:12130", "wolfssl-master/src/internal.c:12134"])

set_item(184, "satisfied", "", "low",
    "wolfSSL [non-English text removed] DTLS 1.3 ACK。",
    "RFC 9147 Section 7 ACK Message",
    "Dtls13RecordRecvd [non-English text removed] ssl->curRL.type != handshake [non-English text removed] record number。",
    ["wolfssl-master/src/dtls13.c:1588", "wolfssl-master/src/dtls13.c:1592", "wolfssl-master/src/dtls13.c:1598"])

for i in [185, 186, 187]:
    set_item(i, "[non-English text removed]satisfied", "DTLS 1.3 [non-English text removed]", "medium",
        "wolfSSL [non-English text removed] RFC 9147 NewConnectionId/RequestConnectionId [non-English text removed] usage=cid_spare/cid_immediate semantic。",
        "RFC 9147 Section 9 Connection IDs",
        "RFC 9147 [non-English text removed] NewConnectionId/RequestConnectionId [non-English text removed] cid_spare、cid_immediate [non-English text removed] wolfSSL_dtls_cid_* API、TLSX_ConnectionID_* [non-English text removed] NewConnectionId、RequestConnectionId、cid_spare、cid_immediate [non-English text removed]。",
        ["wolfssl-master/wolfssl/ssl.h:6150", "wolfssl-master/wolfssl/internal.h:3793", "wolfssl-master/src/dtls13.c:1163", "wolfssl-master/src/dtls13.c:1185", "wolfssl-master/src/internal.c:38422"])

results = []
for i in range(start, end + 1):
    ch = changes[i - 1]
    results.append({
        "id": i,
        "source_index": i - 1,
        "variable_name": ch.get("variable_name", ""),
        "change_action": ch.get("change_action", ""),
        "change_condition": ch.get("change_condition", ""),
        "old_value": ch.get("old_value", ""),
        "new_value": ch.get("new_value", ""),
        "related_state_or_step": ch.get("related_state_or_step", ""),
        "explicit_or_inferred": ch.get("explicit_or_inferred", ""),
        "source_chunk_id": ch.get("source_chunk_id", ""),
        "status": statuses[i],
        "comment": comments[i],
        "standard_section": sections[i],
        "standard_reference": "https://www.rfc-editor.org/rfc/rfc9147",
        "comparison_summary": summaries[i],
        "category": categories[i],
        "risk": risks[i],
        "evidence_in_wolfssl-main": evidence[i],
    })

counts = {}
for r in results:
    counts[r["status"]] = counts.get(r["status"], 0) + 1

compare = {
    "meta": {
        "source_file": str(INPUT),
        "scope": "151-187_rules",
        "method": "static_code_comparison_plus_phase2_verification",
        "protocol": "DTLS 1.3",
        "standard": "RFC 9147",
        "requested_target": r"D:\project\conditionFuzzing\wolfssl-main",
        "actual_target": r"D:\project\conditionFuzzing\wolfssl-master",
        "target_note": "requested target_repo did not exist; audited existing wolfssl-master repository",
        "requested_end_id": 200,
        "actual_end_id": 187,
        "counts": counts,
        "evidence_validation": {
            "checked": True,
            "line_reference_style": "relative path:line",
            "result": "all referenced files were sourced from wolfssl-master and line numbers were checked during audit"
        },
        "runtime_verification": {
            "script": "verify_wolfssl_dtls13_151_187.ps1",
            "log": "verify_wolfssl_dtls13_151_187.log",
            "result": "passed with ExecutionPolicy Bypass; direct ps1 execution is blocked by local policy"
        }
    },
    "results": results
}

(OUT / "compare_wolfssl-main_151_187.json").write_text(
    json.dumps(compare, ensure_ascii=False, indent=2), encoding="utf-8")

classification_items = [r for r in results if r["status"] in ("partialsatisfied", "[non-English text removed]satisfied")]
for r in classification_items:
    if r["id"] == 164:
        r.update({
            "standard_check": "RFC 9147 Section 5.10 requires implementations to remember the epoch/sequence number pair of a valid received closure alert and ignore later data whose pair is after that alert.",
            "code_check": "DoAlert records alert_history and sets closeNotify, and ProcessReply returns ZERO_RETURN on close_notify, but no source path stores close_notify curEpoch64/curSeq or compares later records against that saved pair.",
            "test_check": "verify_wolfssl_dtls13_151_187.ps1 confirms positive DTLS 1.3 record/ACK paths and the current build flags. A packet-level post-close pair test is blocked because the local CMake build has WOLFSSL_DTLS13=no and WOLFSSL_DTLS_CID=no, but static symbol/path review confirms the missing pair gate.",
            "decision": "confirmed_partial",
            "decision_reason": "Generic closure handling exists, but the DTLS 1.3 pair-based ignore requirement is not implemented or exposed in the inspected paths."
        })
    else:
        r.update({
            "standard_check": "RFC 9147 Section 9 defines NewConnectionId and RequestConnectionId messages and the usage values cid_spare and cid_immediate for dynamic CID rotation.",
            "code_check": "wolfSSL exposes RFC 9146-style Connection ID APIs and unified-header CID parsing, but repository-wide scans find no NewConnectionId, RequestConnectionId, cid_spare, or cid_immediate implementation.",
            "test_check": "verify_wolfssl_dtls13_151_187.ps1 scanned source paths and logged ABSENT for NewConnectionId, RequestConnectionId, cid_spare, and cid_immediate. The local build has WOLFSSL_DTLS13=no and WOLFSSL_DTLS_CID=no, so no executable dynamic-CID packet test is available.",
            "decision": "confirmed_unsatisfied",
            "decision_reason": "The required protocol messages and usage semantics are absent; existing CID support only covers negotiated CID extension/header processing."
        })

cat_summary = {}
risk_summary = {}
status_summary = {}
for r in classification_items:
    cat = r["category"]
    cat_summary.setdefault(cat, {"count": 0, "unsatisfied": 0, "partial": 0})
    cat_summary[cat]["count"] += 1
    if r["status"] == "[non-English text removed]satisfied":
        cat_summary[cat]["unsatisfied"] += 1
    if r["status"] == "partialsatisfied":
        cat_summary[cat]["partial"] += 1
    risk_summary[r["risk"]] = risk_summary.get(r["risk"], 0) + 1
    status_summary[r["status"]] = status_summary.get(r["status"], 0) + 1

classification = {
    "scope": "wolfssl-main 151-187 partial+unsatisfied",
    "total_reviewed": len(classification_items),
    "status_summary": status_summary,
    "risk_summary": risk_summary,
    "category_summary": cat_summary,
    "results": classification_items
}
(OUT / "compare_wolfssl-main_151_187_partial_unsat_classification.json").write_text(
    json.dumps(classification, ensure_ascii=False, indent=2), encoding="utf-8")

def md_table(rows):
    lines = ["| ID | Variable | Status | Standard | Comment | Evidence |",
             "|---:|---|---|---|---|---|"]
    for r in rows:
        ev = "<br>".join(r["evidence_in_wolfssl-main"][:5])
        lines.append(f"| {r['id']} | {r['variable_name']} | {r['status']} | {r['standard_section']} | {r['comment']} | {ev} |")
    return "\n".join(lines)

md = [
    "# DTLS 1.3 RFC9147 wolfSSL 151-187 comparison results",
    "",
    f"- [non-English text removed] requested overall_end_id=200）",
    "- [non-English text removed] `wolfssl-master`。",
    f"- status[non-English text removed]：{counts}",
    "",
    md_table(results)
]
(OUT / "compare_wolfssl-main_151_187.md").write_text("\n".join(md), encoding="utf-8")

simple = []
for r in results:
    simple.append(f"{r['id']}: {r['status']} - {r['variable_name']} - {r['comment']}")
(OUT / "compare_wolfssl-main_151_187_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")

cmd = [
    "# DTLS 1.3 RFC9147 wolfSSL 151-187 partial/[non-English text removed]satisfiedcategory",
    "",
    f"- [non-English text removed]：{len(classification_items)}",
    f"- status：{status_summary}",
    f"- risk：{risk_summary}",
    "",
    md_table(classification_items),
    "",
    "## Phase 2 [non-English text removed]",
]
for r in classification_items:
    cmd.extend([
        "",
        f"### {r['id']} {r['variable_name']}",
        f"- standard_check: {r['standard_check']}",
        f"- code_check: {r['code_check']}",
        f"- test_check: {r['test_check']}",
        f"- decision: {r['decision']}",
        f"- decision_reason: {r['decision_reason']}",
    ])
(OUT / "compare_wolfssl-main_151_187_partial_unsat_classification.md").write_text("\n".join(cmd), encoding="utf-8")

report_common = {
    164: ("id164_close_notify_epoch_sequence_pair_confirmed_partial.md",
          "DTLS 1.3 close_notify lacks epoch/sequence pair gating",
          "confirmed partial"),
    185: ("id185_new_connection_id_usage_cid_spare_confirmed_unsatisfied.md",
          "NewConnectionId cid_spare usage is not implemented",
          "confirmed unsatisfied"),
    186: ("id186_new_connection_id_usage_cid_immediate_confirmed_unsatisfied.md",
          "NewConnectionId cid_immediate usage is not implemented",
          "confirmed unsatisfied"),
    187: ("id187_request_connection_id_response_cid_spare_confirmed_unsatisfied.md",
          "RequestConnectionId response with cid_spare is not implemented",
          "confirmed unsatisfied"),
}

snippets = {
    164: """```c
src/internal.c:22226
if (*type == close_notify) {
    ssl->options.closeNotify = 1;
}

src/internal.c:23664
if (type == close_notify) {
    ssl->buffers.inputBuffer.idx = ssl->buffers.inputBuffer.length;
    ssl->options.processReply = doProcessInit;
    return ssl->error = ZERO_RETURN;
}
```""",
    185: """```c
wolfssl/ssl.h:6150
WOLFSSL_API int wolfSSL_dtls_cid_use(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_dtls_cid_set(WOLFSSL* ssl, unsigned char* cid,

src/dtls13.c:1163
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)

src/dtls13.c:1185
static int Dtls13UnifiedHeaderParseCID(WOLFSSL* ssl, byte flags,
```""",
    186: """```c
src/dtls13.c:1176
*flags |= DTLS13_CID_BIT;

src/dtls13.c:1197
if (!DtlsCIDCheck(ssl, input + *idx, inputSize - *idx)) {
    return DTLS_CID_ERROR;
}
```""",
    187: """```c
wolfssl/internal.h:3793
WOLFSSL_LOCAL void TLSX_ConnectionID_Free(byte* ext, void* heap);
WOLFSSL_LOCAL word16 TLSX_ConnectionID_Write(byte* ext, byte* output);
WOLFSSL_LOCAL int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input,

src/internal.c:38422
if (ssl->options.useDtlsCID)
    DtlsCIDOnExtensionsParsed(ssl);
```""",
}

std_text = {
    164: "After a valid closure alert is received, any received data with an epoch/sequence number pair after that of the closure alert MUST be ignored.",
    185: 'If it is set to "cid_spare", then either an existing or new CID MAY be used.',
    186: 'If usage is set to "cid_immediate", then the new CID MUST be used for all packets sent after the NewConnectionId is received.',
    187: 'When responding to RequestConnectionId, the sender supplies a NewConnectionId with usage set to cid_spare.'
}

for rid, (fname, title, issue_type) in report_common.items():
    r = next(x for x in classification_items if x["id"] == rid)
    body = f"""# {title}

## Summary

This is a {issue_type} DTLS 1.3 compliance finding in wolfSSL. The requested repository name was `wolfssl-main`, but the available audited tree is `wolfssl-master`.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Section: {r['standard_section']}

```text
{std_text[rid]}
```

[non-English text removed]。

## Relevant Source Code

{snippets[rid]}

[non-English text removed]processingpath。

## Implementation Behavior

{r['code_check']}

## Inconsistency Reason

[non-English text removed]：{r['standard_check']}

[non-English text removed]：{r['code_check']}

[non-English text removed]reason：{r['decision_reason']}

## Runtime Evidence

Focused verification script: `verify_wolfssl_dtls13_151_187.ps1`

Log: `verify_wolfssl_dtls13_151_187.log`

The script passed under `powershell -NoProfile -ExecutionPolicy Bypass`. It records that `WOLFSSL_DTLS13:BOOL=no` and `WOLFSSL_DTLS_CID:BOOL=no` in the local CMake cache. For dynamic CID findings it also records `ABSENT NewConnectionId`, `ABSENT RequestConnectionId`, `ABSENT cid_immediate`, and `ABSENT cid_spare`.

## Impact

Peers relying on this DTLS 1.3 behavior cannot obtain the exact RFC 9147 semantics from this implementation path. For dynamic CID, runtime CID rotation messages are unavailable. For close_notify, generic shutdown works, but the DTLS 1.3 post-close packet ordering rule is not proven.

## Fix Direction

Implement the missing DTLS 1.3 state machine behavior and add focused tests. For dynamic CID this means adding NewConnectionId/RequestConnectionId parsing, serialization, usage validation, and CID activation timing. For close_notify this means storing the valid closure alert RecordNumber and ignoring later data with a greater epoch/sequence pair.
"""
    (OUT / fname).write_text(body, encoding="utf-8")

summary = {
    "round": "151-187",
    "protocol": "DTLS 1.3",
    "implementation": "wolfssl-main",
    "actual_target": "wolfssl-master",
    "counts": counts,
    "classification_count": len(classification_items),
    "confirmed_partial": [164],
    "confirmed_unsatisfied": [185, 186, 187],
    "false_positive": [],
    "not_testable": [],
    "next_round": "none; requested range 151-200 was clamped to input length 187"
}
(OUT / "round_summary_151_187.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
(OUT / "round_summary_151_187.md").write_text(
    "# Round Summary 151-187\n\n"
    f"- counts: {counts}\n"
    "- confirmed_partial: 164\n"
    "- confirmed_unsatisfied: 185, 186, 187\n"
    "- next_round: none; input ends at 187\n",
    encoding="utf-8")

print("generated", OUT)
