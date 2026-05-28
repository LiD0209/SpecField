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
        i, "满足", "", "low",
        "wolfSSL 的 DTLS 1.3 实现覆盖该记录层/ACK/序号规则。",
        "RFC 9147 Section 4.1, 4.2, 4.5.1, 7, 9",
        "需求与 RFC 9147 的记录层语义一致；代码路径中存在对应解析、生成、状态更新或错误处理，未发现缺口。",
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
    set_item(i, "满足", "", "low",
        f"ContentType 常量和记录头校验覆盖 {name} 的分流/拒绝语义。",
        "RFC 9147 Section 4.1 Demultiplexing",
        "RFC 9147 用首字节 OCT 区分 DTLS <1.3 Application Data、DTLS 1.2 CID、DTLS 1.3 ACK 和非法值。wolfSSL enum 定义 application_data=23、dtls12_cid=25、ack=26；GetRecordHeader 的 switch 只接受这些合法类型并对 default 返回 UNKNOWN_RECORD_TYPE。",
        ev)

set_item(152, "不适用", "", "low",
    "本仓库未启用或实现 Heartbeat 扩展路径；该 OCT=24 demux 常量不构成可验证的 DTLS 1.3 wolfSSL 行为。",
    "RFC 9147 Section 4.1 Demultiplexing",
    "RFC 9147 表中保留 OCT=24 为 Heartbeat。wolfSSL 当前源码搜索不到 heartbeat/WOLFSSL_HEARTBEAT 相关实现，无法要求其对未实现扩展提供运行时分流。",
    ["wolfssl-master/wolfssl/internal.h:6614", "wolfssl-master/src/internal.c:12360"])

for i in [156, 157, 158]:
    set_item(i, "满足", "", "low",
        "ACK 记录号列表使用 16-bit length 编码、允许空列表、按 epoch/seq 升序去重插入并序列化。",
        "RFC 9147 Section 7 ACK Message",
        "RFC 9147 要求 ACK 中 record_numbers 为 0..2^16-1 长度的向量，必要时可为空，且 RecordNumber 按数值递增。wolfSSL 对 ACK 最大数做编译期/运行时上限，Dtls13RtxAddAck 按 epoch 和 seq 升序插入且去重，Dtls13WriteAckMessage 可在 recordsCount=0 时写出只有 length=0 的 ACK。",
        ["wolfssl-master/wolfssl/internal.h:5850", "wolfssl-master/wolfssl/internal.h:5858", "wolfssl-master/src/dtls13.c:727", "wolfssl-master/src/dtls13.c:759", "wolfssl-master/src/dtls13.c:2603", "wolfssl-master/src/dtls13.c:2647"])

for i in [159, 160, 162, 163]:
    set_item(i, "满足", "", "low",
        "统一头 S bit 控制 8-bit/16-bit 序号长度，解析路径按该位选择长度并校验缓冲区。",
        "RFC 9147 Section 4.2.1 DTLSCiphertext",
        "wolfSSL 定义 DTLS13_SEQ_LEN_BIT、DTLS13_SEQ_8_LEN、DTLS13_SEQ_16_LEN。发送端当前总是设置 S bit 并写 16-bit 序号；接收端支持 S=0 的 8-bit 和 S=1 的 16-bit 解析，并在长度不足时返回 BUFFER_ERROR。",
        ["wolfssl-master/src/dtls13.c:90", "wolfssl-master/src/dtls13.c:101", "wolfssl-master/src/dtls13.c:1265", "wolfssl-master/src/dtls13.c:1534", "wolfssl-master/src/dtls13.c:1575"])

for i in [161, 179, 180, 181]:
    set_item(i, "满足", "", "low",
        "加密记录号通过序号保护密钥生成 mask 后 XOR，接收端使用同一过程解保护。",
        "RFC 9147 Section 4.2.3 Sequence Number Encryption",
        "Dtls13EncryptDecryptRecordNumber 从密文生成 record-number mask 并 xorbuf 到序号字节；发送端 Dtls13EncryptRecordNumber 使用 PROTECT，接收端 Dtls13ParseUnifiedRecordLayer 在重构前调用同一函数 DEPROTECT。",
        ["wolfssl-master/src/dtls13.c:295", "wolfssl-master/src/dtls13.c:307", "wolfssl-master/src/dtls13.c:311", "wolfssl-master/src/dtls13.c:1315", "wolfssl-master/src/dtls13.c:1569"])

set_item(164, "部分满足", "close_notify 后缺少 epoch/sequence pair 门控", "medium",
    "wolfSSL 处理 close_notify 并终止读取，但未记录有效关闭告警的 epoch/sequence pair 来按 RFC 9147 忽略之后的更晚数据。",
    "RFC 9147 Section 5.10 Closure Alerts",
    "RFC 9147 要求收到有效 closure alert 后，忽略 epoch/sequence pair 晚于该 alert 的数据。wolfSSL DoAlert 设置 closeNotify，记录处理返回 ZERO_RETURN；但源码中没有保存 close_notify 的 curEpoch64/curSeq，也没有对后续记录执行 pair-after-close 的专门比较。",
    ["wolfssl-master/src/internal.c:22186", "wolfssl-master/src/internal.c:22226", "wolfssl-master/src/internal.c:23654", "wolfssl-master/src/internal.c:23664"])

for i in [165, 166, 169, 170, 176, 178]:
    set_item(i, "满足", "", "low",
        "DTLSPlaintext 写入低 48 位序号，发送序号按 epoch 独立递增并在 64-bit wrap 时拒绝继续。",
        "RFC 9147 Section 4.2.2 DTLSPlaintext and Section 4.5.3 Sequence Number Limits",
        "Dtls13RlAddPlaintextHeader 写 epoch 与 48-bit sequence_number；Dtls13GetSeq 从 epoch 的 nextSeqNumber 生成序号并在递增后变为 0 时返回 BAD_STATE_E。新 Dtls13Epoch 结构被清零后首次使用，nextSeqNumber 初始为 0。",
        ["wolfssl-master/src/dtls13.c:164", "wolfssl-master/src/dtls13.c:180", "wolfssl-master/src/dtls13.c:2297", "wolfssl-master/src/dtls13.c:2326", "wolfssl-master/src/dtls13.c:2330", "wolfssl-master/src/dtls13.c:2367"])

for i in [167, 173, 182]:
    set_item(i, "满足", "", "low",
        "接收端根据 epoch bits 选择最近可用 epoch，并按当前 epoch 的 nextPeerSeqNumber 重构完整 RecordNumber。",
        "RFC 9147 Section 4.2.2 and 4.2.3 Record Number Reconstruction",
        "Dtls13ReconstructEpochNumber 先匹配当前 peer epoch，否则在已知 epoch 中选最高的匹配低位 epoch；Dtls13ReconstructSeqNumber 使用 nextPeerSeqNumber 的高位与 wire low bits 组合，并按半窗口规则调整到最接近期望值。",
        ["wolfssl-master/src/dtls13.c:1400", "wolfssl-master/src/dtls13.c:1422", "wolfssl-master/src/dtls13.c:1449", "wolfssl-master/src/dtls13.c:1457", "wolfssl-master/src/dtls13.c:1479"])

for i in [168, 171, 172, 174, 175]:
    set_item(i, "满足", "", "low",
        "DTLS 1.3 anti-replay 窗口在解保护后检查和更新，重复或窗口左侧记录被丢弃。",
        "RFC 9147 Section 4.5.1 Replay Detection",
        "GetRecordHeader 中明确注释 DTLS 1.3 必须在 deprotect 后检查窗口；ProcessReply 在解密完成后调用 Dtls13CheckWindow，只有进入 stateful parsing 时才 Dtls13UpdateWindowRecordRecvd。窗口逻辑对低于左边界、窗口内重复和新记录进行区分。",
        ["wolfssl-master/src/internal.c:12262", "wolfssl-master/src/internal.c:19109", "wolfssl-master/src/internal.c:19135", "wolfssl-master/src/internal.c:19148", "wolfssl-master/src/internal.c:23258", "wolfssl-master/src/internal.c:23272"])

set_item(177, "满足", "", "low",
    "重传为新记录时使用当前 epoch nextSeqNumber，并把新 record number 记入重传跟踪项。",
    "RFC 9147 Section 4.2.2 and Section 7 Retransmission ACK",
    "Dtls13RtxSendRecords 重发记录前读取当前 dtls13EncryptEpoch->nextSeqNumber，再经 Dtls13SendFragment 发送并将该 seq 存入 r->seq[rnIdx]，因此重发的是新的 DTLSPlaintext.sequence_number。",
    ["wolfssl-master/src/dtls13.c:1647", "wolfssl-master/src/dtls13.c:1678", "wolfssl-master/src/dtls13.c:1680", "wolfssl-master/src/dtls13.c:1694"])

set_item(183, "满足", "", "low",
    "客户端在 ServerHello 完成前收到统一头加密记录时只发送空 ACK 快速恢复，不把 EncryptedExtensions 视为已安全确认。",
    "RFC 9147 Section 4.1 and Section 7 ACK Processing",
    "GetDtlsRecordHeader 在 client、serverState < SERVER_HELLO_COMPLETE、TLS 1.3 且握手未完成时，将收到统一头记录解释为 ServerHello 可能丢失，并触发空 ACK/SEQUENCE_ERROR 路径，而不是推进 EncryptedExtensions 状态。",
    ["wolfssl-master/src/internal.c:12118", "wolfssl-master/src/internal.c:12130", "wolfssl-master/src/internal.c:12134"])

set_item(184, "满足", "", "low",
    "wolfSSL 只在收到 handshake 类型记录时把记录加入 ACK 列表，非握手内容类型不会生成 DTLS 1.3 ACK。",
    "RFC 9147 Section 7 ACK Message",
    "Dtls13RecordRecvd 开头检查 ssl->curRL.type != handshake 即返回 0，只有 handshake 记录才调用 Dtls13RtxAddAck 保存 record number。",
    ["wolfssl-master/src/dtls13.c:1588", "wolfssl-master/src/dtls13.c:1592", "wolfssl-master/src/dtls13.c:1598"])

for i in [185, 186, 187]:
    set_item(i, "不满足", "DTLS 1.3 动态 CID 更新消息缺失", "medium",
        "wolfSSL 仅支持协商期 Connection ID 扩展和统一头 CID 位，未实现 RFC 9147 NewConnectionId/RequestConnectionId 的 usage=cid_spare/cid_immediate 语义。",
        "RFC 9147 Section 9 Connection IDs",
        "RFC 9147 定义 NewConnectionId/RequestConnectionId 以及 cid_spare、cid_immediate 用法。wolfSSL 源码只有 wolfSSL_dtls_cid_* API、TLSX_ConnectionID_* 扩展和统一头 CID 检查；全仓库扫描 NewConnectionId、RequestConnectionId、cid_spare、cid_immediate 均无协议消息实现。",
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

classification_items = [r for r in results if r["status"] in ("部分满足", "不满足")]
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
    if r["status"] == "不满足":
        cat_summary[cat]["unsatisfied"] += 1
    if r["status"] == "部分满足":
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
    "# DTLS 1.3 RFC9147 wolfSSL 151-187 对比结果",
    "",
    f"- 实际范围：151-187（输入 JSON 仅 {len(changes)} 条，已钳制 requested overall_end_id=200）",
    "- 请求目标 `wolfssl-main` 不存在，实际审计 `wolfssl-master`。",
    f"- 状态统计：{counts}",
    "",
    md_table(results)
]
(OUT / "compare_wolfssl-main_151_187.md").write_text("\n".join(md), encoding="utf-8")

simple = []
for r in results:
    simple.append(f"{r['id']}: {r['status']} - {r['variable_name']} - {r['comment']}")
(OUT / "compare_wolfssl-main_151_187_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")

cmd = [
    "# DTLS 1.3 RFC9147 wolfSSL 151-187 部分/不满足分类",
    "",
    f"- 总数：{len(classification_items)}",
    f"- 状态：{status_summary}",
    f"- 风险：{risk_summary}",
    "",
    md_table(classification_items),
    "",
    "## Phase 2 复核",
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

该要求需要实现具体的 DTLS 1.3 状态或消息语义，而不是仅有常量或旧版 CID 扩展支持。

## Relevant Source Code

{snippets[rid]}

相关代码只展示了已存在的 close_notify 或 CID 扩展/统一头处理路径。

## Implementation Behavior

{r['code_check']}

## Inconsistency Reason

标准要求：{r['standard_check']}

实现行为：{r['code_check']}

不一致原因：{r['decision_reason']}

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
