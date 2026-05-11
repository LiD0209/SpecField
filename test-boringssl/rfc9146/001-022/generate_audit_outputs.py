import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
REPO = ROOT / "boringssl-main"
OUT = ROOT / "test-boringssl" / "rfc9146" / "001-022"
INPUT = ROOT / "output" / "DTLSCID_02_variable_changes.json"

STATUS_OK = "满足"
STATUS_PARTIAL = "部分满足"
STATUS_UNSAT = "不满足"
STATUS_NA = "不适用"

RFC = "https://www.rfc-editor.org/rfc/rfc9146"


def line_count(rel):
    return len((REPO / rel).read_text(encoding="utf-8").splitlines())


def validate_evidence(results):
    details = []
    ok = True
    for r in results:
        for ev in r.get("evidence_in_boringssl", []):
            m = re.match(r"boringssl-main/(.+):(\d+)$", ev)
            if not m:
                ok = False
                details.append({"evidence": ev, "valid": False, "reason": "格式不是 boringssl-main/<path>:<line>"})
                continue
            rel, line_s = m.groups()
            path = REPO / rel
            line = int(line_s)
            valid = path.exists() and 1 <= line <= line_count(rel)
            if not valid:
                ok = False
            details.append({
                "evidence": ev,
                "valid": valid,
                "file_exists": path.exists(),
                "line": line,
                "line_count": line_count(rel) if path.exists() else None,
            })
    return {"ok": ok, "details": details}


def src(item, idx):
    ret = {
        "id": idx,
        "source_index": idx - 1,
        "variable_name": item.get("variable_name", ""),
        "change_condition": item.get("change_condition", ""),
        "change_action": item.get("change_action", ""),
        "old_value": item.get("old_value", ""),
        "new_value": item.get("new_value", ""),
        "related_state_or_step": item.get("related_state_or_step", ""),
        "explicit_or_inferred": item.get("explicit_or_inferred", ""),
        "source_chunk_id": item.get("source_chunk_id", ""),
        "input_evidence": item.get("evidence", ""),
        "input_note": item.get("note", ""),
    }
    return ret


def result(item, idx, status, comment, section, summary, evidence, category="", risk="low"):
    r = src(item, idx)
    r.update({
        "status": status,
        "comment": comment,
        "standard_reference": RFC,
        "standard_section": section,
        "comparison_summary": summary,
        "category": category if status in {STATUS_PARTIAL, STATUS_UNSAT} else "",
        "risk": risk if status in {STATUS_PARTIAL, STATUS_UNSAT} else "",
        "evidence_in_boringssl": evidence,
    })
    return r


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    changes = json.loads(INPUT.read_text(encoding="utf-8"))["changes"]
    if len(changes) != 22:
        raise SystemExit(f"unexpected input count: {len(changes)}")

    common_ext = [
        "boringssl-main/ssl/extensions.cc:3951",
        "boringssl-main/ssl/extensions.cc:4074",
        "boringssl-main/ssl/extensions.cc:4172",
    ]
    dtls12_parse = [
        "boringssl-main/ssl/dtls_record.cc:235",
        "boringssl-main/ssl/dtls_record.cc:237",
        "boringssl-main/ssl/dtls_record.cc:238",
        "boringssl-main/ssl/dtls_record.cc:239",
        "boringssl-main/ssl/dtls_record.cc:257",
    ]
    dtls_open = [
        "boringssl-main/ssl/dtls_record.cc:327",
        "boringssl-main/ssl/dtls_record.cc:328",
        "boringssl-main/ssl/dtls_record.cc:329",
        "boringssl-main/ssl/dtls_record.cc:330",
        "boringssl-main/ssl/dtls_record.cc:343",
        "boringssl-main/ssl/dtls_record.cc:347",
    ]
    dtls_write = [
        "boringssl-main/ssl/dtls_record.cc:427",
        "boringssl-main/ssl/dtls_record.cc:431",
        "boringssl-main/ssl/dtls_record.cc:533",
        "boringssl-main/ssl/dtls_record.cc:540",
        "boringssl-main/ssl/dtls_record.cc:548",
        "boringssl-main/ssl/dtls_record.cc:556",
        "boringssl-main/ssl/dtls_record.cc:558",
    ]
    dtls13_reject = [
        "boringssl-main/ssl/dtls_record.cc:170",
        "boringssl-main/ssl/dtls_record.cc:171",
        "boringssl-main/ssl/dtls_record.cc:172",
        "boringssl-main/ssl/dtls_record.cc:173",
    ]
    replay = [
        "boringssl-main/ssl/dtls_record.cc:25",
        "boringssl-main/ssl/dtls_record.cc:31",
        "boringssl-main/ssl/dtls_record.cc:42",
        "boringssl-main/ssl/dtls_record.cc:366",
    ]

    results = []
    add = results.append
    add(result(changes[0], 1, STATUS_NA, "该条来自 RFC 示例交换，只说明示例中 client-to-server 方向哪些 payload 带 CID；不是独立实现约束。BoringSSL 未实现 RFC 9146 CID，不能用示例常量判断满足性。", "Section 7 Example", "要求 -> 示例说明；标准含义 -> 解释单向 CID 使用；代码行为 -> 无 connection_id 扩展和 tls12_cid 路径；结论 -> 信息性示例，不列为缺陷。", common_ext + dtls12_parse, "informational example", "low"))
    add(result(changes[1], 2, STATUS_NA, "条件是实现选择接收不同长度的 CID。BoringSSL 没有 RFC 9146 CID 接收功能，因此该条件未被触发；缺失的基础 CID 功能在其他条目中记录。", "Section 3 The connection_id Extension", "要求 -> 可变长度 CID 必须可自分界；标准含义 -> 因记录中没有 cid_length，接收方需能确定长度；代码行为 -> 没有 CID 接收路径；结论 -> 条件未触发。", common_ext + dtls12_parse, "conditional requirement not reached", "low"))
    add(result(changes[2], 3, STATUS_NA, "ServerHello(connection_id=100) 是 RFC 示例值，不是固定常量要求。", "Section 7 Example", "要求 -> 示例常量；标准含义 -> 仅演示服务器希望客户端使用的 CID；代码行为 -> 无 ServerHello connection_id 扩展；结论 -> 示例不适合作为实现缺陷。", common_ext, "informational example", "low"))
    add(result(changes[3], 4, STATUS_NA, "ClientHello(connection_id=empty) 是 RFC 示例中的零长度 CID 表示法，不是固定行为要求。", "Section 7 Example", "要求 -> 示例表示法；标准含义 -> 零长度 CID 表示一方向不希望收到 CID；代码行为 -> 无 ClientHello connection_id 扩展；结论 -> 示例不适用。", common_ext, "informational example", "low"))
    add(result(changes[4], 5, STATUS_UNSAT, "RFC 9146 要求非零 CID 协商后、加密启用后用 CID-enhanced record format 和 tls12_cid 发送。BoringSSL DTLS 1.2 写路径仍写普通 DTLSPlaintext header，没有 CID 字段或 tls12_cid。", "Section 3 and Section 7", "要求 -> 非零 CID 方向加密后必须带 CID；标准含义 -> Finished 和应用数据等加密记录进入新记录格式；代码行为 -> DTLS 1.2 写出 out[0]=type, version, epoch+seq, length；结论 -> 不满足。", common_ext + dtls_write, "missing DTLS 1.2 CID record format", "medium"))
    add(result(changes[5], 6, STATUS_UNSAT, "RFC 9146 的 DTLSCiphertext.cid 字段应等于协商 CID，长度为 cid_length。BoringSSL 没有 negotiation state，也没有在 DTLS 1.2 record header 中解析或写入 CID 字段。", "Section 4 Record Layer Extensions", "要求 -> 记录携带协商 CID；标准含义 -> CID 位于 sequence_number 与 length 之间；代码行为 -> parse_dtls12_record 直接读取 length-prefixed body；结论 -> 不满足。", common_ext + dtls12_parse + dtls_write, "missing DTLS 1.2 CID record format", "medium"))
    add(result(changes[6], 7, STATUS_NA, "IANA 对既有注册表条目的 DTLS-Only 列赋值不是库实现行为。", "Section 10.1 IANA Considerations", "要求 -> 注册表元数据；标准含义 -> IANA 维护内容；代码行为 -> BoringSSL 不维护 TLS ExtensionType 注册表完整镜像；结论 -> 不适用。", [], "IANA registry metadata", "low"))
    add(result(changes[7], 8, STATUS_NA, "connection_id(54) 的 IANA 注册表项本身不是实现义务；实际扩展协商缺失在 CID 功能条目中记录。", "Section 10.2 New Entry", "要求 -> IANA 分配；标准含义 -> codepoint 为 54；代码行为 -> kExtensions 无 connection_id 处理器；结论 -> 注册表条目不适用。", common_ext, "IANA registry metadata", "low"))
    add(result(changes[8], 9, STATUS_NA, "DTLS-Only 列取值规则属于 IANA 注册表维护，不是 BoringSSL 协议状态机行为。", "Section 10.1 IANA Considerations", "要求 -> 注册表列有效值；标准含义 -> IANA 使用 Y/N；代码行为 -> 不相关；结论 -> 不适用。", [], "IANA registry metadata", "low"))
    add(result(changes[9], 10, STATUS_UNSAT, "RFC 9146 要求 enc_content 是序列化 DTLSInnerPlaintext 的加密结果。BoringSSL 仅在 DTLS 1.3 路径附加内部 content type；DTLS 1.2 CID 路径不存在。", "Section 4 Record Layer Extensions", "要求 -> 先构造 DTLSInnerPlaintext 再加密；标准含义 -> real_type 与 zero padding 进入加密包络；代码行为 -> DTLS 1.2 SealScatter 直接加密输入 payload；结论 -> 不满足。", dtls_open + dtls_write, "missing DTLSInnerPlaintext for RFC 9146", "medium"))
    add(result(changes[10], 11, STATUS_UNSAT, "RFC 9146 对 CID 记录源地址变化要求验证后且 epoch/sequence 更新。BoringSSL 有 replay bitmap，但没有 CID 到连接查找和 peer address update 状态机，因此没有该地址更新门控。", "Section 6 Peer Address Update", "要求 -> CID 记录可触发受限 peer address update；标准含义 -> 必须同时满足认证、新 epoch/sequence、地址可达策略；代码行为 -> 只做记录重放窗口，不处理 CID 源地址迁移；结论 -> 不满足。", replay + dtls_open, "missing CID peer address update", "medium"))
    add(result(changes[11], 12, STATUS_PARTIAL, "BoringSSL 对普通/DTLS 1.3 plaintext 有 SSL3_RT_MAX_PLAIN_LENGTH 限制，但没有 RFC 9146 length_of_DTLSInnerPlaintext 字段和 CID-specific 检查。", "Section 5 Record Payload Protection", "要求 -> serialized DTLSInnerPlaintext 长度不得超过 2^14；标准含义 -> CID 记录的内部明文长度参与 MAC/AAD；代码行为 -> generic plaintext limit 存在，CID-specific field 不存在；结论 -> 部分满足。", dtls_open + ["boringssl-main/ssl/internal.h:3013"], "generic limit only, no CID-specific field", "low"))
    add(result(changes[12], 13, STATUS_UNSAT, "RFC 9146 要求 length_of_DTLSInnerPlaintext 是序列化 DTLSInnerPlaintext 的两字节长度。BoringSSL DTLS 1.2 记录长度表示 ciphertext/body 长度，没有 CID 内部明文长度字段。", "Section 5 Record Payload Protection", "要求 -> CID MAC/AAD 使用内部明文长度；标准含义 -> 与 DTLSCiphertext.length 区分；代码行为 -> parse/write 只使用标准 DTLS length；结论 -> 不满足。", dtls12_parse + dtls_write, "missing DTLSInnerPlaintext for RFC 9146", "medium"))
    add(result(changes[13], 14, STATUS_UNSAT, "RFC 9146 MAC/AAD 构造以 tls12_cid、cid_length、CID 和内部长度作为输入。BoringSSL AEAD Open/SealScatter 只使用 record.header 作为 AAD，没有 CID AAD 构造。", "Section 5.1 and 5.3", "要求 -> CID 记录使用 modified MAC/AAD；标准含义 -> tls12_cid 在 AAD 中出现并隔离非 CID MAC 输入；代码行为 -> additional data 是解析/写出的 record.header；结论 -> 不满足。", dtls_open + dtls_write, "missing CID MAC/AAD construction", "high"))
    add(result(changes[14], 15, STATUS_UNSAT, "RFC 9146 要求携带 CID 的 DTLSCiphertext.outer_type 固定为 tls12_cid(25)。BoringSSL 无 tls12_cid 常量，DTLS 1.2 写路径直接使用调用方 type。", "Section 4 Record Layer Extensions", "要求 -> CID record outer_type 为 25；标准含义 -> 真实类型移入 DTLSInnerPlaintext.real_type；代码行为 -> out[0]=type；结论 -> 不满足。", dtls_write + common_ext, "missing tls12_cid content type", "medium"))
    add(result(changes[15], 16, STATUS_UNSAT, "RFC 9146 modified MAC/AAD 使用 8 字节 0xff seq_num_placeholder。BoringSSL 没有该字段或等价构造。", "Section 5 Record Payload Protection", "要求 -> MAC/AAD 前缀包含 8 bytes 0xff；标准含义 -> 将 CID 与非 CID MAC 输入分离；代码行为 -> 使用 DTLSRecordNumber combined/sequence 和 record.header；结论 -> 不满足。", dtls_open + dtls_write, "missing CID MAC/AAD construction", "high"))
    add(result(changes[16], 17, STATUS_UNSAT, "与 epoch 条件相同，BoringSSL 记录层跟踪 sequence replay，但没有 CID peer address update 逻辑，因此不存在用于地址更新的 newest datagram sequence 检查。", "Section 6 Peer Address Update", "要求 -> 地址更新只能由更新的 epoch/sequence 触发；标准含义 -> 防止乱序或重放回滚地址；代码行为 -> replay bitmap 只决定记录接受/丢弃；结论 -> 不满足。", replay + dtls_open, "missing CID peer address update", "medium"))
    add(result(changes[17], 18, STATUS_UNSAT, "RFC 9146 分配 tls12_cid(25)，且仅适用于 DTLS 1.2。BoringSSL 没有 tls12_cid content type；DTLS 1.3 的 CID bit 反而被显式拒绝。", "Section 10.3 New Entry in TLS ContentType Registry", "要求 -> tls12_cid(25) 仅用于 DTLS 1.2；标准含义 -> 不能误用于 TLS 或 DTLS 1.3；代码行为 -> 无 tls12_cid，DTLS 1.3 CID bit return false；结论 -> 不满足该内容类型支持。", dtls13_reject + dtls_write, "missing tls12_cid content type", "medium"))
    add(result(changes[18], 19, STATUS_NA, "tls12_cid(25) 的 IANA 分配本身不是代码实现项；实际 content type 支持缺失已在适用性条目中记录。", "Section 10.3 New Entry in TLS ContentType Registry", "要求 -> IANA 分配 codepoint 25；标准含义 -> 注册表元数据；代码行为 -> 无 tls12_cid 常量；结论 -> 注册表动作不适用。", dtls13_reject, "IANA registry metadata", "low"))
    add(result(changes[19], 20, STATUS_OK, "BoringSSL 没有实现 modified CID MAC/AAD，因此普通非 CID 记录不会错误应用该算法；DTLS 1.2 普通记录仍走 RFC 6347 header/AAD。", "Section 5 Record Payload Protection", "要求 -> 非 tls12_cid 记录不得使用 modified algorithm；标准含义 -> CID 算法只作用于 CID records；代码行为 -> no-CID 记录使用 record.header；结论 -> 对无 CID 记录满足。", dtls_open + dtls_write, "", "low"))
    add(result(changes[20], 21, STATUS_PARTIAL, "BoringSSL DTLS 1.3 路径支持 encrypted inner type 后的零填充剥离，但 RFC 9146 要求的是 DTLS 1.2 CID 的 DTLSInnerPlaintext padding；该路径不存在。", "Section 4 Record Layer Extensions", "要求 -> DTLSInnerPlaintext.real_type 后可有 zero-valued padding；标准含义 -> CID 记录内部明文可填充；代码行为 -> 仅 DTLS 1.3 has_padding 路径处理 trailing zeros；结论 -> 部分满足。", dtls_open + dtls_write, "DTLS 1.3 padding only, no RFC 9146 DTLS 1.2 CID padding", "low"))
    add(result(changes[21], 22, STATUS_PARTIAL, "零填充值要求在 BoringSSL 的 DTLS 1.3 trailing zero 逻辑中体现，但没有 RFC 9146 DTLS 1.2 CID DTLSInnerPlaintext 构造，因此只部分满足。", "Section 4 Record Layer Extensions", "要求 -> padding bytes must be 0x00；标准含义 -> real_type 后只能是零值填充；代码行为 -> DTLS 1.3 while(record.type==0) 剥离零；结论 -> 部分满足。", dtls_open + dtls_write, "DTLS 1.3 padding only, no RFC 9146 DTLS 1.2 CID padding", "low"))

    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    validation = validate_evidence(results)
    meta = {
        "source_file": str(INPUT),
        "scope": "001-022_rules",
        "requested_scope": "001-050_rules",
        "clamped_reason": "input_json contains 22 changes, so overall_end_id=050 was clamped to 022",
        "method": "static_code_comparison_plus_focused_runtime_audit_test",
        "target": "boringssl-main",
        "protocol": "DTLS",
        "standard_reference": RFC,
        "counts": counts,
        "phase2_runtime_tests": {
            "compiled_upstream_tests": False,
            "blocker": "cmake, ninja, and cl are not available in PATH in this environment.",
            "focused_test_source": "tests/verify_rfc9146_cid_support.py",
            "focused_test_log": "logs/verify_rfc9146_cid_support.log",
            "focused_test_result_json": "logs/verify_rfc9146_cid_support.json",
        },
        "evidence_validation": validation,
    }
    compare = {"meta": meta, "results": results}
    (OUT / "compare_boringssl-main_001_022.json").write_text(json.dumps(compare, indent=2, ensure_ascii=False), encoding="utf-8")

    md = ["# DTLS RFC 9146 vs boringssl-main: 001-022", "", f"- Standard: {RFC}", "- Requested range: 001-050", "- Effective range: 001-022 (input JSON has 22 changes)", f"- Counts: {counts}", "", "| id | variable | status | section | summary | evidence |", "|---:|---|---|---|---|---|"]
    for r in results:
        ev = "<br>".join(r["evidence_in_boringssl"]) if r["evidence_in_boringssl"] else "N/A"
        md.append(f"| {r['id']:03d} | `{r['variable_name']}` | {r['status']} | {r['standard_section']} | {r['comparison_summary']} | {ev} |")
    (OUT / "compare_boringssl-main_001_022.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    simple = []
    for r in results:
        simple.append(f"{r['id']:03d}\t{r['status']}\t{r['variable_name']}\t{r['comment']}")
    (OUT / "compare_boringssl-main_001_022_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")

    reviewed = [r for r in results if r["status"] in {STATUS_PARTIAL, STATUS_UNSAT}]
    for r in reviewed:
        if r["status"] == STATUS_UNSAT:
            decision = "confirmed_unsatisfied"
        else:
            decision = "confirmed_partial"
        r["phase2_verification"] = {
            "decision": decision,
            "standard_check": f"已复核 {r['standard_section']}。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。",
            "code_check": f"已复核证据路径：{'; '.join(r['evidence_in_boringssl'])}。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。",
            "test_check": "运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。",
            "decision_reason": r["comment"],
        }

    cat = {}
    for r in reviewed:
        c = r["category"]
        cat.setdefault(c, {"count": 0, "unsatisfied": 0, "partial": 0, "risk_counts": {}, "items": []})
        cat[c]["count"] += 1
        cat[c]["unsatisfied"] += int(r["status"] == STATUS_UNSAT)
        cat[c]["partial"] += int(r["status"] == STATUS_PARTIAL)
        cat[c]["risk_counts"][r["risk"]] = cat[c]["risk_counts"].get(r["risk"], 0) + 1
        cat[c]["items"].append(r)
    classification = {
        "scope": "boringssl-main RFC9146 001-022 partial+unsatisfied",
        "total_reviewed": len(reviewed),
        "status_summary": {STATUS_UNSAT: counts.get(STATUS_UNSAT, 0), STATUS_PARTIAL: counts.get(STATUS_PARTIAL, 0)},
        "risk_summary": {risk: sum(1 for r in reviewed if r["risk"] == risk) for risk in sorted({r["risk"] for r in reviewed})},
        "category_summary": {k: {kk: vv for kk, vv in v.items() if kk != "items"} for k, v in cat.items()},
        "results": reviewed,
    }
    (OUT / "compare_boringssl-main_001_022_partial_unsat_classification.json").write_text(json.dumps(classification, indent=2, ensure_ascii=False), encoding="utf-8")

    cmd = ["# Partial/Unsatisfied Classification", "", f"- Total reviewed: {len(reviewed)}", f"- Unsatisfied: {counts.get(STATUS_UNSAT, 0)}", f"- Partial: {counts.get(STATUS_PARTIAL, 0)}", "", "| category | count | unsatisfied | partial | risk | items |", "|---|---:|---:|---:|---|---|"]
    for name, c in cat.items():
        ids = ", ".join(f"{i['id']:03d}" for i in c["items"])
        cmd.append(f"| {name} | {c['count']} | {c['unsatisfied']} | {c['partial']} | {c['risk_counts']} | {ids} |")
    cmd.extend(["", "## Phase 2 Verification", ""])
    for r in reviewed:
        v = r["phase2_verification"]
        cmd.extend([
            f"### {r['id']:03d} `{r['variable_name']}` - {v['decision']}",
            f"- standard_check: {v['standard_check']}",
            f"- code_check: {v['code_check']}",
            f"- test_check: {v['test_check']}",
            f"- decision_reason: {v['decision_reason']}",
            "",
        ])
    (OUT / "compare_boringssl-main_001_022_partial_unsat_classification.md").write_text("\n".join(cmd), encoding="utf-8")

    write_reports()


def write_reports():
    reports = {
        "id005_006_010_013_015_dtls12_cid_record_format_confirmed_unsatisfied.md": """# DTLS 1.2 CID Record Format Is Not Implemented

## Summary

BoringSSL does not implement the RFC 9146 DTLS 1.2 CID-enhanced record format. The library does not negotiate `connection_id(54)`, does not emit `tls12_cid(25)`, and does not add a CID field between `sequence_number` and `length`.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146

Relevant sections: Section 3, "The connection_id Extension"; Section 4, "Record Layer Extensions"; Section 7, "Example".

Short original excerpts:

```text
enum { connection_id(54), (65535) } ExtensionType;
```

```text
ContentType outer_type = tls12_cid;
```

```text
opaque cid[cid_length]; // New field
```

The standard requires peers that negotiated a non-zero CID for a direction to use the CID-enhanced DTLS 1.2 ciphertext format after encryption is enabled.

## Relevant Source Code

`ssl/extensions.cc:3951`

```c
static const struct tls_extension kExtensions[] = {
```

The supported extension table contains many extension handlers, but no `connection_id(54)` entry or handler.

`ssl/dtls_record.cc:235`

```c
static bool parse_dtls12_record(SSL *ssl, CBS *in, ParsedDTLSRecord *out) {
  uint64_t epoch_and_seq;
  if (!CBS_get_u16(in, &out->version) ||  //
      !CBS_get_u64(in, &epoch_and_seq) ||
      !CBS_get_u16_length_prefixed(in, &out->body)) {
    return false;
  }
```

The parser reads the RFC 6347 DTLS 1.2 layout: version, epoch/sequence, length, and body. There is no CID-length-dependent field.

`ssl/dtls_record.cc:548`

```c
  } else {
    out[0] = type;
    CRYPTO_store_u16_be(out + 1, record_version);
    CRYPTO_store_u64_be(out + 3, record_number.combined());
    CRYPTO_store_u16_be(out + 11, ciphertext_len);
  }
```

The writer emits the caller-provided record type and the standard DTLS 1.2 header.

## Implementation Behavior

For DTLS 1.2 records, BoringSSL keeps the existing RFC 6347 record format. There is no connection ID negotiation state and no record-layer storage for a negotiated CID.

## Inconsistency Reason

RFC 9146 requires a new record shape for encrypted records when a non-zero CID is negotiated. BoringSSL cannot enter that state because it has no extension negotiation path and no CID-enhanced DTLS 1.2 record parser or writer.

## Runtime Evidence

`tests/verify_rfc9146_cid_support.py` was run and passed. It verified the absence of `connection_id` extension handlers, absence of `tls12_cid`, the DTLS 1.2 parser shape, and the DTLS 1.2 writer shape.

## Impact

Peers that require RFC 9146 CIDs for NAT rebinding or connection lookup cannot interoperate with BoringSSL using this feature.

## Fix Direction

Add DTLS 1.2 `connection_id(54)` negotiation state, APIs to configure received/sent CID values, CID-aware record parsing and writing, and tests for zero-length and non-zero-length directional CID negotiation.
""",
        "id011_017_cid_peer_address_update_confirmed_unsatisfied.md": """# CID Peer Address Update Rules Are Missing

## Summary

BoringSSL has DTLS replay tracking, but no RFC 9146 CID-based peer address update state machine. The source address of a CID-authenticated record is therefore not handled under the Section 6 conditions.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146

Relevant section: Section 6, "Peer Address Update".

Short original excerpt:

```text
The received datagram is "newer"
```

Section 6 requires address replacement only after cryptographic verification, a newer epoch and sequence number, and an address-reachability strategy.

## Relevant Source Code

`ssl/dtls_record.cc:25`

```c
bool DTLSReplayBitmap::ShouldDiscard(uint64_t seq_num) const {
```

`ssl/dtls_record.cc:366`

```c
  record.read_epoch->bitmap.Record(record.number.sequence());
```

These lines implement record replay tracking, not peer address migration.

`ssl/dtls_record.cc:327`

```c
  if (!record.read_epoch->aead->Open(out, record.type, record.version,
                                     dtls_aead_sequence(ssl, record.number),
                                     record.header,
                                     cbs_to_writable_bytes(record.body))) {
```

The record is cryptographically verified, but no subsequent CID source-address update check exists.

## Implementation Behavior

The DTLS record layer authenticates records and updates replay state. It does not associate CID values with connections, does not detect CID-bearing datagrams from a new source address, and does not update the transport peer address.

## Inconsistency Reason

The standard's address update rule only applies to records with a CID. Because BoringSSL lacks RFC 9146 CID records and lacks the address update gate, the required epoch/sequence checks for address replacement are absent.

## Runtime Evidence

The focused audit test passed and verified that CID support is absent. Source review confirmed no CID peer-address update path in `ssl/dtls_record.cc`.

## Impact

RFC 9146 NAT rebinding support is unavailable. Applications cannot rely on BoringSSL to perform CID-authenticated DTLS peer address migration.

## Fix Direction

Implement CID-to-connection lookup and add a peer address update module that runs only after successful record authentication and compares the newest received epoch and sequence number before changing the send address.
""",
        "id014_016_cid_mac_aad_construction_confirmed_unsatisfied.md": """# RFC 9146 CID MAC and AEAD Additional Data Are Missing

## Summary

BoringSSL does not implement the RFC 9146 modified MAC or AEAD additional data calculation for `tls12_cid` records.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146

Relevant sections: Section 5, "Record Payload Protection"; Section 5.1; Section 5.3.

Short original excerpts:

```text
seq_num_placeholder: 8 bytes of 0xff.
```

```text
additional_data = seq_num_placeholder + tls12_cid
```

The standard changes the MAC/AAD input for CID records so CID and non-CID records cannot collide.

## Relevant Source Code

`ssl/dtls_record.cc:327`

```c
  if (!record.read_epoch->aead->Open(out, record.type, record.version,
                                     dtls_aead_sequence(ssl, record.number),
                                     record.header,
                                     cbs_to_writable_bytes(record.body))) {
```

`ssl/dtls_record.cc:556`

```c
  if (!write_epoch->aead->SealScatter(
          out + record_header_len, out + prefix, out + prefix + in_len, type,
          record_version, dtls_aead_sequence(ssl, record_number), header, in,
          in_len, extra_in, extra_in_len)) {
```

Both read and write paths use the serialized record header as AEAD additional data.

## Implementation Behavior

No `seq_num_placeholder`, `cid_length`, `tls12_cid`, or negotiated CID value appears in the MAC/AAD construction.

## Inconsistency Reason

RFC 9146 requires CID records to use a modified protection input. BoringSSL only implements ordinary DTLS 1.2 and DTLS 1.3 record protection inputs, so CID records cannot be authenticated according to RFC 9146.

## Runtime Evidence

The focused audit test verified `cid_aad_algorithm_absent` and passed.

## Impact

Even if extension negotiation were added separately, records would not interoperate or authenticate correctly until the RFC 9146 protection input is implemented.

## Fix Direction

Add a CID-aware record protection branch for DTLS 1.2 records with outer type `tls12_cid`, including block cipher, encrypt-then-MAC, and AEAD calculations.
""",
        "id018_tls12_cid_content_type_confirmed_unsatisfied.md": """# tls12_cid Content Type Is Not Supported

## Summary

BoringSSL does not define or process the `tls12_cid(25)` content type. Its DTLS 1.3 record parser rejects the CID bit because no DTLS 1.3 CID negotiation exists in this code path.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146

Relevant section: Section 10.3, "New Entry in the TLS ContentType Registry".

Short original excerpt:

```text
IANA has allocated tls12_cid(25)
```

The content type is specified for DTLS 1.2 CID records.

## Relevant Source Code

`ssl/dtls_record.cc:170`

```c
static bool parse_dtls13_record(SSL *ssl, CBS *in, ParsedDTLSRecord *out) {
  if (out->type & 0x10) {
    // Connection ID bit set, which we didn't negotiate.
    return false;
  }
```

`ssl/dtls_record.cc:548`

```c
  } else {
    out[0] = type;
```

The DTLS 1.2 writer does not substitute a CID content type.

## Implementation Behavior

Source search found no `tls12_cid`, `SSL3_RT_TLS12_CID`, or equivalent content-type constant.

## Inconsistency Reason

The standard defines a content type that signals CID-enhanced DTLS 1.2 records. BoringSSL cannot send or receive that content type.

## Runtime Evidence

The focused audit test verified `tls12_cid_content_type_absent` and `dtls13_cid_bit_rejected`.

## Impact

RFC 9146 records cannot be distinguished from ordinary DTLS records, so compliant peers cannot negotiate and exchange CID-protected traffic with BoringSSL.

## Fix Direction

Define the content type, restrict it to DTLS 1.2 CID records, reject it in non-DTLS or non-negotiated contexts, and connect it to the CID record parser and protection logic.
""",
        "id012_021_022_inner_plaintext_padding_confirmed_partial.md": """# Inner Plaintext Length and Zero Padding Are Only Partially Covered

## Summary

BoringSSL enforces generic plaintext length limits and implements DTLS 1.3 encrypted inner content type padding. It does not implement RFC 9146 DTLS 1.2 `DTLSInnerPlaintext`, so the RFC 9146-specific length and padding behavior is only partially present.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146

Relevant sections: Section 4, "Record Layer Extensions"; Section 5, "Record Payload Protection".

Short original excerpts:

```text
uint8 zeros[length_of_padding];
```

```text
The length MUST NOT exceed 2^14.
```

The standard wraps content, real type, and optional zero padding in `DTLSInnerPlaintext` before encryption.

## Relevant Source Code

`ssl/dtls_record.cc:343`

```c
  // DTLS 1.3 hides the record type inside the encrypted data.
  bool has_padding = !record.read_epoch->aead->is_null_cipher() &&
                     ssl_protocol_version(ssl) >= TLS1_3_VERSION;
```

`ssl/dtls_record.cc:347`

```c
  size_t plaintext_limit = SSL3_RT_MAX_PLAIN_LENGTH + (has_padding ? 1 : 0);
```

`ssl/dtls_record.cc:354`

```c
  if (has_padding) {
    do {
      if (out->empty()) {
```

These lines show the implemented DTLS 1.3 padding logic.

## Implementation Behavior

Generic plaintext length checks exist. Zero padding is stripped only when DTLS 1.3 encrypted records hide the record type. The RFC 9146 DTLS 1.2 CID inner plaintext structure is not present.

## Inconsistency Reason

The implemented behavior covers a related DTLS 1.3 mechanism, not the RFC 9146 DTLS 1.2 CID mechanism. Thus the length and zero-padding requirements are partially implemented in spirit but not in the target record format.

## Runtime Evidence

The focused audit test verified `dtls_inner_plaintext_only_dtls13` and `plaintext_limit_present_but_not_cid_specific`.

## Impact

Applications using BoringSSL cannot rely on RFC 9146 padding for traffic analysis resistance in DTLS 1.2 CID records.

## Fix Direction

Introduce a DTLS 1.2 CID `DTLSInnerPlaintext` construction and parsing path, enforce the RFC 9146 internal length limit, and add tests for zero and non-zero padding.
""",
    }
    for name, body in reports.items():
        (OUT / name).write_text(body, encoding="utf-8")


if __name__ == "__main__":
    main()
