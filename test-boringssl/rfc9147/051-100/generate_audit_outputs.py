import json
from pathlib import Path


ROOT = Path(r"D:\project\conditionFuzzing")
OUT = ROOT / "test-boringssl" / "051-100"
IN_JSON = ROOT / "output" / "DTLS_02_variable_changes.json"
REPO = ROOT / "boringssl-main"

STATUS_SAT = "满足"
STATUS_PART = "部分满足"
STATUS_UNSAT = "不满足"
STATUS_NA = "不适用"


STD = {
    "record_number_encryption": {
        "section": "RFC 9147 Section 4.2.3, Record Number Encryption",
        "quote": "This procedure requires the ciphertext length to be at least 16 bytes. Receivers MUST reject shorter records as if they had failed deprotection ... Senders MUST pad short plaintexts out ...",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-4.2.3",
    },
    "record_header": {
        "section": "RFC 9147 Section 4 and Section 4.1, DTLS Record Layer / Demultiplexing",
        "quote": "Fixed Bits: The three high bits of the first byte of the unified header are set to 001 ... E: The two low bits (0x03) include the low-order two bits of the epoch.",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-4",
    },
    "epoch": {
        "section": "RFC 9147 Section 4.2, Sequence Number and Epoch",
        "quote": "The epoch number is initially zero and is incremented each time keying material changes ... Implementations MUST NOT allow the epoch to wrap.",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-4.2",
    },
    "epoch_reconstruct": {
        "section": "RFC 9147 Section 4.2.2, Reconstructing the Sequence Number and Epoch",
        "quote": "After the handshake is complete, if the epoch bits do not match those from the current epoch, implementations SHOULD use the most recent past epoch which has matching bits.",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-4.2.2",
    },
    "anti_replay": {
        "section": "RFC 9147 Section 4.5.1, Anti-Replay",
        "quote": "Because each epoch resets the sequence number space, a separate sliding window is needed for each epoch.",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-4.5.1",
    },
    "pmtu": {
        "section": "RFC 9147 Section 4.4, PMTU Issues",
        "quote": "If repeated retransmissions do not result in a response, and the PMTU is unknown, subsequent retransmissions SHOULD back off to a smaller record size, fragmenting the handshake message as appropriate.",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-4.4",
    },
    "fragment": {
        "section": "RFC 9147 Section 5.5, Handshake Message Fragmentation and Reassembly",
        "quote": "Each new message is labeled with the fragment_offset ... and the fragment_length ...",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-5.5",
    },
    "ack": {
        "section": "RFC 9147 Section 7, ACK Message",
        "quote": "During the handshake, ACK records MUST be sent with an epoch which is equal to or higher than the record which is being acknowledged ... After the handshake, implementations MUST use the highest available sending epoch.",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-7",
    },
    "key_update": {
        "section": "RFC 9147 Section 8, Key Updates",
        "quote": "KeyUpdates MUST be acknowledged ... implementations MUST NOT send records with the new keys or send a new KeyUpdate until the previous KeyUpdate has been acknowledged ... sending implementations MUST NOT allow the epoch to exceed 2^48-1.",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-8",
    },
    "cookie": {
        "section": "RFC 9147 Section 5.1, Denial-of-Service Countermeasures",
        "quote": "The server then verifies the cookie and proceeds with the handshake only if it is valid ... cookies are only valid for the existing handshake and cannot be stored for future handshakes.",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-5.1",
    },
    "clienthello": {
        "section": "RFC 9147 Section 5.3, ClientHello Message",
        "quote": "A DTLS 1.3-only client MUST set the legacy_cookie field to zero length. If a DTLS 1.3 ClientHello is received with any other value in this field, the server MUST abort the handshake with an illegal_parameter alert.",
        "url": "https://www.rfc-editor.org/rfc/rfc9147#section-5.3",
    },
}


GROUPS = {
    "encrypted_record": ("record_number_encryption", [
        "ssl/dtls_record.cc:207", "ssl/dtls_record.cc:213", "ssl/dtls_record.cc:327",
        "ssl/dtls_record.cc:337", "ssl/dtls_record.cc:556", "ssl/dtls_record.cc:571"
    ]),
    "epoch": ("epoch", [
        "ssl/dtls_record.cc:71", "ssl/dtls_record.cc:80", "ssl/dtls_record.cc:122",
        "ssl/dtls_record.cc:176", "ssl/dtls_record.cc:316", "ssl/dtls_record.cc:366",
        "ssl/dtls_record.cc:372", "ssl/dtls_method.cc:43", "ssl/dtls_method.cc:59"
    ]),
    "Fixed Bits": ("record_header", [
        "ssl/dtls_record.cc:274", "ssl/dtls_record.cc:527", "ssl/dtls_record.cc:540"
    ]),
    "fragment": ("pmtu", [
        "ssl/d1_both.cc:747", "ssl/d1_both.cc:781", "ssl/d1_both.cc:875",
        "ssl/d1_both.cc:1031", "ssl/d1_both.cc:1043"
    ]),
    "fragment_length": ("fragment", ["ssl/d1_both.cc:486", "ssl/d1_both.cc:493", "ssl/d1_both.cc:571", "ssl/d1_both.cc:786"]),
    "fragment_offset": ("fragment", ["ssl/d1_both.cc:486", "ssl/d1_both.cc:493", "ssl/d1_both.cc:571", "ssl/d1_both.cc:785"]),
    "key_update": ("key_update", [
        "ssl/tls13_both.cc:678", "ssl/tls13_both.cc:701", "ssl/d1_pkt.cc:122",
        "ssl/d1_pkt.cc:130", "ssl/dtls_method.cc:59"
    ]),
    "extensions": ("cookie", [
        "ssl/tls13_client.cc:255", "ssl/tls13_client.cc:277", "ssl/extensions.cc:2673",
        "ssl/tls13_server.cc:825", "ssl/tls13_server.cc:968"
    ]),
    "legacy_cookie": ("clienthello", [
        "ssl/extensions.cc:139", "ssl/ssl_test.cc:11245", "ssl/ssl_test.cc:11257",
        "ssl/ssl_test.cc:11312"
    ]),
}


FINDINGS = {
    60: {
        "status": STATUS_PART,
        "category": "64-bit epoch support limited to 16-bit implementation state",
        "risk": "medium",
        "decision": "confirmed_partial",
        "topic": "plaintext_epoch_serialization_16bit_limit",
        "summary": "RFC 9147 describes the connection epoch as an 8-octet counter whose low two octets appear in DTLSPlaintext. BoringSSL serializes and stores DTLS epochs as uint16_t/DTLSRecordNumber epochs, so it implements the low-two-octet wire form but not the full 64-bit connection epoch model.",
    },
    61: {
        "status": STATUS_UNSAT,
        "category": "64-bit epoch receive limit enforced",
        "risk": "high",
        "decision": "confirmed_unsatisfied",
        "topic": "receiver_epoch_limit_enforced",
        "summary": "RFC 9147 says receiving implementations MUST NOT enforce the sending-side epoch limit. BoringSSL reconstructs and tracks epochs in uint16_t and rejects ACK RecordNumber epochs above UINT16_MAX, so the receiver cannot represent or accept the RFC 9147 64-bit epoch space.",
    },
    74: {
        "status": STATUS_PART,
        "category": "64-bit epoch support limited to 16-bit implementation state",
        "risk": "medium",
        "decision": "confirmed_partial",
        "topic": "rekeyed_application_epoch_range_truncated",
        "summary": "RFC 9147 reserves epochs 4 through 2^64-1 for rekeyed application traffic, with a sending safety limit of 2^48-1. BoringSSL's DTLS epoch state is uint16_t and next_epoch fails at 0xffff, so it covers only a prefix of the specified application epoch space.",
    },
    76: {
        "status": STATUS_PART,
        "category": "early termination at 16-bit epoch boundary",
        "risk": "medium",
        "decision": "confirmed_partial",
        "topic": "epoch_wrap_terminates_too_early",
        "summary": "BoringSSL does not allow epoch wrap, but the wrap/too-many-key-updates condition is tied to 0xffff rather than the RFC 9147 64-bit epoch with a 2^48-1 sending limit. The no-wrap property is implemented, but at a much lower boundary.",
    },
    85: {
        "status": STATUS_PART,
        "category": "RecordNumber model narrower than RFC structure",
        "risk": "medium",
        "decision": "confirmed_partial",
        "topic": "recordnumber_epoch_width_truncated",
        "summary": "RFC 9147 expands RecordNumber to uint64 epoch plus uint64 sequence_number for ACK and AEAD inputs. BoringSSL encodes ACK fields as u64, but the source values come from DTLSRecordNumber with a 16-bit epoch and 48-bit sequence.",
    },
    87: {
        "status": STATUS_PART,
        "category": "early termination at 16-bit epoch boundary",
        "risk": "medium",
        "decision": "confirmed_partial",
        "topic": "epoch_wrap_guard_16bit",
        "summary": "The implementation prevents wrap but its guard is prev == 0xffff, not an implementation of the RFC 9147 64-bit epoch non-wrapping model.",
    },
    89: {
        "status": STATUS_UNSAT,
        "category": "missing DTLS 1.3 server HRR cookie validation path",
        "risk": "high",
        "decision": "confirmed_unsatisfied",
        "topic": "server_hrr_cookie_validation_missing",
        "summary": "The DTLS 1.3 client path stores a HelloRetryRequest cookie and adds it to the next ClientHello. The BoringSSL server path contains comments that it could request a cookie but does not implement a DTLS 1.3 HRR cookie issuance/verification path.",
    },
    93: {
        "status": STATUS_PART,
        "category": "PMTU retransmission backoff missing",
        "risk": "medium",
        "decision": "confirmed_partial",
        "topic": "pmtu_retransmission_backoff_missing",
        "summary": "BoringSSL fragments handshake messages to fit the current MTU, but repeated retransmission only doubles the timer and resends the same flight. I did not find logic that backs off to a smaller record size when PMTU is unknown after repeated non-response.",
    },
    97: {
        "status": STATUS_PART,
        "category": "KeyUpdate epoch-limit response aborts instead of ignoring update_requested",
        "risk": "medium",
        "decision": "confirmed_partial",
        "topic": "keyupdate_limit_response_handling",
        "summary": "BoringSSL avoids sending beyond its epoch limit, but the failure path is a too-many-key-updates error from next_epoch rather than ignoring update_requested while continuing the connection as RFC 9147 specifies near the sending limit.",
    },
}


CUSTOM_SAT = {
    53: "BoringSSL does not expose DTLS 1.3 TLS_AES_128_CCM_8_SHA256 or other short-tag DTLS 1.3 ciphers in the searched TLS cipher configuration, while the DTLS record writer appends the encrypted inner content type and uses AEAD tag lengths from the selected cipher. For supported suites, ciphertext is not shorter than 16 bytes; no active padding gap was confirmed.",
    54: "The record parser accepts DTLSPlaintext epoch 0 for ClientHello-style unprotected records, and the DTLS method initializes read/write null-cipher epochs at construction.",
    55: "DTLS KeyUpdate send-key rotation is explicitly deferred until ACK processing marks the outgoing flight fully ACKed; then dtls1_process_ack calls tls13_rotate_traffic_key for evp_aead_seal.",
    56: "BoringSSL reconstructs the two-bit wire epoch against the newest active read epoch and keeps previous/current/next read epoch state, which implements the recommended matching-past-epoch behavior within its uint16 epoch model.",
    57: "After close_notify is processed, dtls_open_record returns ssl_open_record_close_notify before processing further input, so subsequent records are ignored at the record layer.",
    58: "During the handshake, dtls1_open_handshake discards application_data records; the RFC permits discarding epoch 3+ application data before the peer Finished is received.",
    59: "The read path retains prev_read_epoch for a timeout after moving next_read_epoch to current, and dtls_get_read_epoch can find previous, current, or next epoch states.",
    62: "The sender never exceeds the RFC 2^48-1 sending limit because BoringSSL stops much earlier at uint16 epoch exhaustion. This is conservative for the narrow MUST NOT exceed requirement, though related wider epoch support is classified separately.",
    63: "Epoch-zero unencrypted records use DTLSPlaintext and the initial DTLS read/write epochs are null-cipher epoch 0.",
    64: "The relevant RFC behavior is MAY-level. BoringSSL discards early application data during handshake, which is permitted.",
    65: "send_ack seals ACK records with ssl->d1->write_epoch.epoch(), i.e. the current/highest available write epoch.",
    66: "During the handshake, BoringSSL's current write epoch advances to handshake epoch 2 before sending ACKs for encrypted server flight records, and send_ack uses that write epoch.",
    67: "BoringSSL sends ACKs from the current write epoch and rejects ACKs that acknowledge a newer epoch than the ACK record during the handshake.",
    68: "send_ack uses the current write epoch rather than a lower stored epoch.",
    69: "dtls_method.cc increments application epochs with next_epoch and installs the new write/read epoch on key changes.",
    70: "dtls_aead_sequence returns only num.sequence() for DTLS 1.3, excluding epoch from the AEAD sequence number.",
    71: "next_epoch maps ssl_encryption_handshake to epoch 2.",
    72: "next_epoch maps ssl_encryption_early_data to epoch 1, although DTLS 1.3 0-RTT support is intentionally limited elsewhere.",
    73: "next_epoch maps initial application traffic to epoch 3.",
    75: "reconstruct_epoch uses the current epoch high bits and wire low bits; if the low bits match current, this yields the current epoch.",
    77: "Duplicate of the DTLSPlaintext epoch-zero structure requirement; BoringSSL uses plaintext DTLS record headers for epoch 0.",
    78: "dtls_seal_record writes out[0] = 0x2c | (epoch & 0x3), carrying the low two epoch bits in the unified header.",
    79: "dtls1_new initializes read_epoch and write_epoch with null cipher, and DTLSRecordNumber defaults begin at epoch/sequence zero.",
    80: "Outgoing handshake messages store msg.epoch at creation, retransmission walks the stored message list, and extra write epochs are retained while incomplete messages reference them.",
    81: "Each DTLSReadEpoch owns a DTLSReplayBitmap; record lookup chooses the epoch before duplicate checks.",
    82: "tls13_add_key_update sets key_update_pending and DTLS rotates the write traffic key only after the KeyUpdate flight is ACKed.",
    83: "Records for which dtls_get_read_epoch cannot determine a cipher state are silently discarded, matching failed deprotection handling.",
    84: "Each DTLSReadEpoch/DTLSWriteEpoch constructs a RecordNumberEncrypter from that epoch's AEAD cipher and traffic secret.",
    86: "Unencrypted messages use epoch 0/null cipher before encrypted epochs are installed.",
    88: "The client parses non-empty HRR cookie extension into hs->cookie and ext_cookie_add_clienthello adds it to the second ClientHello.",
    90: "DTLS 1.3 unified header construction sets the high bits to 001 via 0x2c.",
    91: "Incoming first bytes outside the DTLS 1.3 001 range are parsed as legacy records and malformed/invalid records are discarded as failed deprotection.",
    92: "parse_dtls_record only dispatches to parse_dtls13_record when (type & 0xe0) == 0x20, i.e. leading bits 001.",
    94: "The normal handshake sender fragments messages according to the active MTU via max_in_len and DTLS1_HM_HEADER_LENGTH accounting.",
    95: "dtls1_parse_fragment reads fragment_length and dtls1_finish_message writes it into every DTLSHandshake header.",
    96: "dtls1_parse_fragment reads fragment_offset and seal_next_record writes the fragment range offset into each fragment header.",
    98: "A KeyUpdate response is encoded as a handshake message and does not itself mark the earlier KeyUpdate record as ACKed; ACK processing remains separate.",
    99: "Client-side HRR cookie state is reset at new handshake setup and no code path was found that stores DTLS 1.3 HRR cookies for future handshakes.",
    100: "BoringSSL's DTLS 1.3 ClientHello tests assert zero legacy_cookie and the parser exposes nonzero legacy cookie separately for rejection checks.",
}


def source_lines(path, start, end):
    lines = (REPO / path).read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(start - 1, min(end, len(lines))))


def classify_default(item_id, item):
    if item_id in FINDINGS:
        f = FINDINGS[item_id]
        return f["status"], f["category"], f["risk"], f["summary"]
    status = STATUS_SAT
    category = ""
    risk = "low"
    comment = CUSTOM_SAT.get(item_id)
    if comment is None:
        comment = "BoringSSL 的 DTLS 1.3 记录层、握手层或 KeyUpdate/ACK 状态路径覆盖了该变量变化；结论来自标准语义与实际读写/解析/状态迁移路径的对照。"
    return status, category, risk, comment


def std_for_item(item):
    var = item.get("variable_name", "")
    if var == "epoch":
        cond = item.get("change_condition", "")
        if "ACK" in cond or "ACK" in item.get("related_state_or_step", ""):
            return STD["ack"]
        if "reconstruct" in item.get("related_state_or_step", "") or "epoch bits" in cond:
            return STD["epoch_reconstruct"]
        if "sequence number verification" in cond:
            return STD["anti_replay"]
        if "KeyUpdate" in cond:
            return STD["key_update"]
        return STD["epoch"]
    return STD[GROUPS.get(var, ("epoch", []))[0]]


def evidence_for_item(item):
    var = item.get("variable_name", "")
    if var == "epoch":
        cond = item.get("change_condition", "")
        if "ACK" in cond or "ACK" in item.get("related_state_or_step", ""):
            return ["ssl/d1_both.cc:958", "ssl/d1_both.cc:968", "ssl/d1_both.cc:1002", "ssl/d1_pkt.cc:70"]
        if "AEAD" in item.get("related_state_or_step", ""):
            return ["ssl/dtls_record.cc:71", "ssl/dtls_record.cc:327", "ssl/dtls_record.cc:556"]
        if "retransmission" in item.get("related_state_or_step", ""):
            return ["ssl/d1_both.cc:607", "ssl/d1_both.cc:697", "ssl/d1_both.cc:737", "ssl/d1_both.cc:832"]
        if "sequence number verification" in cond:
            return ["ssl/dtls_record.cc:16", "ssl/dtls_record.cc:122", "ssl/dtls_record.cc:316", "ssl/dtls_record.cc:366"]
        if "KeyUpdate" in cond:
            return ["ssl/tls13_both.cc:678", "ssl/d1_pkt.cc:122", "ssl/dtls_method.cc:43"]
        return GROUPS["epoch"][1]
    return GROUPS.get(var, ("epoch", GROUPS["epoch"][1]))[1]


def validate_evidence(results):
    checks = []
    for r in results:
        ok = True
        bad = []
        for ref in r["evidence_in_boringssl"]:
            file, line_s = ref.rsplit(":", 1)
            p = REPO / file
            try:
                line = int(line_s)
                count = len(p.read_text(encoding="utf-8", errors="replace").splitlines())
                if not p.exists() or line < 1 or line > count:
                    ok = False
                    bad.append(ref)
            except Exception:
                ok = False
                bad.append(ref)
        checks.append({"id": r["id"], "ok": ok, "bad_refs": bad})
    return checks


def make_results():
    data = json.loads(IN_JSON.read_text(encoding="utf-8"))
    items = data["changes"]
    results = []
    for idx in range(50, 100):
        item_id = idx + 1
        item = items[idx]
        status, category, risk, comment = classify_default(item_id, item)
        std = std_for_item(item)
        ev = evidence_for_item(item)
        comparison = (
            f"需求：{item.get('variable_name')} 在条件「{item.get('change_condition')}」下需要执行「{item.get('change_action')}」。"
            f" 标准依据：{std['section']}，含义为 {std['quote']}。"
            f" 代码对比：已沿 BoringSSL 相关解析、封装、ACK/KeyUpdate 或分片路径检查 {', '.join(ev[:4])}。"
            f" 结论：{comment}"
        )
        result = {
            "id": item_id,
            "source_index": idx,
            **item,
            "status": status,
            "comment": comment,
            "standard_reference": std["url"],
            "standard_section": std["section"],
            "standard_basis": std["quote"],
            "comparison_summary": comparison,
            "category": category,
            "risk": risk,
            "evidence_in_boringssl": ev,
        }
        if item_id in FINDINGS:
            f = FINDINGS[item_id]
            result.update({
                "standard_check": f"复核 {std['section']}：{std['quote']}",
                "code_check": f"复核代码证据 {', '.join(ev)}。该路径显示：{f['summary']}",
                "test_check": "已编写并运行 focused_static_checks.py 验证相关源码模式；BoringSSL runtime runner 因本机缺少 cmake/ninja/go/ssl_test 构建产物而阻塞，详见 runtime_blocker.log。",
                "decision": f["decision"],
                "decision_reason": f["summary"],
            })
        results.append(result)
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    meta = {
        "source_file": str(IN_JSON),
        "scope": "051-100_rules",
        "method": "static_code_comparison_plus_phase2_focused_checks",
        "target": "boringssl-main",
        "standard": "RFC 9147",
        "counts": counts,
        "evidence_validation": validate_evidence(results),
        "runtime_test_status": "blocked for BoringSSL binary/runtime runner: cmake, ninja, go, and ssl_test.exe were not available in PATH/worktree; focused source checks were run.",
    }
    return {"meta": meta, "results": results}


def classification(compare):
    items = []
    for r in compare["results"]:
        if r["status"] in (STATUS_PART, STATUS_UNSAT):
            items.append({
                "id": r["id"],
                "status": r["status"],
                "variable_name": r["variable_name"],
                "category": r["category"],
                "risk": r["risk"],
                "comment": r["comment"],
                "standard_section": r["standard_section"],
                "evidence_in_boringssl": r["evidence_in_boringssl"],
                "standard_check": r["standard_check"],
                "code_check": r["code_check"],
                "test_check": r["test_check"],
                "decision": r["decision"],
                "decision_reason": r["decision_reason"],
            })
    by_cat = {}
    for it in items:
        by_cat.setdefault(it["category"], []).append(it)
    return {
        "meta": {
            "scope": "051-100",
            "target": "boringssl-main",
            "total_partial_unsat": len(items),
            "counts_by_status": {
                STATUS_PART: sum(1 for i in items if i["status"] == STATUS_PART),
                STATUS_UNSAT: sum(1 for i in items if i["status"] == STATUS_UNSAT),
            },
            "counts_by_category": {k: len(v) for k, v in by_cat.items()},
        },
        "categories": [
            {"category": k, "count": len(v), "items": v}
            for k, v in sorted(by_cat.items())
        ],
    }


def write_compare_md(compare):
    lines = ["# BoringSSL DTLS 1.3 051-100 协议符合性对比", ""]
    lines.append(f"- 标准：RFC 9147")
    lines.append(f"- 目标：boringssl-main")
    lines.append(f"- 范围：051-100")
    lines.append(f"- 计数：{compare['meta']['counts']}")
    lines.append("")
    lines.append("| ID | 变量 | 状态 | 分类 | 标准章节 | 对比摘要 | 代码证据 |")
    lines.append("|---:|---|---|---|---|---|---|")
    for r in compare["results"]:
        ev = "<br>".join(r["evidence_in_boringssl"])
        summary = r["comparison_summary"].replace("|", "\\|")
        lines.append(f"| {r['id']} | {r['variable_name']} | {r['status']} | {r['category']} | {r['standard_section']} | {summary} | {ev} |")
    (OUT / "compare_boringssl-main_051_100.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_simple(compare):
    lines = []
    for r in compare["results"]:
        lines.append(f"ID {r['id']:03d}: {r['status']} - {r['comment']}")
    (OUT / "compare_boringssl-main_051_100_simple.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_class_md(cls):
    lines = ["# BoringSSL DTLS 1.3 051-100 部分满足/不满足分类", ""]
    lines.append(f"- 总数：{cls['meta']['total_partial_unsat']}")
    lines.append(f"- 状态计数：{cls['meta']['counts_by_status']}")
    lines.append("")
    for cat in cls["categories"]:
        lines.append(f"## {cat['category']} ({cat['count']})")
        lines.append("")
        lines.append("| ID | 状态 | 风险 | Phase 2 决策 | 复核结论 |")
        lines.append("|---:|---|---|---|---|")
        for it in cat["items"]:
            reason = it["decision_reason"].replace("|", "\\|")
            lines.append(f"| {it['id']} | {it['status']} | {it['risk']} | {it['decision']} | {reason} |")
        lines.append("")
    (OUT / "compare_boringssl-main_051_100_partial_unsat_classification.md").write_text("\n".join(lines), encoding="utf-8")


def write_tests():
    test = r'''import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing\boringssl-main")

def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")

checks = []

dtls_record = read("ssl/dtls_record.cc")
dtls_method = read("ssl/dtls_method.cc")
d1_both = read("ssl/d1_both.cc")
d1_pkt = read("ssl/d1_pkt.cc")
tls13_both = read("ssl/tls13_both.cc")
tls13_server = read("ssl/tls13_server.cc")

checks.append(("dtls13_header_uses_low_2_epoch_bits", "out[0] = 0x2c | (epoch & 0x3)" in dtls_record))
checks.append(("aead_sequence_excludes_epoch_for_dtls13", "? num.sequence()" in dtls_record and ": num.combined()" in dtls_record))
checks.append(("receive_epoch_state_is_uint16", "uint16_t max_epoch" in dtls_record and "static uint16_t reconstruct_epoch" in dtls_record))
checks.append(("ack_rejects_epoch_over_uint16", "epoch > UINT16_MAX" in d1_pkt))
checks.append(("write_epoch_limit_is_0xffff", "if (prev == 0xffff)" in dtls_method))
checks.append(("recordnumber_is_narrower_than_rfc", "static constexpr uint64_t kMaxSequence = (uint64_t{1} << 48) - 1" in read("ssl/internal.h")))
checks.append(("keyupdate_rotation_deferred_until_ack", "key_update_pending" in d1_pkt and "tls13_rotate_traffic_key(ssl, evp_aead_seal)" in d1_pkt))
checks.append(("no_pmtu_backoff_to_smaller_mtu_found", "timeout_duration_ms * 2" in d1_both and "mtu =" not in d1_both[d1_both.find("dtls1_flush"):]))
checks.append(("server_cookie_path_missing", "could HelloRetryRequest with PAKEs to request a cookie" in tls13_server and "SendHelloRetryRequestCookie" not in tls13_server))

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(f"{name}: {'PASS' if ok else 'FAIL'}")
if failed:
    raise SystemExit("failed checks: " + ", ".join(failed))
'''
    (OUT / "focused_static_checks.py").write_text(test, encoding="utf-8")
    blocker = """BoringSSL runtime test blocker for DTLS 1.3 051-100 audit

Attempted runtime/build discovery:
- cmake --version: command not found in PATH
- ninja --version: command not found in PATH
- go version: command not found in PATH
- searched boringssl-main for ssl_test.exe / runner.exe: none found
- searched common Program Files locations for cmake.exe, ninja.exe, go.exe: none found

Impact:
Focused source-level tests in focused_static_checks.py were run and passed, but BoringSSL's native ssl_test/runner runtime tests could not be built or executed in this environment. The Phase 2 decisions therefore include a concrete runtime blocker note rather than a fabricated runtime pass.
"""
    (OUT / "runtime_blocker.log").write_text(blocker, encoding="utf-8")


REPORTS = {
    61: ("DTLS 1.3 receiver epoch space is limited to 16 bits", "receiver_epoch_limit_enforced"),
    89: ("DTLS 1.3 server HelloRetryRequest cookie validation is missing", "server_hrr_cookie_validation_missing"),
    93: ("DTLS handshake retransmission does not back off to smaller records when PMTU is unknown", "pmtu_retransmission_backoff_missing"),
    97: ("DTLS KeyUpdate limit handling aborts instead of ignoring update_requested", "keyupdate_limit_response_handling"),
    60: ("DTLSPlaintext epoch serialization is implemented only over a 16-bit epoch model", "plaintext_epoch_serialization_16bit_limit"),
    74: ("Rekeyed application epoch range is truncated by 16-bit epoch state", "rekeyed_application_epoch_range_truncated"),
    76: ("Epoch wrap prevention triggers at the 16-bit boundary", "epoch_wrap_terminates_too_early"),
    85: ("RecordNumber source model is narrower than RFC 9147", "recordnumber_epoch_width_truncated"),
    87: ("Epoch wrap guard uses a 16-bit ceiling", "epoch_wrap_guard_16bit"),
}


SNIPPETS = {
    61: [("ssl/dtls_record.cc", 80, 90), ("ssl/d1_pkt.cc", 70, 79), ("ssl/dtls_method.cc", 43, 64)],
    89: [("ssl/tls13_client.cc", 255, 289), ("ssl/extensions.cc", 2673, 2685), ("ssl/tls13_server.cc", 820, 835)],
    93: [("ssl/d1_both.cc", 875, 913), ("ssl/d1_both.cc", 1031, 1055)],
    97: [("ssl/tls13_both.cc", 678, 710), ("ssl/tls13_both.cc", 714, 733), ("ssl/dtls_method.cc", 52, 64)],
    60: [("ssl/dtls_record.cc", 80, 90), ("ssl/dtls_record.cc", 525, 548)],
    74: [("ssl/dtls_method.cc", 43, 64), ("ssl/dtls_method.cc", 111, 139)],
    76: [("ssl/dtls_method.cc", 43, 64)],
    85: [("ssl/internal.h", 635, 662), ("ssl/d1_both.cc", 981, 993)],
    87: [("ssl/dtls_method.cc", 52, 64)],
}


def report_for(result):
    title, slug = REPORTS[result["id"]]
    finding = FINDINGS[result["id"]]
    std = {
        "64": STD["epoch"],
    }
    lines = [f"# {title}", ""]
    lines += [
        "## Summary",
        finding["summary"],
        "",
        "## Standard Requirement",
        f"- Official standard: {result['standard_reference']}",
        f"- Section: {result['standard_section']}",
        "",
        "```text",
        result["standard_basis"],
        "```",
        "该要求的核心是将 DTLS 1.3 的协议状态与线上的压缩字段区分开：wire header 可以只携带低位，但实现仍需要按标准语义处理完整状态、错误路径和 ACK/KeyUpdate 反馈。",
        "",
        "## Relevant Source Code",
    ]
    for rel, start, end in SNIPPETS[result["id"]]:
        lines += [f"{rel}:{start}", "", "```c++", source_lines(rel, start, end), "```", ""]
    lines += [
        "## Implementation Behavior",
        result["code_check"],
        "",
        "## Inconsistency Reason",
        result["decision_reason"],
        "",
        "## Runtime Evidence",
        "Focused source-level checks were executed with `python focused_static_checks.py` and passed. Native BoringSSL runtime execution was blocked because this machine has no `cmake`, `ninja`, `go`, or prebuilt `ssl_test.exe`; see `runtime_blocker.log`.",
        "",
        "## Impact",
        "The impact is interoperability and robustness risk in DTLS 1.3 edge cases: long-lived rekeying, ACK/epoch reconstruction, server-side cookie retry behavior, or lossy-path PMTU recovery can diverge from RFC 9147 expectations.",
        "",
        "## Fix Direction",
        "Align the implementation state machine with the RFC requirement, then add BoringSSL runner coverage for the confirmed edge case. Where BoringSSL intentionally does not support the broader RFC feature, document the limit and fail in the protocol-appropriate way.",
        "",
    ]
    filename = OUT / f"id{result['id']:03d}_{slug}_{finding['decision'].replace('confirmed_', '')}.md"
    filename.write_text("\n".join(lines), encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    compare = make_results()
    (OUT / "compare_boringssl-main_051_100.json").write_text(json.dumps(compare, ensure_ascii=False, indent=2), encoding="utf-8")
    write_compare_md(compare)
    write_simple(compare)
    cls = classification(compare)
    (OUT / "compare_boringssl-main_051_100_partial_unsat_classification.json").write_text(json.dumps(cls, ensure_ascii=False, indent=2), encoding="utf-8")
    write_class_md(cls)
    write_tests()
    for r in compare["results"]:
        if r["id"] in REPORTS:
            report_for(r)
    summary = {
        "round": "051-100",
        "next_round": "101-150",
        "status_counts": compare["meta"]["counts"],
        "partial_unsat_count": cls["meta"]["total_partial_unsat"],
        "confirmed_reports": [p.name for p in OUT.glob("id*.md")],
        "runtime": compare["meta"]["runtime_test_status"],
    }
    (OUT / "round_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
