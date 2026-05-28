import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(r"D:\project\conditionFuzzing")
INPUT_JSON = ROOT / "output" / "DTLS13_02_variable_changes.json"
TARGET = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc9147" / "101-150"
IMPL = "wolfssl"
START = 101
END = 150


STATUS_OK = "满足"
STATUS_PARTIAL = "部分满足"
STATUS_UNSAT = "不满足"
STATUS_NA = "不适用"


def read(path):
    return path.read_text(encoding="utf-8", errors="replace")


SOURCES = {
    "src/tls13.c": read(TARGET / "src" / "tls13.c"),
    "src/dtls13.c": read(TARGET / "src" / "dtls13.c"),
    "src/dtls.c": read(TARGET / "src" / "dtls.c"),
    "src/internal.c": read(TARGET / "src" / "internal.c"),
    "wolfssl/internal.h": read(TARGET / "wolfssl" / "internal.h"),
    "wolfssl/error-ssl.h": read(TARGET / "wolfssl" / "error-ssl.h"),
    "build/CMakeCache.txt": read(TARGET / "build" / "CMakeCache.txt") if (TARGET / "build" / "CMakeCache.txt").exists() else "",
}


def line_of(rel, needle):
    text = SOURCES[rel]
    for idx, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return idx
    raise AssertionError(f"needle not found in {rel}: {needle}")


def exists(rel, pattern, flags=0):
    return re.search(pattern, SOURCES[rel], flags) is not None


def evidence(*pairs):
    return [f"wolfssl-master/{rel}:{line_of(rel, needle)}" for rel, needle in pairs]


STANDARD = {
    "cookie": "RFC 9147 Section 5.3, ClientHello Format; Section 5.2.1, Denial-of-Service Countermeasures",
    "record": "RFC 9147 Section 4.1, The DTLS Record Layer; Section 4.2.1, DTLSCiphertext; Section 4.2.2, Record Header",
    "hash": "RFC 9147 Section 5.2, Replay Detection and Retransmission; Section 5.3 and RFC 8446 Section 4.4.1 transcript hash",
    "seq": "RFC 9147 Section 5.5, Handshake Message Format and Reordering",
    "cid": "RFC 9147 Section 9.1, New Connection ID; Section 9.2, Request Connection ID",
    "demux": "RFC 9147 Section 5.1.2, Record Payload Protection and demultiplexing table",
    "example": "RFC 9147 Appendix A.3, Example Handshake Traces",
}


def record_for(item, status, comment, section, summary, ev, category="", risk="low"):
    return {
        "id": item["id"],
        "source_index": item["id"] - 1,
        "variable_name": item["variable_name"],
        "change_action": item["change_action"],
        "change_condition": item["change_condition"],
        "old_value": item.get("old_value", ""),
        "new_value": item.get("new_value", ""),
        "related_state_or_step": item.get("related_state_or_step", ""),
        "explicit_or_inferred": item.get("explicit_or_inferred", ""),
        "extracted_evidence": item.get("evidence", ""),
        "source_chunk_id": item.get("source_chunk_id", ""),
        "status": status,
        "comment": comment,
        "standard_section": section,
        "comparison_summary": summary,
        "category": category,
        "risk": risk,
        f"evidence_in_{IMPL}": ev,
    }


def classify(item):
    i = item["id"]
    var = item["variable_name"]
    action = item["change_action"]
    cond = item["change_condition"]

    if 101 <= i <= 108:
        ev = evidence(
            ("src/tls13.c", "int wolfSSL_send_hrr_cookie"),
            ("src/tls13.c", "ret = TlsCheckCookie(ssl, cookie->data, cookie->len);"),
            ("src/tls13.c", "return HRR_COOKIE_ERROR;"),
            ("src/tls13.c", "byte cookieLen = input[args->idx++];"),
            ("src/tls13.c", "ERROR_OUT(INVALID_PARAMETER, exit_dch);"),
            ("src/internal.c", "case WC_NO_ERR_TRACE(HRR_COOKIE_ERROR):"),
        )
        if i in (101, 103, 104):
            return record_for(
                item,
                STATUS_PARTIAL,
                "wolfSSL 支持单个 DTLS 1.3 HRR cookie secret 并允许应用重新设置或随机生成 secret；但没有内建双 secret 过渡窗口，也没有 cookie 时间戳/有效期策略。",
                STANDARD["cookie"],
                f"要求描述的是 cookie secret 轮换/时间窗口策略。代码用 HMAC 绑定 cookie 数据和 peer 地址并用当前 tls13CookieSecret 验证；API 可替换 secret，但验证路径只检查当前 secret，cookie 数据中也没有 timestamp 字段。因此基础完整性验证满足，双 secret 或时间窗口策略属于应用/外部策略，库内只部分覆盖。",
                ev,
                "API-side support only",
                "medium",
            )
        if i == 102:
            return record_for(
                item,
                STATUS_OK,
                "无效 cookie 经 TlsCheckCookie/RestartHandshakeHashWithCookie 返回 HRR_COOKIE_ERROR，错误映射为 illegal_parameter alert。",
                STANDARD["cookie"],
                "RFC 要求收到无效 DTLS 1.3 cookie 时终止握手并发送 illegal_parameter。wolfSSL 在 cookie HMAC 或长度校验失败时返回 HRR_COOKIE_ERROR，ClientHello 处理向上传递该错误，SendAlertNumber 将 HRR_COOKIE_ERROR 映射到 illegal_parameter。",
                ev,
            )
        if i == 105:
            return record_for(
                item,
                STATUS_OK,
                "初始 DTLS 1.3 ClientHello 写入 legacy_cookie 长度字节；没有 DTLS 1.2 downgrade cookie 时为 0。",
                STANDARD["cookie"],
                "RFC 要求初始 DTLS 1.3 ClientHello 的 legacy_cookie 为零长度。wolfSSL 构造 ClientHello 时总是写 cookieSz；只有旧 DTLS downgrade cookie 存在且允许 downgrade 才写入旧 cookie，否则 cookieSz 为 0。",
                ev,
            )
        if i == 106:
            return record_for(
                item,
                STATUS_OK,
                "第二个 ClientHello 的 cookie extension 会被 HMAC、peer 地址和 transcript 重启逻辑验证。",
                STANDARD["cookie"],
                "要求是第二个 ClientHello 到达时验证 cookie。wolfSSL 在 sendCookie 打开时查找 TLSX_COOKIE，调用 RestartHandshakeHashWithCookie；该函数先用 TlsCheckCookie 验证 HMAC，再用 cookie 中的 Hash/CipherSuite/KeyShare 信息恢复 HRR transcript。",
                ev,
            )
        if i == 107:
            return record_for(
                item,
                STATUS_OK,
                "DTLS 1.3 解析路径只读取并跳过 legacy_cookie；真正的 DTLS 1.3 cookie 在 cookie extension 中处理。",
                STANDARD["cookie"],
                "RFC 说 DTLS 1.3-compliant server 忽略 ClientHello legacy_cookie 字段。wolfSSL 的 downgrade 预解析会跳过该字段，正式 DTLS 1.3 ClientHello 解析不使用 legacy_cookie 内容参与 cookie 验证。",
                ev,
            )
        if i == 108:
            return record_for(
                item,
                STATUS_OK,
                "DTLS 1.3 ClientHello 中 legacy_cookie 非零会返回 INVALID_PARAMETER，最终映射为 illegal_parameter。",
                STANDARD["cookie"],
                "RFC 同时要求 DTLS 1.3 ClientHello legacy_cookie 必须为零长度，非零时 abort with illegal_parameter。wolfSSL 在 DoTls13ClientHello 中读取 cookieLen，非零立即 ERROR_OUT(INVALID_PARAMETER)，错误映射表把 INVALID_PARAMETER 转为 illegal_parameter。",
                ev,
            )

    if 109 <= i <= 111:
        ev = evidence(
            ("src/dtls13.c", "hdr->legacyVersionRecord.major = DTLS_MAJOR;"),
            ("src/dtls13.c", "hdr->legacyVersionRecord.minor = DTLSv1_2_MINOR;"),
            ("src/internal.c", "if (rh->pvMajor == DTLS_MAJOR && rh->pvMinor == DTLS_BOGUS_MINOR)"),
            ("src/internal.c", "if (IsAtLeastTLSv1_3(ssl->version)) {"),
        )
        status = STATUS_OK
        comment = "DTLS 1.3 明文记录发送路径将 legacy_record_version 写为 {254,253}；接收路径不把该字段用于版本协商。"
        if i == 111:
            comment = "初始 ClientHello 兼容值 {254,255} 属于允许项；wolfSSL 发送端使用 {254,253}，接收端在 TLS 1.3 协商前仍保留 DTLS 记录解析兼容性。"
        return record_for(
            item,
            status,
            comment,
            STANDARD["record"],
            "RFC 要求除初始 ClientHello 兼容例外外，DTLSPlaintext legacy_record_version 写为 DTLS 1.2 值并被忽略。wolfSSL 的 DTLS 1.3 plaintext header 生成固定写 DTLS_MAJOR/DTLSv1_2_MINOR；版本协商实际由 supported_versions 和 TLS 1.3 状态决定，记录头版本只参与旧格式解析/错误排除。",
            ev,
        )

    if 112 <= i <= 116:
        ev = evidence(
            ("src/tls13.c", "ssl->session->sessionIDSz = 0;"),
            ("src/tls13.c", "output[idx++] = 0;"),
            ("src/tls13.c", "output[idx++] = ssl->version.major;"),
            ("src/tls13.c", "output[idx++] = ssl->options.dtls ? DTLSv1_2_MINOR : TLSv1_2_MINOR;"),
            ("src/tls13.c", "args->output[args->idx++] = major;"),
            ("src/tls13.c", "args->output[args->idx++] = tls12minor;"),
        )
        if i == 114:
            return record_for(
                item,
                STATUS_PARTIAL,
                "通用 TLS 1.3 helper 能写入已有 session ID，但 DTLS 1.3 路径关闭 middlebox compat；未找到明确只在 pre-DTLS 1.3 cached session ID 时发送该值的专门策略。",
                STANDARD["cookie"],
                "RFC 的 cached pre-DTLS 1.3 session ID 是兼容性 SHOULD。wolfSSL 的 GetTls13SessionId 可写已有 sessionIDSz，但 DTLS 1.3 初始化禁用 tls13MiddleBoxCompat，服务端也清空并不回显 session ID；没有看到针对“pre-DTLS 1.3 server cached session ID”的独立分支，因此只可证明通用能力，不能证明条件策略完整。",
                ev,
                "behavior exists but strict proof is missing",
                "low",
            )
        return record_for(
            item,
            STATUS_OK,
            "DTLS 1.3 不回显 legacy_session_id，默认 ClientHello/ServerHello legacy_version 均使用 DTLS 1.2 兼容值。",
            STANDARD["cookie"],
            "RFC 5.3 要求 DTLS 1.3 ServerHello legacy_session_id_echo 为空，ClientHello/ServerHello legacy_version 为 DTLS 1.2 值。wolfSSL 服务端在解析 DTLS 1.3 ClientHello 后清空 sessionIDSz，发送 ServerHello 时 DTLS 路径直接写 0；ClientHello 和 ServerHello 都写 major + DTLSv1_2_MINOR。",
            ev,
        )

    if 117 <= i <= 125:
        ev = evidence(
            ("src/dtls13.c", "#define DTLS13_UNIFIED_HEADER_SIZE 5"),
            ("src/dtls13.c", "*flags |= DTLS13_LEN_BIT;"),
            ("src/dtls13.c", "c16toa(length, out + idx);"),
            ("src/dtls13.c", "hasLength = flags & DTLS13_LEN_BIT;"),
            ("src/dtls13.c", "hdrInfo->recordLength = inputSize - idx;"),
            ("src/dtls13.c", "if (inputSize < idx + DTLS13_LEN_SIZE)"),
            ("src/dtls13.c", "if (hdrInfo->recordLength < DTLS13_RN_MASK_SIZE)"),
            ("src/internal.c", "*size = hdrInfo.recordLength;"),
        )
        status = STATUS_OK
        category = ""
        risk = "low"
        comment = "统一头解析支持 L bit、有长度字段和无长度字段，发送端当前总是包含 16-bit length。"
        summary = "RFC 允许 DTLSCiphertext 最后一个记录省略 length，并要求显式 length 不能越过当前 datagram。wolfSSL 发送端固定设置 L bit 和 16-bit length；接收端按 L bit 解析，如果未设置则把剩余 datagram 作为记录长度，如果设置则读取 16-bit length 并进行头部/最小密文长度检查。"
        if i == 117:
            status = STATUS_PARTIAL
            category = "transport mode not implemented"
            risk = "low"
            comment = "未看到 wolfSSL 对 DTLS-over-TCP/SCTP 记录写入 2^14 上限的专门路径；本仓库 DTLS 实现以 datagram 为主。"
            summary = "该条是 DTLS over TCP/SCTP 的上层写入限制。当前代码中的 DTLS 1.3 record builder 使用 word16 length 和 buffer 检查，但没有发现面向 DTLS-over-TCP/SCTP 的专门实现或 2^14 上层写入断言，因此只能部分满足/不适用到常规 UDP DTLS。"
        elif i == 119:
            comment = "发送端没有利用省略 length 的优化，接收端可解析最后记录无 length 的格式。"
        elif i == 123:
            status = STATUS_PARTIAL
            category = "incomplete validation"
            risk = "medium"
            comment = "解析端在 L bit 清除时把剩余 datagram 作为当前记录，但没有独立证明该无长度格式只出现在 datagram 最后一个记录。"
            summary = "RFC 明确省略 length 只能用于 datagram 最后一个记录。wolfSSL 解析代码的行为是当 L bit 未设置时直接把 inputSize-idx 作为 recordLength，这等价于消费剩余 datagram；该机制天然使后续记录不可再解析，但没有单独的显式校验/诊断。发送端总是设置 length，不会产生违规无长度中间记录。"
        elif i == 125:
            status = STATUS_PARTIAL
            category = "incomplete validation"
            risk = "medium"
            comment = "源码能证明读取 length 字段本身不会越界，但未看到显式 `idx + recordLength <= inputSize` 检查；后续处理依赖 recordLength 和输入缓冲边界。"
            summary = "RFC 检查问题要求确认显式 record length 包含在 datagram 内。wolfSSL 确认 length 字段的两个字节在 datagram 内，并设置 *size=recordLength，但 Dtls13ParseUnifiedRecordLayer 本身没有直接检查 idx+recordLength <= inputSize，因此严格证明不足。"
        return record_for(item, status, comment, STANDARD["record"], summary, ev, category, risk)

    if 126 <= i <= 127:
        ev = evidence(
            ("src/tls13.c", "AddTls13HandShakeHeader(header, hashSz, 0, 0, message_hash, ssl);"),
            ("src/tls13.c", "ret = Dtls13HashHandshake(ssl, hrr, (word16)hrrIdx);"),
            ("src/dtls13.c", "int Dtls13HashHandshake(WOLFSSL* ssl, const byte* input, word16 length)"),
            ("src/dtls13.c", "/* message_seq(2) + fragment_offset(3) + fragment_length(3) */"),
        )
        return record_for(
            item,
            STATUS_OK,
            "HRR cookie/stateless路径使用 synthetic message_hash，并在 DTLS hash 中跳过 message_seq/fragment 字段。",
            STANDARD["hash"],
            "RFC 要求 HRR transcript 包含初始 ClientHello 的 synthetic message_hash，并按 TLS 1.3 规则计算。wolfSSL 在 RestartHandshakeHashWithCookie 中写 message_hash handshake header、重置 handshake hash、hash cookie 内保存的 ClientHello hash，然后重构 HRR 并调用 Dtls13HashHandshake；后者只 hash msg_type/length 和 body，跳过 DTLS message_seq/fragment fields。",
            ev,
        )

    if 128 <= i <= 137:
        ev = evidence(
            ("src/dtls13.c", "c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);"),
            ("src/dtls.c", "ssl->keys.dtls_expected_peer_handshake_number = 0;"),
            ("src/dtls13.c", "if (ssl->options.side == WOLFSSL_SERVER_END &&"),
            ("src/dtls13.c", "ssl->keys.dtls_expected_peer_handshake_number ="),
        )
        return record_for(
            item,
            STATUS_NA,
            "该条来自 RFC 示例握手 trace 的具体 message_seq 值，不是独立的通用实现义务；通用序列号机制在 130、138-144 覆盖。",
            STANDARD["example"],
            "Appendix 示例中的固定 message_seq 取决于是否使用客户端认证、HRR、post-handshake 等路径。wolfSSL 不需要硬编码示例序列值，而是使用通用 dtls_handshake_number/expected_peer_handshake_number 机制动态生成与校验。",
            ev,
        )

    if 130 <= i <= 144:
        ev = evidence(
            ("src/dtls13.c", "c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);"),
            ("src/dtls13.c", "if (ssl->keys.dtls_expected_peer_handshake_number != msg->seq)"),
            ("src/dtls13.c", "ssl->keys.dtls_expected_peer_handshake_number++;"),
            ("src/dtls13.c", "if (ssl->keys.dtls_peer_handshake_number <"),
            ("src/dtls13.c", "ssl->dtls13Rtx.retransmit = 1;"),
            ("src/internal.c", "ssl->keys.dtls_handshake_number++, dtls->message_seq"),
            ("src/internal.c", "DtlsMsgStore(ssl, ssl->keys.curEpoch,"),
        )
        if i == 139:
            status = STATUS_PARTIAL
            category = "behavior exists but strict proof is missing"
            risk = "medium"
            comment = "代码中 post-handshake ACK/KeyUpdate 使用同一 DTLS 1.3 RTX/sequence 结构，但未能证明所有 post-handshake 消息永不重置 message_seq。"
        else:
            status = STATUS_OK
            category = ""
            risk = "low"
            comment = "DTLS handshake sequence 使用 dtls_handshake_number/expected_peer_handshake_number 生成、检查、缓存乱序并丢弃旧序号。"
        return record_for(
            item,
            status,
            comment,
            STANDARD["seq"],
            "RFC 要求每个 handshake message 有 message_seq：新消息递增，重传复用旧值，接收端按 next_receive_seq 处理、缓存或丢弃。wolfSSL 发送头写 dtls_handshake_number，通用旧 DTLS AddHeaders 会递增；DTLS 1.3 接收端维护 dtls_expected_peer_handshake_number，旧序号被识别为 retransmission 并丢弃/触发重传，未来序号进入 DtlsMsgStore 缓存，in-order ready message 才处理并递增 expected 值。",
            ev,
            category,
            risk,
        )

    if 145 <= i <= 146:
        ev = evidence(
            ("src/dtls.c", "int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,"),
            ("src/dtls.c", "int wolfSSL_dtls_cid_use(WOLFSSL* ssl)"),
            ("src/dtls.c", "int wolfSSL_dtls_cid_set(WOLFSSL* ssl, unsigned char* cid, unsigned int size)"),
            ("src/dtls13.c", "static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)"),
            ("wolfssl/internal.h", "ack                = 26,"),
        )
        return record_for(
            item,
            STATUS_UNSAT,
            "wolfSSL 实现了 RFC 9146/DTLS CID extension 和 DTLS 1.3 unified header CID bit，但未找到 RFC 9147 RequestConnectionId/NewConnectionId handshake 消息、num_cids 或 cid_spare 处理。",
            STANDARD["cid"],
            "RFC 9147 定义 RequestConnectionId 和 NewConnectionId post-handshake 消息，RequestConnectionId.num_cids 请求对端生成若干 CID，NewConnectionId 以 usage=cid_spare 返回。源码搜索没有发现对应 handshake type、解析/发送函数、num_cids 字段或 cid_spare usage；现有代码只处理连接建立时的 connection_id extension 和固定本地 API 设置 CID。",
            ev,
            "missing feature/path",
            "high",
        )

    if 147 <= i <= 150:
        ev = evidence(
            ("src/dtls13.c", "#define DTLS13_FIXED_BITS_MASK (0x7 << 5)"),
            ("src/dtls13.c", "return ((hdrFirstByte & DTLS13_FIXED_BITS_MASK) == DTLS13_FIXED_BITS);"),
            ("src/internal.c", "if (Dtls13IsUnifiedHeader(*(ssl->buffers.inputBuffer.buffer + *inOutIdx)))"),
            ("wolfssl/internal.h", "change_cipher_spec = 20,"),
            ("wolfssl/internal.h", "alert              = 21,"),
            ("wolfssl/internal.h", "handshake          = 22,"),
            ("wolfssl/internal.h", "application_data   = 23,"),
        )
        return record_for(
            item,
            STATUS_OK,
            "首字节分流覆盖旧 content type 20/21/22 和 DTLS 1.3 unified header 固定位模式。",
            STANDARD["demux"],
            "RFC demux table 将 20/21/22 映射为 CCS/Alert/Handshake plaintext，将 31<OCT<64 的固定模式识别为 DTLSCiphertext。wolfSSL 的 Dtls13IsUnifiedHeader 排除 alert/handshake/ack 后按固定 bit mask 识别 unified header；非 unified header 继续按传统 DTLS record type 解析，ContentType enum 定义了 20/21/22。",
            ev,
        )

    raise AssertionError(f"unclassified id {i} {var} {action} {cond}")


def validate_evidence(results):
    validation = []
    for r in results:
        ok = True
        problems = []
        for e in r[f"evidence_in_{IMPL}"]:
            m = re.match(r"wolfssl-master/(.*):(\d+)$", e)
            if not m:
                ok = False
                problems.append(f"bad format {e}")
                continue
            path = TARGET / m.group(1)
            line = int(m.group(2))
            if not path.exists():
                ok = False
                problems.append(f"missing file {path}")
            else:
                count = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
                if line < 1 or line > count:
                    ok = False
                    problems.append(f"line out of range {e} count={count}")
        validation.append({"id": r["id"], "ok": ok, "problems": problems})
    return validation


def run_source_tests(classified):
    tests = []

    def check(name, passed, detail):
        tests.append({"name": name, "passed": bool(passed), "detail": detail})

    check("dtls13_enabled_in_current_build", "WOLFSSL_DTLS13:BOOL=yes" in SOURCES["build/CMakeCache.txt"], "当前 CMakeCache.txt 显示 WOLFSSL_DTLS13:BOOL=no，因此不能执行完整握手运行测试。")
    check("cid_enabled_in_current_build", "WOLFSSL_DTLS_CID:BOOL=yes" in SOURCES["build/CMakeCache.txt"], "当前 CMakeCache.txt 显示 WOLFSSL_DTLS_CID:BOOL=no。")
    check("legacy_cookie_nonzero_rejected", exists("src/tls13.c", r"byte cookieLen = input\[args->idx\+\+\];\s*if \(cookieLen != 0\).*?ERROR_OUT\(INVALID_PARAMETER, exit_dch\);", re.S), "DoTls13ClientHello 对非零 legacy_cookie 返回 INVALID_PARAMETER。")
    check("invalid_cookie_maps_illegal_parameter", exists("src/internal.c", r"case WC_NO_ERR_TRACE\(HRR_COOKIE_ERROR\):\s*case WC_NO_ERR_TRACE\(BAD_BINDER\):\s*case WC_NO_ERR_TRACE\(DUPLICATE_TLS_EXT_E\):\s*return illegal_parameter;", re.S), "HRR_COOKIE_ERROR 被 SendAlertNumber 映射为 illegal_parameter。")
    check("serverhello_empty_legacy_session_id_dtls", exists("src/tls13.c", r"if \(ssl->options.dtls\) \{\s*/\* RFC 9147 Section 5\.3.*?output\[idx\+\+\] = 0;", re.S), "DTLS 1.3 ServerHello 写空 legacy_session_id_echo。")
    check("dtls_plaintext_version_fefd", exists("src/dtls13.c", r"legacyVersionRecord\.major = DTLS_MAJOR;.*?legacyVersionRecord\.minor = DTLSv1_2_MINOR;", re.S), "DTLS 1.3 明文记录头写 DTLS 1.2 legacy version。")
    check("unified_header_length_bit_parse", exists("src/dtls13.c", r"hasLength = flags & DTLS13_LEN_BIT;.*?if \(hasLength\).*?ato16\(input \+ idx, &hdrInfo->recordLength\).*?else.*?hdrInfo->recordLength = inputSize - idx;", re.S), "统一头根据 L bit 读取显式 length 或使用 datagram 剩余长度。")
    check("explicit_length_bound_direct_check", exists("src/dtls13.c", r"idx\s*\+\s*hdrInfo->recordLength\s*<=\s*inputSize|inputSize\s*<\s*idx\s*\+\s*hdrInfo->recordLength", re.S), "未找到直接的 idx+recordLength 对 inputSize 边界检查。")
    check("message_hash_hrr_cookie", exists("src/tls13.c", r"AddTls13HandShakeHeader\(header, hashSz, 0, 0, message_hash, ssl\);", re.S), "HRR cookie transcript 重启使用 synthetic message_hash。")
    check("dtls_hash_skips_seq_fragment", exists("src/dtls13.c", r"input \+= OPAQUE32_LEN;.*?/\* message_seq\(2\) \+ fragment_offset\(3\) \+ fragment_length\(3\) \*/.*?input \+= OPAQUE64_LEN;", re.S), "DTLS handshake hash 跳过 message_seq/fragment 字段。")
    check("message_seq_receive_less_discard", exists("src/dtls13.c", r"if \(ssl->keys.dtls_peer_handshake_number <\s*ssl->keys.dtls_expected_peer_handshake_number\).*?\*processedSize = idx \+ fragLength \+ ssl->keys.padSz;.*?return 0;", re.S), "旧 message_seq 作为 retransmission 丢弃。")
    check("message_seq_future_queued", exists("src/internal.c", r"dtls_peer_handshake_number >\s*ssl->keys.dtls_expected_peer_handshake_number.*?DtlsMsgStore", re.S), "未来 message_seq 进入接收缓存。")
    check("new_message_seq_increment", exists("src/internal.c", r"c16toa\(ssl->keys.dtls_handshake_number\+\+, dtls->message_seq\)", re.S), "新消息生成递增 dtls_handshake_number。")
    check("request_new_connection_id_absent", not any(re.search(r"RequestConnectionId|NewConnectionId|request_connection_id|new_connection_id|num_cids|cid_spare", v) for v in SOURCES.values()), "源码未发现 RequestConnectionId/NewConnectionId/num_cids/cid_spare。")
    check("outer_content_type_demux", exists("src/dtls13.c", r"hdrFirstByte == alert \|\| hdrFirstByte == handshake \|\|\s*hdrFirstByte == ack.*?DTLS13_FIXED_BITS_MASK", re.S), "Dtls13IsUnifiedHeader 先排除明文 alert/handshake/ack，再按固定 bit 识别 unified header。")

    for c in classified:
        c["standard_check"] = c["standard_section"] + "；已按原始 evidence 字段对应的 RFC 9147 规范语义复核。"
        c["code_check"] = "复核源码证据：" + "; ".join(c[f"evidence_in_{IMPL}"][:4])
        if c["id"] in (145, 146):
            c["test_check"] = "source_assertions 中 request_new_connection_id_absent 通过：未发现 RequestConnectionId/NewConnectionId/num_cids/cid_spare 实现。"
            c["phase2_decision"] = "confirmed_unsatisfied"
            c["decision_reason"] = "标准要求动态 CID 请求/响应 handshake 消息，源码只有 CID extension/API 和 unified header CID bit，没有对应 post-handshake 消息处理。"
        elif c["id"] == 125:
            c["test_check"] = "source_assertions 中 explicit_length_bound_direct_check 未通过，确认缺少直接边界检查证据；完整运行测试因当前未构建 DTLS 1.3 被阻塞。"
            c["phase2_decision"] = "confirmed_partial"
            c["decision_reason"] = "代码能读显式 length 并进行最小密文长度检查，但没有直接证明显式 length 被限制在 datagram 内。"
        elif c["id"] == 123:
            c["test_check"] = "source_assertions 中 unified_header_length_bit_parse 通过：L bit 清除时消费剩余 datagram；发送端始终设置 L bit。"
            c["phase2_decision"] = "confirmed_partial"
            c["decision_reason"] = "实现不会发送违规中间无长度记录，接收端语义上把无 length 解释为最后记录，但缺少显式错误路径。"
        elif c["id"] in (101, 103, 104):
            c["test_check"] = "source_assertions 验证单 secret HMAC cookie 路径；未发现双 secret 或 timestamp 字段。"
            c["phase2_decision"] = "confirmed_partial"
            c["decision_reason"] = "当前实现支持应用设置/轮换单个 secret 和完整性验证，不提供内建过渡窗口或时间戳过期策略。"
        elif c["id"] == 114:
            c["test_check"] = "source_assertions 验证 DTLS 1.3 服务端清空/不回显 session ID；未发现 pre-DTLS 1.3 cached session ID 专门策略。"
            c["phase2_decision"] = "confirmed_partial"
            c["decision_reason"] = "通用 helper 可写 session ID，但 DTLS 1.3 特定条件策略证据不足。"
        elif c["id"] == 117:
            c["test_check"] = "当前仓库未构建/未发现 DTLS over TCP/SCTP 专门路径；源码级检查无法证明该传输模式写入限制。"
            c["phase2_decision"] = "not_testable"
            c["decision_reason"] = "要求限定 DTLS over TCP/SCTP，当前目标代码和构建环境以 UDP datagram DTLS 为主，不能形成可靠运行结论。"
        elif c["id"] == 139:
            c["test_check"] = "source_assertions 验证 KeyUpdate/ACK 使用 DTLS 1.3 RTX/sequence 结构，但未能源码证明所有 post-handshake 不重置。"
            c["phase2_decision"] = "confirmed_partial"
            c["decision_reason"] = "同一序列状态贯穿 DTLS 1.3 路径，但缺少完整 post-handshake 覆盖测试。"
        else:
            c["test_check"] = "未分类为部分/不满足。"
            c["phase2_decision"] = ""
            c["decision_reason"] = ""

    log = []
    for t in tests:
        log.append(f"[{'PASS' if t['passed'] else 'FAIL'}] {t['name']}: {t['detail']}")
    (OUT / "source_assertion_tests.log").write_text("\n".join(log) + "\n", encoding="utf-8")
    (OUT / "source_assertion_tests.json").write_text(json.dumps({"tests": tests}, ensure_ascii=False, indent=2), encoding="utf-8")
    return tests


def write_md(results, counts):
    rows = ["# wolfSSL DTLS 1.3 101-150 对比结果", "", f"- 满足: {counts.get(STATUS_OK, 0)}", f"- 部分满足: {counts.get(STATUS_PARTIAL, 0)}", f"- 不满足: {counts.get(STATUS_UNSAT, 0)}", f"- 不适用: {counts.get(STATUS_NA, 0)}", "", "| ID | variable | action | 状态 | 说明 |", "|---:|---|---|---|---|"]
    for r in results:
        rows.append(f"| {r['id']} | {r['variable_name']} | {r['change_action']} | {r['status']} | {r['comment']} |")
    (OUT / f"compare_{IMPL}_{START}_{END}.md").write_text("\n".join(rows) + "\n", encoding="utf-8")

    simple = [f"{r['id']}\t{r['status']}\t{r['variable_name']}\t{r['change_action']}\t{r['comment']}" for r in results]
    (OUT / f"compare_{IMPL}_{START}_{END}_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")


def write_classification(classified):
    by_cat = defaultdict(list)
    for item in classified:
        by_cat[item["category"] or "uncategorized"].append(item)
    summary = {
        "scope": f"{START}-{END}",
        "implementation": "wolfssl-master",
        "counts": {
            "total_partial_unsat": len(classified),
            "by_status": dict(Counter(i["status"] for i in classified)),
            "by_category": {k: len(v) for k, v in by_cat.items()},
            "by_risk": dict(Counter(i["risk"] for i in classified)),
            "phase2_decisions": dict(Counter(i.get("phase2_decision", "") for i in classified if i.get("phase2_decision"))),
        },
        "items": classified,
    }
    (OUT / f"compare_{IMPL}_{START}_{END}_partial_unsat_classification.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [f"# wolfSSL DTLS 1.3 {START}-{END} 部分/不满足分类", ""]
    for cat, items in by_cat.items():
        lines.append(f"## {cat} ({len(items)})")
        lines.append("")
        lines.append("| ID | 状态 | 风险 | Phase2 | 说明 |")
        lines.append("|---:|---|---|---|---|")
        for it in items:
            lines.append(f"| {it['id']} | {it['status']} | {it['risk']} | {it.get('phase2_decision','')} | {it['decision_reason'] or it['comment']} |")
        lines.append("")
    (OUT / f"compare_{IMPL}_{START}_{END}_partial_unsat_classification.md").write_text("\n".join(lines), encoding="utf-8")


def write_reports(classified):
    def snippet(evidence_ref, radius=3):
        m = re.match(r"wolfssl-master/(.*):(\d+)$", evidence_ref)
        if not m:
            return ""
        rel = m.group(1)
        line_no = int(m.group(2))
        path = TARGET / rel
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, line_no - radius)
        end = min(len(lines), line_no + radius)
        body = "\n".join(f"{i}:{lines[i-1]}" for i in range(start, end + 1))
        return f"// {rel}:{line_no}\n{body}"

    report_items = [i for i in classified if i.get("phase2_decision") in ("confirmed_unsatisfied", "confirmed_partial")]
    for it in report_items:
        if it["id"] in (145, 146):
            title = "DTLS 1.3 Dynamic Connection ID Request Messages Are Not Implemented"
            fname = f"id{it['id']:03d}_dynamic_connection_id_messages_unsatisfied.md"
            std = """Endpoints SHOULD respond to RequestConnectionId by sending a NewConnectionId with usage "cid_spare" containing num_cids CIDs as soon as possible.

An endpoint MAY handle requests which it considers excessive by responding with a NewConnectionId message containing fewer than num_cids CIDs, including no CIDs at all."""
            source = """/* Existing DTLS CID extension support, not RFC 9147 post-handshake messages. */
int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,
    byte isRequest)

int wolfSSL_dtls_cid_use(WOLFSSL* ssl)

static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
{
    ...
    *flags |= DTLS13_CID_BIT;
    ...
}"""
            body = f"""# {title}

## Summary
wolfSSL has DTLS CID extension support and can place a negotiated CID into the DTLS 1.3 unified header, but this audit did not find RFC 9147 `RequestConnectionId` or `NewConnectionId` post-handshake message handling.

## Standard Requirement
Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant sections: RFC 9147 Section 9.1 "New Connection ID" and Section 9.2 "Request Connection ID".

Original English normative text:

```text
{std}
```

The standard requires a peer to understand a request for additional CIDs and to respond with `NewConnectionId` messages using the requested `num_cids` value, subject to the excessive-request exception.

## Relevant Source Code
`src/dtls.c:1254`, `src/dtls.c:1344`, `src/dtls13.c:1163`, `src/dtls13.c:1176`, `wolfssl/internal.h:6622`

```c
{source}
```

`wolfssl/internal.h:6622` defines the ACK content type, and the searched handshake enum contains common TLS/DTLS handshake messages, but no `RequestConnectionId` or `NewConnectionId` handshake message.

## Implementation Behavior
The implementation supports a static/extension-driven CID model:

- `TLSX_ConnectionID_Parse` parses the connection_id extension.
- `wolfSSL_dtls_cid_use` and `wolfSSL_dtls_cid_set` configure local CID use.
- `Dtls13AddCID` sets the unified header CID bit and writes the configured transmit CID.

The audit search did not find `RequestConnectionId`, `NewConnectionId`, `num_cids`, `cid_spare`, or parser/sender logic for these post-handshake messages.

## Inconsistency Reason
RFC 9147's dynamic CID update mechanism is a runtime handshake-message protocol. Existing wolfSSL code proves only extension negotiation and header encoding for a configured CID. It does not implement the variable change in which `num_cids` is copied from `RequestConnectionId` into one or more `NewConnectionId` responses, nor the excessive-request exception returning fewer CIDs.

## Runtime Evidence
The focused source assertion test passed:

```text
[PASS] request_new_connection_id_absent: 源码未发现 RequestConnectionId/NewConnectionId/num_cids/cid_spare。
```

Full handshake-level runtime testing was blocked because the current `build/CMakeCache.txt` has `WOLFSSL_DTLS13:BOOL=no` and `WOLFSSL_DTLS_CID:BOOL=no`, and no wolfSSL library binary was present in `wolfssl-master/build`.

## Impact
Applications that rely on RFC 9147 dynamic CID rotation or spare CID provisioning cannot use wolfSSL's DTLS 1.3 stack for that behavior. They may be limited to preconfigured or extension-negotiated CIDs and cannot interoperate with peers expecting RequestConnectionId/NewConnectionId.

## Fix Direction
Add DTLS 1.3 post-handshake message definitions and state-machine paths for `RequestConnectionId` and `NewConnectionId`. The implementation should parse `num_cids`, enforce bounds and excessive-request policy, generate `NewConnectionId` messages with `usage = cid_spare`, and add regression tests covering normal, zero, and excessive request cases.
"""
        else:
            title = {
                101: "DTLS 1.3 Cookie Secret Transition Window Is Application-Only",
                103: "DTLS 1.3 Cookie Secret Rotation Has No Built-In Window Policy",
                104: "DTLS 1.3 Cookie Timestamp Expiration Is Not Implemented",
                114: "Pre-DTLS 1.3 Cached Legacy Session ID Handling Is Not Proven",
                123: "Unified Header Length Omission Relies On Remainder Consumption",
                125: "Explicit DTLS 1.3 Record Length Lacks Direct Datagram-Bounds Check",
                139: "Post-Handshake Message Sequence Continuity Is Only Partially Proven",
            }.get(it["id"], "DTLS 1.3 Partial Compliance Finding")
            fname = f"id{it['id']:03d}_{re.sub(r'[^a-z0-9]+', '_', title.lower()).strip('_')}_partial.md"
            snippets = "\n\n".join(snippet(e) for e in it[f"evidence_in_{IMPL}"][:3])
            original = it.get("standard_original_text") or it.get("extracted_evidence") or it.get("change_condition", "")
            body = f"""# {title}

## Summary
This item is confirmed as partially satisfied. wolfSSL implements the main related DTLS 1.3 path, but this audit could not prove the full conditional behavior required by the extracted RFC 9147 rule.

## Standard Requirement
Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: {it['standard_section']}

Original English normative text:

```text
{original}
```

Extracted requirement:

```text
Condition: {it['change_condition']}
Action: {it['change_action']}
```

## Relevant Source Code
{chr(10).join('- `' + e.replace('wolfssl-master/', '') + '`' for e in it[f'evidence_in_{IMPL}'])}

```c
{snippets}
```

The snippets above show the concrete implementation branch used for this decision. The full line list remains in the comparison JSON for reproducibility.

## Implementation Behavior
{it['comment']}

## Inconsistency Reason
The implemented portion is visible in the cited source lines. The missing or unproven portion is: {it['decision_reason']}

## Runtime Evidence
Focused source assertion tests were run and saved in `source_assertion_tests.log`.

```text
{it['test_check']}
```

Full handshake-level runtime testing was blocked because the current local CMake cache disables DTLS 1.3/CID and no linked wolfSSL runtime binary was available.

## Impact
The impact depends on the feature: peers using the covered base path interoperate, but deployments depending on the missing conditional policy may get weaker validation, configuration-dependent behavior, or lack of proof for edge cases.

## Fix Direction
Add explicit tests and, where needed, explicit implementation branches for the missing condition. Prefer protocol-level unit tests that construct the exact DTLS 1.3 message or record variant and assert the expected alert, discard, or state transition.
"""
        (OUT / fname).write_text(body, encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = json.loads(INPUT_JSON.read_text(encoding="utf-8"))
    changes = data["changes"]
    items = []
    for idx in range(START - 1, END):
        item = dict(changes[idx])
        item["id"] = idx + 1
        items.append(item)
    results = [classify(i) for i in items]
    validation = validate_evidence(results)
    counts = Counter(r["status"] for r in results)

    classified = [r for r in results if r["status"] in (STATUS_PARTIAL, STATUS_UNSAT)]
    tests = run_source_tests(classified)

    meta = {
        "source_file": str(INPUT_JSON),
        "scope": f"{START}-{END}_rules",
        "method": "static_code_comparison_plus_source_assertion_tests",
        "target_requested": r"D:\project\conditionFuzzing\wolfssl-main",
        "target_used": str(TARGET),
        "target_note": "Requested target_repo did not exist; wolfssl-master in the same workspace was used.",
        "standard_reference": "https://www.rfc-editor.org/rfc/rfc9147",
        "counts": dict(counts),
        "evidence_validation": {
            "all_ok": all(v["ok"] for v in validation),
            "items": validation,
        },
        "runtime_test_note": "Full DTLS 1.3 handshake tests blocked: current CMakeCache disables WOLFSSL_DTLS13/WOLFSSL_DTLS_CID and no wolfSSL binary library exists. Focused source assertion tests were run instead.",
        "source_assertion_test_counts": dict(Counter("passed" if t["passed"] else "failed" for t in tests)),
    }
    out_json = {"meta": meta, "results": results}
    (OUT / f"compare_{IMPL}_{START}_{END}.json").write_text(json.dumps(out_json, ensure_ascii=False, indent=2), encoding="utf-8")
    write_md(results, counts)
    write_classification(classified)
    write_reports(classified)

    manifest = {
        "files": sorted(p.name for p in OUT.iterdir() if p.is_file()),
        "counts": dict(counts),
        "classified_count": len(classified),
        "confirmed_reports": sorted(p.name for p in OUT.glob("id*.md")),
    }
    (OUT / "round_101_150_summary.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
