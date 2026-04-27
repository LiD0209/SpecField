#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


WORKSPACE = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent

SOURCE_JSON = WORKSPACE / "output" / "02_variable_changes.json"

OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_051_100.json"
OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_051_100.md"
OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_051_100_simple.txt"
OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_051_100_partial_unsat_classification.json"
OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_051_100_partial_unsat_classification.md"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_counts(counter: Counter) -> dict:
    return {
        "满足": counter.get("满足", 0),
        "部分满足": counter.get("部分满足", 0),
        "不满足": counter.get("不满足", 0),
        "不适用": counter.get("不适用", 0),
        "待确认": counter.get("待确认", 0),
    }


def validate_evidence_refs(refs: list[str]) -> dict:
    missing_files: list[str] = []
    out_of_range: list[str] = []
    bad_format: list[str] = []
    cache: dict[Path, list[str]] = {}

    for ref in refs:
        m = re.match(r"^([^:]+):(\d+)$", ref)
        if not m:
            bad_format.append(ref)
            continue
        rel_path = m.group(1)
        line_no = int(m.group(2))
        abs_path = WORKSPACE / rel_path
        if not abs_path.exists():
            missing_files.append(ref)
            continue
        if abs_path not in cache:
            cache[abs_path] = abs_path.read_text(encoding="utf-8", errors="replace").splitlines()
        line_count = len(cache[abs_path])
        if line_no < 1 or line_no > line_count:
            out_of_range.append(ref)

    return {
        "total_references": len(refs),
        "missing_files": sorted(set(missing_files)),
        "out_of_range": sorted(set(out_of_range)),
        "bad_format": sorted(set(bad_format)),
        "all_locatable": not (missing_files or out_of_range or bad_format),
    }


def md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def rule_mapping() -> dict[int, dict]:
    return {
        51: {
            "status": "不满足",
            "comment": "空 ClientId + clean_session=0 未返回 0x02（Identifier rejected）。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2918",
                "wolfMQTT-master/src/mqtt_broker.c:2972",
                "wolfMQTT-master/src/mqtt_broker.c:3025",
            ],
            "category": "ClientId拒绝返回码不符合规范",
            "risk_level": "high",
            "reason": "规范要求该场景返回 0x02 并断链，当前实现会进入接受/分配路径。",
        },
        52: {
            "status": "部分满足",
            "comment": "部分校验失败会返回非零 CONNACK，但并非所有失败路径都发送 CONNACK。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2726",
                "wolfMQTT-master/src/mqtt_broker.c:2799",
                "wolfMQTT-master/src/mqtt_broker.c:2960",
                "wolfMQTT-master/src/mqtt_broker.c:2694",
            ],
            "category": "CONNECT失败响应覆盖不完整",
            "risk_level": "medium",
            "reason": "decode 失败等路径会直接断开，未总是“发送非零返回码”。",
        },
        53: {
            "status": "满足",
            "comment": "CONNECT 验证成功时，CONNACK 返回码为 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2918",
                "wolfMQTT-master/src/mqtt_broker.c:3025",
            ],
        },
        54: {
            "status": "满足",
            "comment": "发送非零 CONNACK 后会立即走断链流程。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3043",
                "wolfMQTT-master/src/mqtt_broker.c:3044",
                "wolfMQTT-master/src/mqtt_broker.c:3541",
                "wolfMQTT-master/src/mqtt_broker.c:3544",
            ],
        },
        55: {
            "status": "不满足",
            "comment": "同 ID51：空 ClientId + clean_session=0 未返回 0x02。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2918",
                "wolfMQTT-master/src/mqtt_broker.c:2972",
                "wolfMQTT-master/src/mqtt_broker.c:3025",
            ],
            "category": "ClientId拒绝返回码不符合规范",
            "risk_level": "high",
            "reason": "Identifier rejected 约束未命中该条件分支。",
        },
        56: {
            "status": "满足",
            "comment": "接受 clean_session=0 连接时返回码为 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2744",
                "wolfMQTT-master/src/mqtt_broker.c:2918",
                "wolfMQTT-master/src/mqtt_broker.c:3025",
            ],
        },
        57: {
            "status": "满足",
            "comment": "接受 clean_session=1 连接时返回码为 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2780",
                "wolfMQTT-master/src/mqtt_broker.c:2918",
                "wolfMQTT-master/src/mqtt_broker.c:3025",
            ],
        },
        58: {
            "status": "满足",
            "comment": "无已存会话状态时，接受连接返回码为 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2775",
                "wolfMQTT-master/src/mqtt_broker.c:2918",
                "wolfMQTT-master/src/mqtt_broker.c:3025",
            ],
        },
        59: {
            "status": "部分满足",
            "comment": "存在 ClientId 被拒绝并返回 0x02 的路径（如过长 ID），但覆盖不完整。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2713",
                "wolfMQTT-master/src/mqtt_broker.c:2726",
                "wolfMQTT-master/src/mqtt_broker.c:3025",
            ],
            "category": "ClientId拒绝返回码不符合规范",
            "risk_level": "medium",
            "reason": "并非所有应拒绝 ClientId 的场景都会回 0x02。",
        },
        60: {
            "status": "部分满足",
            "comment": "同 ID59：0x02 返回码仅在部分 ClientId 拒绝路径生效。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2713",
                "wolfMQTT-master/src/mqtt_broker.c:2726",
                "wolfMQTT-master/src/mqtt_broker.c:3025",
            ],
            "category": "ClientId拒绝返回码不符合规范",
            "risk_level": "medium",
            "reason": "拒绝码语义落地存在条件差异。",
        },
        61: {
            "status": "满足",
            "comment": "服务端确认 CONNECT 时使用零返回码。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2918",
                "wolfMQTT-master/src/mqtt_broker.c:3025",
            ],
        },
        62: {
            "status": "不满足",
            "comment": "未见对不支持 protocol level 的显式 0x01 响应校验与分支。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:997",
                "wolfMQTT-master/src/mqtt_broker.c:2736",
                "wolfMQTT-master/src/mqtt_broker.c:2918",
            ],
            "category": "Protocol Level校验缺失",
            "risk_level": "high",
            "reason": "缺少“unsupported level -> 0x01 + disconnect”的明确实现。",
        },
        63: {
            "status": "部分满足",
            "comment": "发送侧 CONNACK flags 置 0，但接收侧未显式校验 bits7..1 为 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2917",
                "wolfMQTT-master/src/mqtt_packet.c:1176",
                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:370",
            ],
            "category": "CONNACK Flags接收校验不足",
            "risk_level": "medium",
            "reason": "编码满足约束，解码未验证保留位合法性。",
        },
        64: {
            "status": "满足",
            "comment": "Connect Flags 同时用于连接行为参数和 payload 字段存在性判定。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:869",
                "wolfMQTT-master/src/mqtt_packet.c:873",
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1130",
            ],
        },
        65: {
            "status": "满足",
            "comment": "对可处理的“well-formed 但无法处理”场景，会给出表内非零返回码。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2726",
                "wolfMQTT-master/src/mqtt_broker.c:2799",
                "wolfMQTT-master/src/mqtt_broker.c:2960",
                "wolfMQTT-master/src/mqtt_broker.c:3025",
            ],
        },
        66: {
            "status": "部分满足",
            "comment": "存在不发 CONNACK 直接断链路径，但非以“无适用返回码”统一决策实现。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2694",
                "wolfMQTT-master/src/mqtt_broker.c:2701",
                "wolfMQTT-master/src/mqtt_broker.c:3541",
                "wolfMQTT-master/src/mqtt_broker.c:3544",
            ],
            "category": "CONNECT失败响应覆盖不完整",
            "risk_level": "medium",
            "reason": "效果上有 close-no-CONNACK，但缺少显式 rule-level 分支。",
        },
        67: {
            "status": "满足",
            "comment": "Remaining Length 编码时，有后续字节会置 continuation bit。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:269",
                "wolfMQTT-master/src/mqtt_packet.c:272",
                "wolfMQTT-master/src/mqtt_packet.c:273",
            ],
        },
        68: {
            "status": "满足",
            "comment": "Remaining Length 解码循环条件为 `(encodedByte & 128) != 0`。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:240",
                "wolfMQTT-master/src/mqtt_packet.c:245",
            ],
        },
        69: {
            "status": "满足",
            "comment": "接收侧未基于 DUP 位做重复抑制判定，同包标识重来仍按发布流程处理。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3207",
                "wolfMQTT-master/src/mqtt_broker.c:3333",
                "wolfMQTT-master/src/mqtt_packet.c:1426",
            ],
        },
        70: {
            "status": "部分满足",
            "comment": "broker 转发 QoS0 时固定 DUP=0，但通用编码接口未硬性禁止 QoS0+dup=1。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3305",
                "wolfMQTT-master/src/mqtt_packet.c:1343",
            ],
            "category": "DUP首发语义约束不完整",
            "risk_level": "medium",
            "reason": "核心路径符合，但库 API 级约束不严格。",
        },
        71: {
            "status": "部分满足",
            "comment": "QoS1 首发在 broker 流程为 DUP=0；通用客户端编码由调用方提供 duplicate。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3300",
                "wolfMQTT-master/src/mqtt_broker.c:3305",
                "wolfMQTT-master/src/mqtt_packet.c:1343",
            ],
            "category": "DUP首发语义约束不完整",
            "risk_level": "medium",
            "reason": "缺少全局“首发必为 0”的硬约束。",
        },
        72: {
            "status": "部分满足",
            "comment": "QoS2 首发同样依赖调用侧 duplicate 输入，未统一强制。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3300",
                "wolfMQTT-master/src/mqtt_broker.c:3305",
                "wolfMQTT-master/src/mqtt_packet.c:1343",
            ],
            "category": "DUP首发语义约束不完整",
            "risk_level": "medium",
            "reason": "通用编码路径未封死异常取值。",
        },
        73: {
            "status": "部分满足",
            "comment": "QoS0 发送常见路径 DUP=0，但非所有调用路径都强制该常量。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3305",
                "wolfMQTT-master/src/mqtt_packet.c:1343",
            ],
            "category": "DUP首发语义约束不完整",
            "risk_level": "medium",
            "reason": "依赖调用约定而非统一约束。",
        },
        74: {
            "status": "部分满足",
            "comment": "“所有 QoS0 消息 DUP=0”未在通用编码层做强制校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1308",
                "wolfMQTT-master/src/mqtt_packet.c:1343",
                "wolfMQTT-master/src/mqtt_broker.c:3305",
            ],
            "category": "DUP首发语义约束不完整",
            "risk_level": "medium",
            "reason": "库允许调用方构造不规范组合。",
        },
        75: {
            "status": "部分满足",
            "comment": "broker 转发不会传播 incoming DUP，但也未实现“重传时按状态置位”的完整机制。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3207",
                "wolfMQTT-master/src/mqtt_broker.c:3305",
                "wolfMQTT-master/src/mqtt_broker.c:3315",
            ],
            "category": "DUP重传语义实现不完整",
            "risk_level": "medium",
            "reason": "做到了“独立于入站 DUP”，但“仅重传置 1”未形成闭环。",
        },
        76: {
            "status": "不满足",
            "comment": "未发现重投递时自动将 DUP 置 1 的实现路径。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1343",
                "wolfMQTT-master/src/mqtt_broker.c:3305",
                "wolfMQTT-master/src/mqtt_client.c:2169",
            ],
            "category": "DUP重传置位缺失",
            "risk_level": "high",
            "reason": "规范要求重投递必须 DUP=1，代码无对应自动机制。",
        },
        77: {
            "status": "部分满足",
            "comment": "同 ID74：QoS0 DUP=0 在主要路径满足，但通用层不强制。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1308",
                "wolfMQTT-master/src/mqtt_packet.c:1343",
                "wolfMQTT-master/src/mqtt_broker.c:3305",
            ],
            "category": "DUP首发语义约束不完整",
            "risk_level": "medium",
            "reason": "缺少库级硬性约束。",
        },
        78: {
            "status": "不满足",
            "comment": "同 ID76：Client/Server 重投递场景未见 DUP=1 自动置位。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1343",
                "wolfMQTT-master/src/mqtt_broker.c:3305",
                "wolfMQTT-master/src/mqtt_client.c:2169",
            ],
            "category": "DUP重传置位缺失",
            "risk_level": "high",
            "reason": "无显式重投递 DUP 置位策略。",
        },
        79: {
            "status": "部分满足",
            "comment": "转发 DUP 不继承入站值（固定 0），但“仅按是否重传决定”仍未完整实现。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3207",
                "wolfMQTT-master/src/mqtt_broker.c:3305",
            ],
            "category": "DUP重传语义实现不完整",
            "risk_level": "medium",
            "reason": "独立性满足，重传状态机不足。",
        },
        80: {
            "status": "满足",
            "comment": "Variable Byte Integer 编码实现了 `encodedByte = X MOD 128`。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:269",
            ],
        },
        81: {
            "status": "满足",
            "comment": "解码时 `encodedByte` 从后续字节流读取。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:240",
            ],
        },
        82: {
            "status": "满足",
            "comment": "存在后续编码数据时执行 `encodedByte |= 128`。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:272",
                "wolfMQTT-master/src/mqtt_packet.c:273",
            ],
        },
        83: {
            "status": "不满足",
            "comment": "接收侧固定报头 flags 未按包类型做保留位合法性校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:197",
                "wolfMQTT-master/src/mqtt_packet.c:202",
                "wolfMQTT-master/src/mqtt_broker.c:3570",
            ],
            "category": "Fixed Header Flags校验缺失",
            "risk_level": "high",
            "reason": "仅校验 packet type，缺少 flags 合法值约束。",
        },
        84: {
            "status": "不满足",
            "comment": "未实现通用“invalid flags -> close connection”处理。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:197",
                "wolfMQTT-master/src/mqtt_packet.c:202",
                "wolfMQTT-master/src/mqtt_broker.c:3438",
            ],
            "category": "Fixed Header Flags校验缺失",
            "risk_level": "high",
            "reason": "缺少对非法 flags 的统一拒绝断链。",
        },
        85: {
            "status": "不满足",
            "comment": "同 ID84：非法 flags 场景未覆盖到协议级断链处理。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:197",
                "wolfMQTT-master/src/mqtt_packet.c:202",
                "wolfMQTT-master/src/mqtt_broker.c:3438",
            ],
            "category": "Fixed Header Flags校验缺失",
            "risk_level": "high",
            "reason": "保留位/非法位值缺少接收端严格校验。",
        },
        86: {
            "status": "部分满足",
            "comment": "客户端携带 Keep Alive 并提供 PING API，但未自动调度保证发送间隔不超时。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:888",
                "wolfMQTT-master/src/mqtt_client.c:2572",
                "wolfMQTT-master/src/mqtt_client.c:2641",
            ],
            "category": "KeepAlive客户端责任未自动保障",
            "risk_level": "medium",
            "reason": "能力存在，依赖上层应用主动调用与调度。",
        },
        87: {
            "status": "部分满足",
            "comment": "同 ID86：发送间隔控制主要由应用层负责。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:888",
                "wolfMQTT-master/src/mqtt_client.c:2572",
                "wolfMQTT-master/src/mqtt_client.c:2641",
            ],
            "category": "KeepAlive客户端责任未自动保障",
            "risk_level": "medium",
            "reason": "库未内建 keepalive 定时发送策略。",
        },
        88: {
            "status": "满足",
            "comment": "服务端实现了 1.5 倍 Keep Alive 超时断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3607",
                "wolfMQTT-master/src/mqtt_broker.c:3611",
                "wolfMQTT-master/src/mqtt_broker.c:3624",
            ],
        },
        89: {
            "status": "满足",
            "comment": "Keep Alive 为 0 时不会进入超时断链逻辑（机制关闭）。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3608",
            ],
        },
        90: {
            "status": "满足",
            "comment": "超过 1.5 倍 Keep Alive 无控制报文时会判定超时并断开。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3610",
                "wolfMQTT-master/src/mqtt_broker.c:3611",
                "wolfMQTT-master/src/mqtt_broker.c:3624",
            ],
        },
        91: {
            "status": "满足",
            "comment": "Keep Alive 使用 16 位字段（最大 65535 秒）。",
            "evidence": [
                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:363",
                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:420",
                "wolfMQTT-master/src/mqtt_packet.c:1005",
            ],
        },
        92: {
            "status": "满足",
            "comment": "UTF-8 字符串编码使用 2 字节长度前缀，长度为字符串字节数。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:361",
                "wolfMQTT-master/src/mqtt_packet.c:363",
                "wolfMQTT-master/src/mqtt_packet.c:370",
            ],
        },
        93: {
            "status": "满足",
            "comment": "Password 存在时通过长度前缀编码，长度来自实际字节数。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:846",
                "wolfMQTT-master/src/mqtt_packet.c:941",
                "wolfMQTT-master/src/mqtt_packet.c:361",
            ],
        },
        94: {
            "status": "满足",
            "comment": "UTF-8 字符串长度有 65535 上限且解码时做边界验证。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:366",
                "wolfMQTT-master/src/mqtt_packet.c:367",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
        },
        95: {
            "status": "满足",
            "comment": "Will Message 长度前缀来自数据长度，且不包含前缀自身长度。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:818",
                "wolfMQTT-master/src/mqtt_packet.c:934",
                "wolfMQTT-master/src/mqtt_packet.c:383",
            ],
        },
        96: {
            "status": "部分满足",
            "comment": "packet_id 在发送过程中保持调用方提供值，但未实现统一自动重发管理策略。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1309",
                "wolfMQTT-master/src/mqtt_packet.c:1363",
                "wolfMQTT-master/src/mqtt_client.c:2169",
                "wolfMQTT-master/src/mqtt_client.c:2288",
            ],
            "category": "Packet Identifier重发语义不完整",
            "risk_level": "medium",
            "reason": "可保持同 ID，但缺少内建“重发必须复用”策略层。",
        },
        97: {
            "status": "满足",
            "comment": "PUBACK/PUBREC/PUBREL 响应路径都复用原始 PUBLISH 的 packet_id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3335",
                "wolfMQTT-master/src/mqtt_broker.c:3341",
                "wolfMQTT-master/src/mqtt_broker.c:3411",
                "wolfMQTT-master/src/mqtt_client.c:964",
            ],
        },
        98: {
            "status": "满足",
            "comment": "QoS0 的 PUBLISH 不编码 packet_id，解码也仅在 QoS>0 时读取。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1308",
                "wolfMQTT-master/src/mqtt_packet.c:1362",
                "wolfMQTT-master/src/mqtt_packet.c:1444",
            ],
        },
        99: {
            "status": "满足",
            "comment": "SUBACK/UNSUBACK 都使用对应 SUBSCRIBE/UNSUBSCRIBE 的 packet_id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3111",
                "wolfMQTT-master/src/mqtt_broker.c:3161",
                "wolfMQTT-master/src/mqtt_packet.c:2623",
                "wolfMQTT-master/src/mqtt_packet.c:2319",
            ],
        },
        100: {
            "status": "满足",
            "comment": "接收端对同 packet_id 的后续 PUBLISH 仍按新发布流程处理，不依赖 DUP 位判断。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3207",
                "wolfMQTT-master/src/mqtt_broker.c:3333",
                "wolfMQTT-master/src/mqtt_packet.c:1426",
            ],
        },
    }


def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:
    results: list[dict] = []
    for i, change in enumerate(changes, start=51):
        m = mapping[i]
        results.append(
            {
                "id": i,
                "source_index": i - 1,
                "variable_name": change.get("variable_name", ""),
                "change_action": change.get("change_action", ""),
                "change_condition": change.get("change_condition", ""),
                "old_value": change.get("old_value", ""),
                "new_value": change.get("new_value", ""),
                "related_state_or_step": change.get("related_state_or_step", ""),
                "source_chunk_id": change.get("source_chunk_id", ""),
                "status": m["status"],
                "comment": m["comment"],
                "evidence_in_wolfmqtt": m.get("evidence", []),
            }
        )

    counts = normalize_counts(Counter([r["status"] for r in results]))
    all_refs: list[str] = []
    for r in results:
        all_refs.extend(r.get("evidence_in_wolfmqtt", []))
    evidence_check = validate_evidence_refs(all_refs)

    meta = {
        "source_file": str(SOURCE_JSON),
        "scope": "source_changes_index_50_to_99",
        "display_scope": "051-100",
        "method": "static_code_comparison",
        "target": "wolfMQTT-master",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "counts": counts,
        "evidence_validation": evidence_check,
    }
    return {"meta": meta, "results": results}


def build_compare_md(compare: dict) -> str:
    meta = compare["meta"]
    rows = compare["results"]
    lines = [
        "# wolfMQTT-master 051-100 对比结果",
        "",
        f"- 对比输入: `output/02_variable_changes.json` 的索引 `50..99`（共 {len(rows)} 条）",
        "- 目标代码: `wolfMQTT-master`",
        f"- 满足: {meta['counts']['满足']}",
        f"- 部分满足: {meta['counts']['部分满足']}",
        f"- 不满足: {meta['counts']['不满足']}",
        f"- 不适用: {meta['counts']['不适用']}",
        f"- 待确认: {meta['counts']['待确认']}",
        (
            "- 证据定位校验: "
            f"all_locatable={meta['evidence_validation']['all_locatable']}, "
            f"references={meta['evidence_validation']['total_references']}"
        ),
        "",
        "| ID | source_idx | variable | action | 状态 | 说明 | 证据数 |",
        "|---:|---:|---|---|---|---|---:|",
    ]
    for r in rows:
        lines.append(
            "| {id} | {idx} | {var} | {act} | {status} | {comment} | {ev_count} |".format(
                id=r["id"],
                idx=r["source_index"],
                var=md_escape(r["variable_name"]),
                act=md_escape(r["change_action"]),
                status=r["status"],
                comment=md_escape(r["comment"]),
                ev_count=len(r.get("evidence_in_wolfmqtt", [])),
            )
        )
    lines.append("")
    return "\n".join(lines)


def build_simple_txt(compare: dict) -> str:
    lines: list[str] = []
    for r in compare["results"]:
        lines.append(f"{r['id']:03d}\t{r['status']}\t{r['comment']}")
    return "\n".join(lines) + "\n"


def build_classification(compare: dict, mapping: dict[int, dict]) -> dict:
    rows = [r for r in compare["results"] if r["status"] in ("部分满足", "不满足")]
    out: list[dict] = []
    for r in rows:
        m = mapping[r["id"]]
        out.append(
            {
                "id": r["id"],
                "status": r["status"],
                "category": m.get("category", "未分类"),
                "risk_level": m.get("risk_level", "medium"),
                "reason": m.get("reason", r["comment"]),
                "variable_name": r["variable_name"],
                "change_action": r["change_action"],
                "change_condition": r["change_condition"],
                "source_index": r["source_index"],
                "source_chunk_id": r["source_chunk_id"],
                "original_comment": r["comment"],
                "evidence_in_wolfmqtt": r.get("evidence_in_wolfmqtt", []),
            }
        )

    status_counter = Counter([x["status"] for x in out])
    risk_counter = Counter([x["risk_level"] for x in out])
    category_summary: dict[str, dict] = defaultdict(
        lambda: {"count": 0, "partial": 0, "unsatisfied": 0}
    )

    for row in out:
        c = category_summary[row["category"]]
        c["count"] += 1
        if row["status"] == "部分满足":
            c["partial"] += 1
        else:
            c["unsatisfied"] += 1

    return {
        "scope": "wolfMQTT-master 051-100 partial+unsatisfied",
        "total_reviewed": len(out),
        "status_summary": {
            "部分满足": status_counter.get("部分满足", 0),
            "不满足": status_counter.get("不满足", 0),
        },
        "risk_summary": {
            "low": risk_counter.get("low", 0),
            "medium": risk_counter.get("medium", 0),
            "high": risk_counter.get("high", 0),
        },
        "category_summary": dict(sorted(category_summary.items(), key=lambda x: x[0])),
        "results": out,
    }


def build_classification_md(cls: dict) -> str:
    lines = [
        "# wolfMQTT-master 051-100 未满足/部分满足分类",
        "",
        f"- total_reviewed: {cls['total_reviewed']}",
        f"- 部分满足: {cls['status_summary']['部分满足']}",
        f"- 不满足: {cls['status_summary']['不满足']}",
        (
            "- 风险分布: "
            f"low={cls['risk_summary']['low']}, "
            f"medium={cls['risk_summary']['medium']}, "
            f"high={cls['risk_summary']['high']}"
        ),
        "",
        "## 分类汇总",
        "",
        "| 分类 | 数量 | 部分满足 | 不满足 |",
        "|---|---:|---:|---:|",
    ]
    for cat, s in cls["category_summary"].items():
        lines.append(f"| {md_escape(cat)} | {s['count']} | {s['partial']} | {s['unsatisfied']} |")

    lines.extend(
        [
            "",
            "## 明细",
            "",
            "| ID | source_idx | 状态 | 风险 | 分类 | 说明 |",
            "|---:|---:|---|---|---|---|",
        ]
    )
    for r in cls["results"]:
        lines.append(
            "| {id} | {idx} | {status} | {risk} | {cat} | {reason} |".format(
                id=r["id"],
                idx=r["source_index"],
                status=r["status"],
                risk=r["risk_level"],
                cat=md_escape(r["category"]),
                reason=md_escape(r["reason"]),
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    source = load_json(SOURCE_JSON)
    changes = source.get("changes", [])[50:100]
    if len(changes) != 50:
        raise RuntimeError(f"Expected 50 items for 051-100, got {len(changes)}")

    mapping = rule_mapping()
    if sorted(mapping.keys()) != list(range(51, 101)):
        raise RuntimeError("Rule mapping must cover IDs 51..100")

    compare = build_compare(changes, mapping)
    save_json(OUT_COMPARE_JSON, compare)
    OUT_COMPARE_MD.write_text(build_compare_md(compare), encoding="utf-8")
    OUT_SIMPLE_TXT.write_text(build_simple_txt(compare), encoding="utf-8")

    cls = build_classification(compare, mapping)
    save_json(OUT_CLASS_JSON, cls)
    OUT_CLASS_MD.write_text(build_classification_md(cls), encoding="utf-8")

    print("Generated:")
    print(f"- {OUT_COMPARE_JSON}")
    print(f"- {OUT_COMPARE_MD}")
    print(f"- {OUT_SIMPLE_TXT}")
    print(f"- {OUT_CLASS_JSON}")
    print(f"- {OUT_CLASS_MD}")


if __name__ == "__main__":
    main()
