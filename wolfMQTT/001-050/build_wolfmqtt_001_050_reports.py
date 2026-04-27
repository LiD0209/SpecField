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
TARGET_DIR = WORKSPACE / "wolfMQTT-master"

OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_001_050.json"
OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_001_050.md"
OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_001_050_simple.txt"
OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_001_050_partial_unsat_classification.json"
OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_001_050_partial_unsat_classification.md"


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
        1: {
            "status": "部分满足",
            "comment": "clean_session=0 断连后会保留订阅关系，但未实现离线 QoS1/QoS2 消息存储。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:1397",
                "wolfMQTT-master/src/mqtt_broker.c:1405",
                "wolfMQTT-master/src/mqtt_broker.c:3291",
                "wolfMQTT-master/src/mqtt_broker.c:3497",
            ],
            "category": "会话持久化仅保留订阅",
            "risk_level": "high",
            "reason": "仅 orphan 订阅，不缓存离线 QoS>0 消息，无法满足“断线后继续存储消息”。",
        },
        2: {
            "status": "满足",
            "comment": "SUBSCRIBE 编码固定使用 QoS1，低 4 位为 0010。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1753",
                "wolfMQTT-master/src/mqtt_packet.c:1754",
            ],
        },
        3: {
            "status": "满足",
            "comment": "UNSUBSCRIBE 编码固定使用 QoS1，低 4 位为 0010。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:2047",
                "wolfMQTT-master/src/mqtt_packet.c:2048",
            ],
        },
        4: {
            "status": "不满足",
            "comment": "SUBSCRIBE 入站仅校验 packet type，不校验固定报头低 4 位，也未在该场景显式断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:198",
                "wolfMQTT-master/src/mqtt_packet.c:1814",
                "wolfMQTT-master/src/mqtt_broker.c:3570",
                "wolfMQTT-master/src/mqtt_broker.c:3571",
            ],
            "category": "固定报头保留位未校验",
            "risk_level": "high",
            "reason": "保留位非法值可穿过解码路径，未按规范执行 malformed+close。",
        },
        5: {
            "status": "不满足",
            "comment": "UNSUBSCRIBE 与 ID4 同类问题：无保留位值校验，缺少该违规场景的断链路径。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:198",
                "wolfMQTT-master/src/mqtt_packet.c:2103",
                "wolfMQTT-master/src/mqtt_broker.c:3573",
                "wolfMQTT-master/src/mqtt_broker.c:3574",
            ],
            "category": "固定报头保留位未校验",
            "risk_level": "high",
            "reason": "保留位非法值不会触发协议违规断链。",
        },
        6: {
            "status": "满足",
            "comment": "PUBREL 发送路径强制 QoS1，固定报头低 4 位为 0010。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1563",
                "wolfMQTT-master/src/mqtt_packet.c:1566",
                "wolfMQTT-master/src/mqtt_broker.c:3425",
            ],
        },
        7: {
            "status": "满足",
            "comment": "同 ID6，PUBREL 编码常量符合 0010 语义。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1563",
                "wolfMQTT-master/src/mqtt_packet.c:1566",
                "wolfMQTT-master/src/mqtt_broker.c:3428",
            ],
        },
        8: {
            "status": "不满足",
            "comment": "PUBREL 入站只校验类型，不校验低 4 位是否为 0010，违规包不会按规范断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:198",
                "wolfMQTT-master/src/mqtt_packet.c:1625",
                "wolfMQTT-master/src/mqtt_broker.c:3375",
                "wolfMQTT-master/src/mqtt_broker.c:3561",
            ],
            "category": "固定报头保留位未校验",
            "risk_level": "high",
            "reason": "PUBREL 保留位非法值未触发 malformed+close。",
        },
        9: {
            "status": "不满足",
            "comment": "同 ID8，PUBREL 保留位违规未被拒绝并断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:198",
                "wolfMQTT-master/src/mqtt_packet.c:1625",
                "wolfMQTT-master/src/mqtt_broker.c:3375",
                "wolfMQTT-master/src/mqtt_broker.c:3561",
            ],
            "category": "固定报头保留位未校验",
            "risk_level": "high",
            "reason": "保留位非法值可通过接收链路。",
        },
        10: {
            "status": "满足",
            "comment": "SUBSCRIBE 固定报头编码常量满足要求。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1753",
                "wolfMQTT-master/src/mqtt_packet.c:1754",
            ],
        },
        11: {
            "status": "不满足",
            "comment": "SUBSCRIBE 非 0010 的非法固定报头未被显式识别并关闭连接。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:198",
                "wolfMQTT-master/src/mqtt_packet.c:1814",
                "wolfMQTT-master/src/mqtt_broker.c:3570",
                "wolfMQTT-master/src/mqtt_broker.c:3571",
            ],
            "category": "固定报头保留位未校验",
            "risk_level": "high",
            "reason": "缺少对 SUBSCRIBE 报头低 4 位的协议约束校验。",
        },
        12: {
            "status": "满足",
            "comment": "UNSUBSCRIBE 固定报头编码常量满足要求。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:2047",
                "wolfMQTT-master/src/mqtt_packet.c:2048",
            ],
        },
        13: {
            "status": "不满足",
            "comment": "UNSUBSCRIBE 非 0010 的非法固定报头未触发规范要求的断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:198",
                "wolfMQTT-master/src/mqtt_packet.c:2103",
                "wolfMQTT-master/src/mqtt_broker.c:3573",
                "wolfMQTT-master/src/mqtt_broker.c:3574",
            ],
            "category": "固定报头保留位未校验",
            "risk_level": "high",
            "reason": "缺少 UNSUBSCRIBE 保留位违规处理。",
        },
        14: {
            "status": "部分满足",
            "comment": "与 ID1 同类：仅持久化订阅，不持久化离线 QoS>0 消息。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:1397",
                "wolfMQTT-master/src/mqtt_broker.c:1405",
                "wolfMQTT-master/src/mqtt_broker.c:3291",
                "wolfMQTT-master/src/mqtt_broker.c:3497",
            ],
            "category": "会话持久化仅保留订阅",
            "risk_level": "high",
            "reason": "未满足“断线后继续存储 QoS1/QoS2 消息”。",
        },
        15: {
            "status": "部分满足",
            "comment": "clean_session=0 可重关联历史订阅，但未恢复离线在途消息状态。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2775",
                "wolfMQTT-master/src/mqtt_broker.c:2778",
                "wolfMQTT-master/src/mqtt_broker.c:1745",
                "wolfMQTT-master/src/mqtt_broker.c:1780",
            ],
            "category": "会话恢复覆盖不完整",
            "risk_level": "high",
            "reason": "会话恢复仅覆盖订阅映射，未覆盖 QoS 在途消息。",
        },
        16: {
            "status": "满足",
            "comment": "clean_session=1 分支会移除同 client_id 历史订阅并开启新会话语义。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2780",
                "wolfMQTT-master/src/mqtt_broker.c:2782",
                "wolfMQTT-master/src/mqtt_broker.c:1677",
            ],
        },
        17: {
            "status": "不满足",
            "comment": "零长度 ClientId 未强制要求 clean_session=1；客户端和服务端均未做该联动约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:804",
                "wolfMQTT-master/src/mqtt_packet.c:869",
                "wolfMQTT-master/src/mqtt_broker.c:2744",
                "wolfMQTT-master/src/mqtt_broker.c:2972",
            ],
            "category": "零长度ClientId与CleanSession联动缺失",
            "risk_level": "high",
            "reason": "允许空 ClientId 且 clean_session=0 进入后续处理。",
        },
        18: {
            "status": "不满足",
            "comment": "空 ClientId + clean_session=0 未返回 0x02 并关闭连接，MQTT5 路径会进入自动分配 ID。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2918",
                "wolfMQTT-master/src/mqtt_broker.c:2972",
                "wolfMQTT-master/src/mqtt_broker.c:2980",
                "wolfMQTT-master/src/mqtt_broker.c:3043",
            ],
            "category": "零长度ClientId与CleanSession联动缺失",
            "risk_level": "high",
            "reason": "规范要求拒绝+0x02，但实现会在特定路径接受并分配 ID。",
        },
        19: {
            "status": "不满足",
            "comment": "同 ID17：空 ClientId 场景未绑定 clean_session=1。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:804",
                "wolfMQTT-master/src/mqtt_packet.c:869",
                "wolfMQTT-master/src/mqtt_broker.c:2972",
            ],
            "category": "零长度ClientId与CleanSession联动缺失",
            "risk_level": "high",
            "reason": "clean_session 常量约束未落地。",
        },
        20: {
            "status": "不满足",
            "comment": "空 ClientId + clean_session=0 的违规路径未执行 0x02 + 断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2918",
                "wolfMQTT-master/src/mqtt_broker.c:2972",
                "wolfMQTT-master/src/mqtt_broker.c:3043",
            ],
            "category": "零长度ClientId与CleanSession联动缺失",
            "risk_level": "high",
            "reason": "规范拒绝路径缺失。",
        },
        21: {
            "status": "部分满足",
            "comment": "可确认 clean_session=1 时 CONNACK flags 固定为 0，但该条规则原文信息不完整。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2917",
                "wolfMQTT-master/src/mqtt_broker.c:2918",
            ],
            "category": "规则文本信息不完整",
            "risk_level": "low",
            "reason": "规则目标字段未完整展开，仅能就可观测行为做部分映射。",
        },
        22: {
            "status": "满足",
            "comment": "clean_session=1 路径会删除历史订阅并进入新会话。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2780",
                "wolfMQTT-master/src/mqtt_broker.c:2782",
            ],
        },
        23: {
            "status": "不适用",
            "comment": "该条为客户端重连策略建议（should），不属于 broker 协议强制校验项。",
            "evidence": [],
        },
        24: {
            "status": "不适用",
            "comment": "该条为客户端使用建议（随机 ClientId 与 clean_session=0 组合的使用约束），非 broker 强制规则。",
            "evidence": [],
        },
        25: {
            "status": "部分满足",
            "comment": "实现保留 clean_session=0 的订阅会话语义，但离线 QoS 消息持久化缺失。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:1397",
                "wolfMQTT-master/src/mqtt_broker.c:3581",
                "wolfMQTT-master/src/mqtt_broker.c:3586",
            ],
            "category": "会话持久化仅保留订阅",
            "risk_level": "high",
            "reason": "仅满足订阅层面的“保持会话”。",
        },
        26: {
            "status": "不适用",
            "comment": "该条为客户端生命周期建议，不是服务端协议接收校验规则。",
            "evidence": [],
        },
        27: {
            "status": "不满足",
            "comment": "clean_session=0 重连后未实现未确认 PUBLISH/PUBREL 的离线重发机制。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2777",
                "wolfMQTT-master/src/mqtt_broker.c:3291",
                "wolfMQTT-master/src/mqtt_broker.c:3333",
            ],
            "category": "重连重传语义缺失",
            "risk_level": "high",
            "reason": "无离线 inflight 队列与原 packet_id 重发流程。",
        },
        28: {
            "status": "部分满足",
            "comment": "clean_session=0 的“会话恢复”仅在订阅重关联层面实现。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2775",
                "wolfMQTT-master/src/mqtt_broker.c:2778",
                "wolfMQTT-master/src/mqtt_broker.c:1745",
            ],
            "category": "会话恢复覆盖不完整",
            "risk_level": "high",
            "reason": "恢复范围不含离线 QoS 流状态。",
        },
        29: {
            "status": "不满足",
            "comment": "接收链路未执行 UTF-8 well-formed 校验，无法保证 ill-formed 时断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:356",
                "wolfMQTT-master/src/mqtt_broker.c:2694",
            ],
            "category": "UTF-8协议校验缺失",
            "risk_level": "high",
            "reason": "字符串解码仅处理长度与边界，不验证 Unicode 合法性。",
        },
        30: {
            "status": "满足",
            "comment": "服务端允许零长度 ClientId（可选行为），并在 MQTT5 路径进入特殊处理。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1038",
                "wolfMQTT-master/src/mqtt_broker.c:2972",
            ],
        },
        31: {
            "status": "部分满足",
            "comment": "实现未见 BOM 去除逻辑（不会主动 strip），但也未显式做 U+FEFF 语义解释校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:354",
                "wolfMQTT-master/src/mqtt_broker.c:175",
                "wolfMQTT-master/src/mqtt_broker.c:202",
            ],
            "category": "UTF-8语义保障不足",
            "risk_level": "low",
            "reason": "表现上不会剥离 BOM，但缺少明确语义验证路径。",
        },
        32: {
            "status": "不满足",
            "comment": "未发现对 UTF-8 代理区编码（U+D800~U+DFFF）的拒绝校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:356",
            ],
            "category": "UTF-8协议校验缺失",
            "risk_level": "high",
            "reason": "缺少 surrogate code point 编码过滤。",
        },
        33: {
            "status": "不满足",
            "comment": "未发现 U+0000 编码拒绝校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:356",
                "wolfMQTT-master/src/mqtt_broker.c:175",
            ],
            "category": "UTF-8协议校验缺失",
            "risk_level": "high",
            "reason": "未实现空字符编码的协议级禁止规则。",
        },
        34: {
            "status": "不满足",
            "comment": "含 U+0000 的 UTF-8 字符串未触发规范要求的断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:356",
                "wolfMQTT-master/src/mqtt_broker.c:2694",
            ],
            "category": "UTF-8协议校验缺失",
            "risk_level": "high",
            "reason": "缺少 U+0000 接收拒绝和断链逻辑。",
        },
        35: {
            "status": "满足",
            "comment": "CONNECT 负载编码与解码顺序均以 ClientId 为首，后续字段顺序符合规范。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:912",
                "wolfMQTT-master/src/mqtt_packet.c:932",
                "wolfMQTT-master/src/mqtt_packet.c:937",
                "wolfMQTT-master/src/mqtt_packet.c:940",
            ],
        },
        36: {
            "status": "满足",
            "comment": "ClientId 为 CONNECT 负载首字段且必经解析路径。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:770",
                "wolfMQTT-master/src/mqtt_packet.c:1038",
            ],
        },
        37: {
            "status": "满足",
            "comment": "实现中 ClientId 字段是 CONNECT 的必经字段。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:770",
                "wolfMQTT-master/src/mqtt_packet.c:1038",
            ],
        },
        38: {
            "status": "满足",
            "comment": "除 ClientId 外，Will/用户名/密码均作为可选字段处理。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:805",
                "wolfMQTT-master/src/mqtt_packet.c:843",
                "wolfMQTT-master/src/mqtt_packet.c:846",
            ],
        },
        39: {
            "status": "不满足",
            "comment": "ClientId UTF-8 合法性（well-formed）未校验，无法保证非法输入断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:1038",
                "wolfMQTT-master/src/mqtt_broker.c:2694",
            ],
            "category": "UTF-8协议校验缺失",
            "risk_level": "high",
            "reason": "ClientId 的 UTF-8 合法性验证缺位。",
        },
        40: {
            "status": "不满足",
            "comment": "ClientId 未显式过滤 U+0000 编码，也未在该场景强制断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:1038",
                "wolfMQTT-master/src/mqtt_broker.c:175",
            ],
            "category": "UTF-8协议校验缺失",
            "risk_level": "high",
            "reason": "空字符编码规则未实现。",
        },
        41: {
            "status": "部分满足",
            "comment": "协议层长度字段覆盖 0..65535，但 broker 侧有实现上限（如静态内存宏限制）。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:366",
                "wolfMQTT-master/src/mqtt_broker.c:2713",
            ],
            "category": "ClientId长度约束与实现上限差异",
            "risk_level": "medium",
            "reason": "协议长度域与具体实现上限并不完全等价。",
        },
        42: {
            "status": "满足",
            "comment": "代码路径可识别并处理零长度 ClientId。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1038",
                "wolfMQTT-master/src/mqtt_broker.c:2972",
            ],
        },
        43: {
            "status": "不满足",
            "comment": "零长度 ClientId + clean_session=0 未执行 0x02 拒绝并断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2744",
                "wolfMQTT-master/src/mqtt_broker.c:2918",
                "wolfMQTT-master/src/mqtt_broker.c:2972",
            ],
            "category": "零长度ClientId与CleanSession联动缺失",
            "risk_level": "high",
            "reason": "规范拒绝条件未落地。",
        },
        44: {
            "status": "部分满足",
            "comment": "MQTT5 路径会给空 ClientId 分配 `auto-xxxx`，但覆盖范围受协议版本与实现条件限制。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2972",
                "wolfMQTT-master/src/mqtt_broker.c:2975",
                "wolfMQTT-master/src/mqtt_broker.c:2980",
            ],
            "category": "零长度ClientId唯一分配覆盖不完整",
            "risk_level": "medium",
            "reason": "仅 MQTT5 接受分支下赋值，不是统一行为。",
        },
        45: {
            "status": "部分满足",
            "comment": "同 ID44：有服务端分配 ID 能力，但并非统一覆盖所有允许空 ID 场景。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2972",
                "wolfMQTT-master/src/mqtt_broker.c:2975",
                "wolfMQTT-master/src/mqtt_broker.c:2980",
            ],
            "category": "零长度ClientId唯一分配覆盖不完整",
            "risk_level": "medium",
            "reason": "分配逻辑存在条件性。",
        },
        46: {
            "status": "部分满足",
            "comment": "ClientId 超长拒绝路径会返回 0x02 并断链，但对其他应拒绝场景覆盖不全。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2713",
                "wolfMQTT-master/src/mqtt_broker.c:2726",
                "wolfMQTT-master/src/mqtt_broker.c:3043",
                "wolfMQTT-master/src/mqtt_broker.c:3541",
            ],
            "category": "ClientId拒绝返回码0x02覆盖不完整",
            "risk_level": "medium",
            "reason": "仅部分拒绝路径绑定 0x02。",
        },
        47: {
            "status": "满足",
            "comment": "0x02(Identifier rejected) 语义在枚举定义和拒绝路径中均有对应。",
            "evidence": [
                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:382",
                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:383",
                "wolfMQTT-master/src/mqtt_broker.c:2726",
            ],
        },
        48: {
            "status": "部分满足",
            "comment": "实现可接受常见合法 ClientId，但未见 1..23 与字符集白名单的显式校验逻辑。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2713",
                "wolfMQTT-master/src/mqtt_broker.c:2731",
            ],
            "category": "ClientId字符集白名单未显式校验",
            "risk_level": "medium",
            "reason": "缺少规范文本级别的长度/字符集显式检查。",
        },
        49: {
            "status": "部分满足",
            "comment": "存在 0x02 拒绝路径，但应拒绝的空 ClientId+clean_session=0 场景未覆盖。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2726",
                "wolfMQTT-master/src/mqtt_broker.c:2972",
            ],
            "category": "ClientId拒绝返回码0x02覆盖不完整",
            "risk_level": "medium",
            "reason": "拒绝码语义具备，但实际触发覆盖不完整。",
        },
        50: {
            "status": "不满足",
            "comment": "通用 UTF-8 字符串接收链路未做 well-formed 校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:356",
                "wolfMQTT-master/src/mqtt_broker.c:2694",
            ],
            "category": "UTF-8协议校验缺失",
            "risk_level": "high",
            "reason": "未实现 Unicode/RFC3629 级别的格式验证。",
        },
    }


def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:
    results: list[dict] = []
    for i, change in enumerate(changes, start=1):
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
        "scope": "source_changes_index_0_to_49",
        "display_scope": "001-050",
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
        "# wolfMQTT-master 001-050 对比结果",
        "",
        f"- 对比输入: `output/02_variable_changes.json` 的索引 `0..49`（共 {len(rows)} 条）",
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
    results = compare["results"]
    filtered = [r for r in results if r["status"] in ("部分满足", "不满足")]
    class_rows: list[dict] = []

    for r in filtered:
        m = mapping[r["id"]]
        class_rows.append(
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

    status_counter = Counter([x["status"] for x in class_rows])
    risk_counter = Counter([x["risk_level"] for x in class_rows])

    category_summary: dict[str, dict] = defaultdict(lambda: {"count": 0, "partial": 0, "unsatisfied": 0})
    for row in class_rows:
        cat = row["category"]
        category_summary[cat]["count"] += 1
        if row["status"] == "部分满足":
            category_summary[cat]["partial"] += 1
        elif row["status"] == "不满足":
            category_summary[cat]["unsatisfied"] += 1

    return {
        "scope": "wolfMQTT-master 001-050 partial+unsatisfied",
        "total_reviewed": len(class_rows),
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
        "results": class_rows,
    }


def build_classification_md(classification: dict) -> str:
    lines = [
        "# wolfMQTT-master 001-050 未满足/部分满足分类",
        "",
        f"- total_reviewed: {classification['total_reviewed']}",
        f"- 部分满足: {classification['status_summary']['部分满足']}",
        f"- 不满足: {classification['status_summary']['不满足']}",
        (
            "- 风险分布: "
            f"low={classification['risk_summary']['low']}, "
            f"medium={classification['risk_summary']['medium']}, "
            f"high={classification['risk_summary']['high']}"
        ),
        "",
        "## 分类汇总",
        "",
        "| 分类 | 数量 | 部分满足 | 不满足 |",
        "|---|---:|---:|---:|",
    ]
    for cat, summary in classification["category_summary"].items():
        lines.append(
            f"| {md_escape(cat)} | {summary['count']} | {summary['partial']} | {summary['unsatisfied']} |"
        )

    lines.extend(
        [
            "",
            "## 明细",
            "",
            "| ID | source_idx | 状态 | 风险 | 分类 | 说明 |",
            "|---:|---:|---|---|---|---|",
        ]
    )
    for row in classification["results"]:
        lines.append(
            "| {id} | {idx} | {status} | {risk} | {cat} | {reason} |".format(
                id=row["id"],
                idx=row["source_index"],
                status=row["status"],
                risk=row["risk_level"],
                cat=md_escape(row["category"]),
                reason=md_escape(row["reason"]),
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    source = load_json(SOURCE_JSON)
    changes = source.get("changes", [])[:50]
    if len(changes) != 50:
        raise RuntimeError(f"Expected 50 records for 001-050, got {len(changes)}")

    mapping = rule_mapping()
    if sorted(mapping.keys()) != list(range(1, 51)):
        raise RuntimeError("Rule mapping must cover IDs 1..50")

    compare = build_compare(changes, mapping)
    save_json(OUT_COMPARE_JSON, compare)
    OUT_COMPARE_MD.write_text(build_compare_md(compare), encoding="utf-8")
    OUT_SIMPLE_TXT.write_text(build_simple_txt(compare), encoding="utf-8")

    classification = build_classification(compare, mapping)
    save_json(OUT_CLASS_JSON, classification)
    OUT_CLASS_MD.write_text(build_classification_md(classification), encoding="utf-8")

    print("Generated:")
    print(f"- {OUT_COMPARE_JSON}")
    print(f"- {OUT_COMPARE_MD}")
    print(f"- {OUT_SIMPLE_TXT}")
    print(f"- {OUT_CLASS_JSON}")
    print(f"- {OUT_CLASS_MD}")


if __name__ == "__main__":
    main()

