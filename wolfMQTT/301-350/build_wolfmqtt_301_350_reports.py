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

OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_301_350.json"
OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_301_350.md"
OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_301_350_simple.txt"
OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_301_350_partial_unsat_classification.json"
OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_301_350_partial_unsat_classification.md"


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
            cache[abs_path] = abs_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
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
        301: {
            "status": "满足",
            "comment": "Will Flag=0 时解码侧 `enable_lwt` 为 0，编码侧也仅在启用时置位该标志。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:872",
                "wolfMQTT-master/src/mqtt_packet.c:873",
                "wolfMQTT-master/src/mqtt_packet.c:1000",
            ],
        },
        302: {
            "status": "满足",
            "comment": "Will Flag=1 时可正确置位并在解码中读取为启用 LWT。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:872",
                "wolfMQTT-master/src/mqtt_packet.c:873",
                "wolfMQTT-master/src/mqtt_packet.c:1001",
            ],
        },
        303: {
            "status": "满足",
            "comment": "Will Flag=1 时，CONNECT 载荷解析进入 LWT 字段分支。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1048",
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:1098",
            ],
        },
        304: {
            "status": "满足",
            "comment": "服务端 CONNECT 处理会依据解码得到的 `mc.enable_lwt` 执行 Will 逻辑。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1001",
                "wolfMQTT-master/src/mqtt_broker.c:2739",
                "wolfMQTT-master/src/mqtt_broker.c:2789",
            ],
        },
        305: {
            "status": "部分满足",
            "comment": "Will Flag=0 时不解析 Will 字段，但未做“剩余载荷必须恰好消费完”的强校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1048",
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "Will Flag=0 的载荷一致性校验不足",
            "risk_level": "high",
            "reason": "可能放行 Flag 与载荷不一致的 CONNECT 报文。",
        },
        306: {
            "status": "部分满足",
            "comment": "同 ID305：缺少对 Will Flag=0 且载荷仍含 Will 内容的显式拒绝。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1048",
                "wolfMQTT-master/src/mqtt_packet.c:1142",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "Will Flag=0 的载荷一致性校验不足",
            "risk_level": "high",
            "reason": "协议一致性约束不完整。",
        },
        307: {
            "status": "满足",
            "comment": "Will Flag=1 时必须进入 LWT 字段解析，字段缺失会触发越界/解码错误。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1048",
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:1090",
            ],
        },
        308: {
            "status": "满足",
            "comment": "CONNECT 被接受后，服务端会存储 Will Topic/Payload/QoS/Retain 并关联到客户端连接。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2789",
                "wolfMQTT-master/src/mqtt_broker.c:2833",
                "wolfMQTT-master/src/mqtt_broker.c:2845",
            ],
        },
        309: {
            "status": "满足",
            "comment": "收到 DISCONNECT 时清除 Will，不触发发布。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3579",
                "wolfMQTT-master/src/mqtt_broker.c:3580",
                "wolfMQTT-master/src/mqtt_broker.c:3588",
            ],
        },
        310: {
            "status": "满足",
            "comment": "Will 发布后立即清除；正常 DISCONNECT 也清除。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2438",
                "wolfMQTT-master/src/mqtt_broker.c:2441",
                "wolfMQTT-master/src/mqtt_broker.c:3580",
            ],
        },
        311: {
            "status": "满足",
            "comment": "同 ID310，Will 生命周期包含发布后/正常断开后清理。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2012",
                "wolfMQTT-master/src/mqtt_broker.c:2417",
                "wolfMQTT-master/src/mqtt_broker.c:3580",
            ],
        },
        312: {
            "status": "满足",
            "comment": "Will Flag=1 时，Will topic 与 Will payload 在 CONNECT 载荷中按顺序作为后续字段解析。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:1098",
                "wolfMQTT-master/src/mqtt_packet.c:1118",
            ],
        },
        313: {
            "status": "满足",
            "comment": "连接接受并启用 LWT 时会将 Will 持久于连接上下文（`bc->has_will=1`）。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2789",
                "wolfMQTT-master/src/mqtt_broker.c:2845",
                "wolfMQTT-master/src/mqtt_broker.c:3043",
            ],
        },
        314: {
            "status": "满足",
            "comment": "Will Flag=1 的 CONNECT 解析必须包含 Will 字段路径。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1048",
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:1115",
            ],
        },
        315: {
            "status": "部分满足",
            "comment": "编码侧仅在 `enable_lwt` 时设置 Will QoS 位；但解码侧未验证 Will Flag=0 时 QoS 位必须为 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:872",
                "wolfMQTT-master/src/mqtt_packet.c:875",
                "wolfMQTT-master/src/mqtt_packet.c:1053",
            ],
            "category": "Will QoS/Retain 与 Will Flag 的联动校验不足",
            "risk_level": "high",
            "reason": "入站 CONNECT 可能携带规范外标志位组合。",
        },
        316: {
            "status": "部分满足",
            "comment": "同 ID315：缺少对 Will Flag=0 下 Will QoS 位非零的协议拒绝。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1000",
                "wolfMQTT-master/src/mqtt_packet.c:1053",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "Will QoS/Retain 与 Will Flag 的联动校验不足",
            "risk_level": "high",
            "reason": "标志位一致性校验不完整。",
        },
        317: {
            "status": "部分满足",
            "comment": "同 ID315/316：未做 Will Flag=0 时 Will QoS=0 的强制验证。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1001",
                "wolfMQTT-master/src/mqtt_packet.c:1054",
                "wolfMQTT-master/src/mqtt_packet.c:1142",
            ],
            "category": "Will QoS/Retain 与 Will Flag 的联动校验不足",
            "risk_level": "high",
            "reason": "协议位约束未被严格执行。",
        },
        318: {
            "status": "不满足",
            "comment": "未发现对 Will QoS=3（保留值）的拒绝逻辑，解码直接取两位值。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1053",
                "wolfMQTT-master/src/mqtt_packet.c:1054",
                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:323",
            ],
            "category": "Will QoS 合法取值校验缺失",
            "risk_level": "high",
            "reason": "Will QoS 保留值可能进入后续处理路径。",
        },
        319: {
            "status": "不满足",
            "comment": "同 ID318：未限制 Will QoS 仅允许 {0,1,2}。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1054",
                "wolfMQTT-master/src/mqtt_broker.c:2833",
                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:335",
            ],
            "category": "Will QoS 合法取值校验缺失",
            "risk_level": "high",
            "reason": "协议保留值未被拦截。",
        },
        320: {
            "status": "不满足",
            "comment": "同 ID318/319：Will QoS=3 未被判定为错误。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1054",
                "wolfMQTT-master/src/mqtt_broker.c:2833",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "Will QoS 合法取值校验缺失",
            "risk_level": "high",
            "reason": "可能导致非标准 QoS 分发行为。",
        },
        321: {
            "status": "满足",
            "comment": "Will Flag=1 时，Will QoS 从 CONNECT flags 提取并被服务端保存使用。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1053",
                "wolfMQTT-master/src/mqtt_packet.c:1054",
                "wolfMQTT-master/src/mqtt_broker.c:2833",
            ],
        },
        322: {
            "status": "部分满足",
            "comment": "编码侧可保证 Will Flag=0 时不会置位 Will Retain；但解码侧未显式拒绝违规置位。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:872",
                "wolfMQTT-master/src/mqtt_packet.c:879",
                "wolfMQTT-master/src/mqtt_packet.c:1056",
            ],
            "category": "Will QoS/Retain 与 Will Flag 的联动校验不足",
            "risk_level": "high",
            "reason": "入站 CONNECT 位组合校验缺失。",
        },
        323: {
            "status": "部分满足",
            "comment": "同 ID322：Will Flag=0 时 Will Retain 必为 0 的接收侧强校验不存在。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1000",
                "wolfMQTT-master/src/mqtt_packet.c:1056",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "Will QoS/Retain 与 Will Flag 的联动校验不足",
            "risk_level": "high",
            "reason": "协议一致性约束不完整。",
        },
        324: {
            "status": "满足",
            "comment": "Will Retain=0 时不会写 retained 存储，Will 普通分发。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2453",
                "wolfMQTT-master/src/mqtt_broker.c:2454",
                "wolfMQTT-master/src/mqtt_broker.c:2490",
            ],
        },
        325: {
            "status": "满足",
            "comment": "Will Retain=1 时进入 retained 处理路径（存储/删除 retained）。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2454",
                "wolfMQTT-master/src/mqtt_broker.c:2459",
                "wolfMQTT-master/src/mqtt_broker.c:2466",
            ],
        },
        326: {
            "status": "满足",
            "comment": "Will Retain 从 CONNECT flags 解码并写入连接状态。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1056",
                "wolfMQTT-master/src/mqtt_broker.c:2834",
                "wolfMQTT-master/src/mqtt_broker.c:2848",
            ],
        },
        327: {
            "status": "部分满足",
            "comment": "Will Flag=0 时不解析 Will topic，但未严格拒绝多余 Will topic 载荷。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1048",
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "Will Flag=0 的载荷一致性校验不足",
            "risk_level": "high",
            "reason": "可兼容接受不符合字段出现规则的报文。",
        },
        328: {
            "status": "部分满足",
            "comment": "同 ID327：缺乏对 Flag=0 且出现 Will topic 字段的显式无效判定。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1000",
                "wolfMQTT-master/src/mqtt_packet.c:1048",
                "wolfMQTT-master/src/mqtt_packet.c:1142",
            ],
            "category": "Will Flag=0 的载荷一致性校验不足",
            "risk_level": "high",
            "reason": "与协议字段出现条件存在偏差。",
        },
        329: {
            "status": "满足",
            "comment": "Will Flag=1 时 CONNECT 解析会读取 Will topic。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1048",
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:1096",
            ],
        },
        330: {
            "status": "部分满足",
            "comment": "Will topic 仅做长度前缀字符串解码，无 UTF-8 语义合法性校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
            "category": "Will topic UTF-8 语义校验缺失",
            "risk_level": "high",
            "reason": "无法拦截 malformed UTF-8 Will topic。",
        },
        331: {
            "status": "满足",
            "comment": "Will Flag=1 时，Will topic 是 CONNECT 中 Will 区段的首字段并先于 Will payload 解析。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:1098",
                "wolfMQTT-master/src/mqtt_packet.c:1118",
            ],
        },
        332: {
            "status": "满足",
            "comment": "Will Flag=1 的解析路径会要求并消费 Will topic 字段。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1048",
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:1090",
            ],
        },
        333: {
            "status": "部分满足",
            "comment": "Will topic 采用长度前缀字符串格式，但未校验 UTF-8 码点合法性。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:366",
            ],
            "category": "Will topic UTF-8 语义校验缺失",
            "risk_level": "high",
            "reason": "仅完成长度层校验。",
        },
        334: {
            "status": "部分满足",
            "comment": "同 ID330/333：Will topic 缺失 UTF-8 字符语义校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
            "category": "Will topic UTF-8 语义校验缺失",
            "risk_level": "high",
            "reason": "不能保证 UTF-8 数据严格合规。",
        },
        335: {
            "status": "不满足",
            "comment": "未发现对 Will topic 中 U+0000 的显式拒绝。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1087",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_broker.c:2803",
            ],
            "category": "Will topic 禁用字符校验缺失（U+0000）",
            "risk_level": "high",
            "reason": "NUL 会破坏字符串一致性并影响后续匹配/日志。",
        },
        336: {
            "status": "满足",
            "comment": "Will topic 字符串长度采用 2 字节长度字段，范围可覆盖 0..65535 并含边界校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:285",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
        },
    }


def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:
    results: list[dict] = []
    for i, change in enumerate(changes, start=301):
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
        "scope": "source_changes_index_300_to_335",
        "display_scope": "301-336",
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
        "# wolfMQTT-master 301-336 对比结果（存放于 301-350 目录）",
        "",
        f"- 对比源：`output/02_variable_changes.json` 的 `300..335`（共 {len(rows)} 条）",
        "- 目标代码：`wolfMQTT-master`",
        f"- 满足：{meta['counts']['满足']}",
        f"- 部分满足：{meta['counts']['部分满足']}",
        f"- 不满足：{meta['counts']['不满足']}",
        f"- 不适用：{meta['counts']['不适用']}",
        f"- 待确认：{meta['counts']['待确认']}",
        (
            "- 证据定位校验："
            f"all_locatable={meta['evidence_validation']['all_locatable']}, "
            f"references={meta['evidence_validation']['total_references']}"
        ),
        "",
        "| ID | source_idx | variable | action | 状态 | 结论说明 | 证据数 |",
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
        "scope": "wolfMQTT-master 301-336 partial+unsatisfied",
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
        "# wolfMQTT-master 301-336 未满足/部分满足分类",
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
            "| ID | source_idx | 状态 | 风险 | 分类 | 原因 |",
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
    changes = source.get("changes", [])[300:]

    mapping = rule_mapping()
    if len(changes) != len(mapping):
        raise RuntimeError(
            f"Expected {len(mapping)} items for 301..{300+len(mapping)}, got {len(changes)}"
        )
    if sorted(mapping.keys()) != list(range(301, 301 + len(mapping))):
        raise RuntimeError("Rule mapping keys are not continuous from 301")

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

