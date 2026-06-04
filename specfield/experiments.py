#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline_utils import OpenAICompatClient, now_ts, write_json  # noqa: E402
from specfield.core import (  # noqa: E402
    CodeIndex,
    EvidenceBundle,
    FieldRule,
    PipelineConfig,
    align_rule_to_code,
    evidence_driven_reasoning,
    run_validation_agent,
)
from specfield.core import heuristic_reason, read_json  # noqa: E402


CONFIGS = (
    "direct-agent",
    "generic-rag",
    "field-rules",
    "iter-reasoning",
    "forced-binary",
    "full-system",
)


DIRECT_AGENT_PROMPT = """
Compare this standard rule directly against the implementation code snippets.
Return strict JSON:
{
  "y": "CONSISTENT|INCONSISTENT|INSUFFICIENT",
  "R": "reason",
  "U": [],
  "E": {"code": []},
  "confidence": 0.0
}

Rule:
{rule_json}

Code snippets:
{snippets_json}
""".strip()


def make_client(config: PipelineConfig) -> OpenAICompatClient | None:
    if not config.use_llm or not config.api_key:
        return None
    return OpenAICompatClient(config.api_key, config.base_url, config.model)


def load_rules(path: str) -> list[FieldRule]:
    obj = read_json(path)
    rows = obj.get("rules", obj if isinstance(obj, list) else [])
    rules = []
    for i, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        if {"f", "C", "A", "M", "E", "action_type"}.issubset(row):
            data = dict(row)
        else:
            data = {
                "rule_id": f"rule_{i:05d}",
                "f": row.get("variable_name", row.get("f", "")),
                "C": row.get("change_condition", row.get("C", "")),
                "A": row.get("change_action", row.get("A", "")),
                "M": row.get("modality", row.get("M", "MUST")),
                "E": row.get("evidence", row.get("E", "")),
                "action_type": row.get("action_type", "compare"),
                "source_location": row.get("source_location", ""),
                "source_chunk_id": row.get("source_chunk_id", ""),
            }
        data.setdefault("rule_id", f"rule_{i:05d}")
        data.setdefault("source_location", "")
        data.setdefault("source_chunk_id", "")
        data.setdefault("field_id", "")
        data.setdefault("explicit_or_inferred", "explicit")
        data.setdefault("note", "")
        data.setdefault("out_of_scope", False)
        data.setdefault("validation_errors", [])
        rules.append(FieldRule(**data))
    return rules


def generic_rag_bundle(index: CodeIndex, rule: FieldRule, config: PipelineConfig) -> EvidenceBundle:
    from evalute.context.rule_to_code_alignment_baselines import bm25_candidates, build_query_tokens, candidate_to_context, rank_variables

    rule_dict = {"variable_name": rule.f, "change_condition": rule.C, "change_action": rule.A, "evidence": rule.E, "action_type": rule.action_type}
    aliases = [rule.f]
    qtokens = build_query_tokens(rule_dict, aliases)
    cands = bm25_candidates(index.chunks, qtokens, config.top_snippets, config.max_snippet_lines)
    contexts = [candidate_to_context(c) for c in cands]
    ranked = rank_variables(cands, aliases, qtokens, config.top_variables)
    return EvidenceBundle(rule.rule_id, rule, ranked, contexts, contexts, [], "Generic RAG BM25 retrieval.")


def direct_agent_judgment(index: CodeIndex, rule: FieldRule, config: PipelineConfig, client: OpenAICompatClient | None) -> dict[str, Any]:
    bundle = generic_rag_bundle(index, rule, config)
    if client is not None:
        prompt = DIRECT_AGENT_PROMPT.replace("{rule_json}", json.dumps(asdict(rule), ensure_ascii=False, indent=2)).replace(
            "{snippets_json}", json.dumps(bundle.contexts[: config.top_snippets], ensure_ascii=False, indent=2)[:25000]
        )
        try:
            raw = client.chat(prompt)
            obj = json.loads(raw[raw.find("{") : raw.rfind("}") + 1])
            label = str(obj.get("y", "INSUFFICIENT")).upper()
            if label not in {"CONSISTENT", "INCONSISTENT", "INSUFFICIENT"}:
                label = "INSUFFICIENT"
            obj["y"] = label
            obj["raw_response"] = raw
            return {"rule": asdict(rule), "bundle": asdict(bundle), "reasoning": [obj], "validation": {}}
        except Exception as exc:  # noqa: BLE001
            rr = heuristic_reason(bundle, 0)
            rr.U.append(f"direct agent LLM failed: {exc}")
            return {"rule": asdict(rule), "bundle": asdict(bundle), "reasoning": [asdict(rr)], "validation": {}}
    rr = heuristic_reason(bundle, 0)
    return {"rule": asdict(rule), "bundle": asdict(bundle), "reasoning": [asdict(rr)], "validation": {}}


def force_binary(item: dict[str, Any]) -> dict[str, Any]:
    rounds = item.get("reasoning", [])
    if not rounds:
        return item
    final = rounds[-1]
    if final.get("y") == "INSUFFICIENT":
        text = json.dumps(item.get("bundle", {}), ensure_ascii=False).lower()
        final["y"] = "INCONSISTENT" if any(k in text for k in ["no explicit", "missing", "error", "reject"]) else "CONSISTENT"
        final["R"] = (final.get("R") or "") + " Forced binary diagnostic converted INSUFFICIENT."
    return item


def run_component(config_name: str, rules: list[FieldRule], config: PipelineConfig, output_dir: Path) -> dict[str, Any]:
    client = make_client(config)
    index = CodeIndex(Path(config.repo_root), config.max_files, config.max_file_size, config.max_code_chunks)
    fields_by_id = {}
    judgments = []
    for i, rule in enumerate(rules, start=1):
        print(f"[{now_ts()}] {config_name} {i}/{len(rules)} {rule.rule_id}")
        if config_name == "direct-agent":
            item = direct_agent_judgment(index, rule, config, client)
        elif config_name == "generic-rag":
            bundle = generic_rag_bundle(index, rule, config)
            rr = heuristic_reason(bundle, 0)
            item = {"rule": asdict(rule), "bundle": asdict(bundle), "reasoning": [asdict(rr)], "validation": {}}
        else:
            bundle = align_rule_to_code(index, fields_by_id, rule, config, client if config.use_llm else None)
            if config_name == "field-rules":
                rr = heuristic_reason(bundle, 0)
                item = {"rule": asdict(rule), "bundle": asdict(bundle), "reasoning": [asdict(rr)], "validation": {}}
            else:
                rounds = evidence_driven_reasoning(index, bundle, config, client if config.use_llm else None)
                item = {"rule": asdict(rule), "bundle": asdict(bundle), "reasoning": [asdict(r) for r in rounds], "validation": {}}
                if config_name == "full-system" and config.run_validation and rounds[-1].y == "INCONSISTENT":
                    validation_dir = output_dir / "validation_artifacts" / config_name
                    validation = run_validation_agent(rule, rounds[-1], bundle, config, client if config.use_llm else None, validation_dir)
                    rounds[-1].T = validation
                    item = {"rule": asdict(rule), "bundle": asdict(bundle), "reasoning": [asdict(r) for r in rounds], "validation": validation}
            if config_name == "forced-binary":
                item = force_binary(item)
        judgments.append(item)
    result = {"meta": {"configuration": config_name, "generated_at": now_ts(), "rule_count": len(rules)}, "judgments": judgments}
    write_json(output_dir / f"{config_name.replace('-', '_')}.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SpecField RQ5 component configurations.")
    parser.add_argument("--config", choices=[*CONFIGS, "all"], required=True)
    parser.add_argument("--rules", required=True, help="Rules JSON from specfield/core.py or step2 output.")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output-dir", default="output/specfield_components")
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--base-url", default="https://api.bltcy.ai/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--max-files", type=int, default=20000)
    parser.add_argument("--max-file-size", type=int, default=600000)
    parser.add_argument("--max-code-chunks", type=int, default=6000)
    parser.add_argument("--top-files", type=int, default=15)
    parser.add_argument("--top-variables", type=int, default=8)
    parser.add_argument("--top-snippets", type=int, default=12)
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--no-validation", action="store_true")
    parser.add_argument("--validation-command", action="append", default=[])
    args = parser.parse_args()

    rules = load_rules(args.rules)
    if args.limit > 0:
        rules = rules[: args.limit]
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = PipelineConfig(
        standard_doc="",
        repo_root=args.repo_root,
        output_dir=str(out_dir),
        api_key=args.api_key,
        base_url=args.base_url,
        model=args.model,
        use_llm=args.use_llm,
        max_files=args.max_files,
        max_file_size=args.max_file_size,
        max_code_chunks=args.max_code_chunks,
        top_files=args.top_files,
        top_variables=args.top_variables,
        top_snippets=args.top_snippets,
        max_rounds=args.max_rounds,
        run_validation=not args.no_validation,
        validation_commands=args.validation_command,
    )
    configs = list(CONFIGS) if args.config == "all" else [args.config]
    manifest = {}
    for name in configs:
        result = run_component(name, rules, cfg, out_dir)
        manifest[name] = str(out_dir / f"{name.replace('-', '_')}.json")
    write_json(out_dir / "manifest.json", manifest)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
