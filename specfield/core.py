#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline_utils import (  # noqa: E402
    OpenAICompatClient,
    aliases_from_record,
    build_variable_catalog,
    extract_json_array,
    field_name_from_record,
    first_text,
    is_packet_field_name,
    now_ts,
    normalize_text,
    parent_from_record,
    source_evidence_from_record,
    source_locations_from_record,
    write_json,
    write_text,
)
from step0_preprocess import run_preprocess  # noqa: E402
from utils.variable_context_pipeline import (  # noqa: E402
    Chunk,
    Hit,
    build_semantic_chunks,
    build_symbol_index,
    classify_line_kind,
    collect_files,
    expand_var_aliases,
    fallback_text_search,
    infer_category,
    parse_var_names,
    render_snippet,
    run_rg_json,
    split_identifier,
    symbol_at_line,
    tokenize,
)

ACTION_TYPES = {
    "assign",
    "derive",
    "select",
    "require-present",
    "require-absent",
    "compare",
    "range-check",
    "state-update",
    "reject",
}
MODALITIES = {"MUST", "MUST NOT", "SHOULD", "SHOULD NOT"}
DETERMINATE_LABELS = {"CONSISTENT", "INCONSISTENT"}
ALL_LABELS = {"CONSISTENT", "INCONSISTENT", "INSUFFICIENT"}
EVIDENCE_COMPLETION_HINTS = {
    "caller",
    "callers",
    "macro",
    "definition",
    "helper",
    "config",
    "build",
    "error",
    "return",
    "validation",
    "parse",
    "state",
}
GENERIC_IDENTS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "case",
    "break",
    "continue",
    "static",
    "const",
    "struct",
    "enum",
    "typedef",
    "unsigned",
    "signed",
    "void",
    "char",
    "int",
    "long",
    "short",
    "byte",
    "word16",
    "word32",
    "size_t",
    "ret",
    "err",
    "tmp",
    "buf",
    "data",
    "len",
    "length",
    "idx",
    "i",
    "j",
    "k",
}


@dataclass
class FieldEntry:
    field_id: str
    canonical_name: str
    aliases: list[str]
    parent: str
    field_kind: str
    type: str
    allowed_values: str
    definition: str
    semantic_role: str
    source_locations: str
    source_evidence: str
    source_chunks: list[str] = field(default_factory=list)
    ambiguous: bool = False
    ambiguity_reason: str = ""


@dataclass
class FieldRule:
    rule_id: str
    f: str
    C: str
    A: str
    M: str
    E: str
    action_type: str
    source_location: str
    source_chunk_id: str
    field_id: str = ""
    explicit_or_inferred: str = "explicit"
    note: str = ""
    out_of_scope: bool = False
    validation_errors: list[str] = field(default_factory=list)


@dataclass
class CodeCandidate:
    candidate_id: str
    file: str
    symbol: str
    start_line: int
    end_line: int
    score: float
    source_tags: list[str]
    reason: str
    snippet: str
    variable_hits: list[str] = field(default_factory=list)


@dataclass
class EvidenceBundle:
    rule_id: str
    field_rule: FieldRule
    ranked_variables: list[dict[str, Any]]
    contexts: list[dict[str, Any]]
    candidate_snippets: list[dict[str, Any]]
    missing_links: list[str] = field(default_factory=list)
    alignment_summary: str = ""


@dataclass
class ReasoningResult:
    y: str
    E: dict[str, Any]
    U: list[str]
    T: dict[str, Any]
    R: str
    confidence: float
    round_index: int
    raw_response: str = ""


@dataclass
class PipelineConfig:
    standard_doc: str
    repo_root: str
    output_dir: str
    api_key: str = ""
    base_url: str = "https://api.bltcy.ai/v1/"
    model: str = "gpt-5.4"
    chunk_size: int = 6000
    max_chunks: int = 0
    max_rules: int = 0
    max_files: int = 20000
    max_file_size: int = 600000
    max_code_chunks: int = 6000
    top_files: int = 15
    top_variables: int = 8
    top_snippets: int = 12
    max_rounds: int = 3
    context_window: int = 30
    max_snippet_lines: int = 180
    use_llm: bool = False
    run_validation: bool = True
    validation_commands: list[str] = field(default_factory=list)


def read_json(path: Path | str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dataclass_to_dict(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return obj


def _dedupe_text(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = normalize_text(item)
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def _normalize_modality(value: Any) -> str:
    text = normalize_text(value).upper().replace("_", " ")
    text = " ".join(text.split())
    if text in MODALITIES:
        return text
    if text in {"MUSTNT", "MUSTN T"}:
        return "MUST NOT"
    if text in {"SHOULDNT", "SHOULDN T"}:
        return "SHOULD NOT"
    low = text.lower()
    if "must not" in low:
        return "MUST NOT"
    if "should not" in low:
        return "SHOULD NOT"
    if "must" in low:
        return "MUST"
    if "should" in low:
        return "SHOULD"
    return ""


def infer_action_type(action: str) -> str:
    low = action.lower()
    if any(word in low for word in ["reject", "abort", "fail", "close", "error", "terminate", "discard"]):
        return "reject"
    if any(word in low for word in ["must be present", "include", "contain", "appear", "send"]):
        return "require-present"
    if any(word in low for word in ["absent", "omit", "not include", "must not be sent", "not present"]):
        return "require-absent"
    if any(word in low for word in ["range", "bound", "less than", "greater than", "at least", "at most", "length", "non-empty"]):
        return "range-check"
    if any(word in low for word in ["equal", "match", "same", "different", "compare", "associated with"]):
        return "compare"
    if any(word in low for word in ["derive", "compute", "calculate", "hash", "hmac"]):
        return "derive"
    if any(word in low for word in ["select", "choose", "negotiate", "offered list"]):
        return "select"
    if any(word in low for word in ["state", "update", "remember", "store", "clear"]):
        return "state-update"
    if any(word in low for word in ["set", "assign", "increment", "decrement"]):
        return "assign"
    return "compare"


def evidence_supported(evidence: str, text: str) -> bool:
    evidence_norm = " ".join(evidence.lower().split())
    text_norm = " ".join(text.lower().split())
    if not evidence_norm:
        return False
    if evidence_norm in text_norm:
        return True
    tokens = [tok.strip(".,;:()[]{}<>\"'`") for tok in evidence_norm.split()]
    tokens = [tok for tok in tokens if len(tok) >= 4]
    if not tokens:
        return False
    hits = sum(1 for tok in tokens if tok in text_norm)
    return hits >= max(2, min(6, len(tokens) // 2))


def make_client(config: PipelineConfig) -> OpenAICompatClient | None:
    if not config.use_llm or not config.api_key:
        return None
    return OpenAICompatClient(api_key=config.api_key, base_url=config.base_url, model=config.model)


def build_field_space_from_definitions(definitions: list[dict[str, Any]]) -> list[FieldEntry]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in definitions:
        name = field_name_from_record(row)
        if not name or not is_packet_field_name(name):
            continue
        parent = parent_from_record(row)
        location = source_locations_from_record(row)
        grouped[(name.lower(), parent.lower(), location.lower())].append(row)

    entries: list[FieldEntry] = []
    for idx, ((_, _, _), rows) in enumerate(sorted(grouped.items()), start=1):
        first = rows[0]
        name = field_name_from_record(first)
        parent = parent_from_record(first)
        aliases = _dedupe_text(sum((aliases_from_record(r) for r in rows), []))
        source_chunks = _dedupe_text([normalize_text(r.get("source_chunk_id")) for r in rows])
        source_locations = _dedupe_text([source_locations_from_record(r) for r in rows])
        evidence = _dedupe_text([source_evidence_from_record(r) for r in rows])
        entries.append(
            FieldEntry(
                field_id=f"field_{idx:05d}",
                canonical_name=name,
                aliases=aliases,
                parent=parent,
                field_kind=first_text(first, "field_kind"),
                type=first_text(first, "type"),
                allowed_values=first_text(first, "allowed_values", "initial_value_or_range", "value_range", "range"),
                definition=first_text(first, "definition"),
                semantic_role=first_text(first, "semantic_role"),
                source_locations="; ".join(source_locations),
                source_evidence="; ".join(evidence),
                source_chunks=source_chunks,
            )
        )

    by_name: dict[str, list[FieldEntry]] = defaultdict(list)
    for entry in entries:
        by_name[entry.canonical_name.lower()].append(entry)
    for same_name in by_name.values():
        parents = {e.parent.lower() for e in same_name if e.parent}
        locations = {e.source_locations.lower() for e in same_name if e.source_locations}
        if len(same_name) > 1 and (len(parents) > 1 or len(locations) > 1):
            for entry in same_name:
                entry.ambiguous = True
                entry.ambiguity_reason = "same field name appears in multiple parents or source locations"
    return entries


def heuristic_extract_field_definitions(chunks: list[dict[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    field_patterns = [
        re.compile(r"^\s*([A-Za-z][A-Za-z0-9_.\- ]{1,80})\s*:\s+(.{8,})$"),
        re.compile(r"\b(?:uint(?:8|16|24|32|64)|opaque|struct|enum)\s+([A-Za-z][A-Za-z0-9_]{1,80})(?:<[^>]+>)?", re.I),
        re.compile(r"\|\s*([A-Za-z][A-Za-z0-9_.\- ]{1,80})\s*\|"),
    ]
    for chunk in chunks:
        chunk_id = chunk["chunk_id"]
        for line in chunk["chunk_text"].splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            for pat in field_patterns:
                m = pat.search(stripped)
                if not m:
                    continue
                name = m.group(1).strip()
                if not is_packet_field_name(name):
                    continue
                rows.append(
                    {
                        "variable_name": name,
                        "canonical_name": name,
                        "alias": [],
                        "parent_message_or_structure": "",
                        "type": "",
                        "definition": stripped[:500],
                        "initial_value_or_range": "",
                        "module_or_section": "",
                        "evidence": stripped[:500],
                        "source_chunk_id": chunk_id,
                    }
                )
                break
    return rows


FIELD_EXTRACTION_PROMPT = """
You construct a field space for field-level protocol conformance checking.
Use only the current standard chunk.

Return a JSON array. Each item:
{
  "canonical_name": "",
  "aliases": [],
  "parent_message_or_structure": "",
  "field_kind": "field|flag|parameter|extension|option|message|frame|header",
  "type": "",
  "allowed_values": "",
  "definition": "",
  "semantic_role": "",
  "source_locations": "",
  "source_evidence": ""
}

Include only concrete serialized/message fields, flags, options, extensions,
parameters, headers, or structured payload members. Exclude abstract concepts.

Current chunk:
{chunk_text}
""".strip()


def extract_field_space(chunks: list[dict[str, str]], client: OpenAICompatClient | None, out_dir: Path) -> list[FieldEntry]:
    parsed: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    for idx, chunk in enumerate(chunks, start=1):
        chunk_id = chunk["chunk_id"]
        if client is None:
            rows = heuristic_extract_field_definitions([chunk])
            raw = ""
        else:
            prompt = FIELD_EXTRACTION_PROMPT.replace("{chunk_text}", chunk["chunk_text"])
            try:
                raw = client.chat(prompt)
                rows = extract_json_array(raw)
            except Exception as exc:  # noqa: BLE001
                raw = f"ERROR: {exc}"
                rows = heuristic_extract_field_definitions([chunk])
        for row in rows:
            row["source_chunk_id"] = chunk_id
        parsed.extend(rows)
        logs.append({"chunk_id": chunk_id, "parsed_count": len(rows), "raw_response": raw[:4000]})
        if idx % 25 == 0:
            print(f"[{now_ts()}] field-space chunks {idx}/{len(chunks)}")

    entries = build_field_space_from_definitions(parsed)
    write_json(out_dir / "01_field_space.json", {"fields": [asdict(e) for e in entries], "logs": logs})
    return entries


def field_space_catalog(fields: list[FieldEntry], chunk_id: str | None = None, max_rows: int = 120) -> str:
    selected = []
    for f in fields:
        if chunk_id and f.source_chunks and chunk_id not in f.source_chunks:
            # Include globally known fields only when same-section entries are sparse.
            continue
        selected.append(f)
    if not selected:
        selected = fields
    rows = []
    for i, f in enumerate(selected[:max_rows], start=1):
        parts = [f"{i}. id={f.field_id}", f"name={f.canonical_name}"]
        if f.aliases:
            parts.append(f"aliases={', '.join(f.aliases[:8])}")
        if f.parent:
            parts.append(f"parent={f.parent}")
        if f.type:
            parts.append(f"type={f.type}")
        if f.allowed_values:
            parts.append(f"allowed_values={f.allowed_values}")
        if f.source_locations:
            parts.append(f"source={f.source_locations}")
        rows.append(" | ".join(parts))
    return "\n".join(rows) if rows else "[]"


RULE_EXTRACTION_PROMPT = """
You extract field-centric normative rules for protocol conformance checking.
Use only the current standard chunk and the field-space catalog.

Normative modalities:
- Keep MUST, MUST NOT, SHOULD, SHOULD NOT.
- Ignore MAY.

Field-level rule shape:
{
  "f": "field name or field id from the catalog",
  "C": "applicability condition",
  "A": "required action or constraint",
  "M": "MUST|MUST NOT|SHOULD|SHOULD NOT",
  "E": "source evidence copied from the current chunk",
  "action_type": "assign|derive|select|require-present|require-absent|compare|range-check|state-update|reject",
  "source_location": "",
  "note": ""
}

Rules:
1. Split multiple independent constraints into multiple rules.
2. Rewrite negated requirements into explicit action_type values.
3. Resolve field references to the catalog when possible.
4. If the statement is normative but outside concrete field-level scope, omit it.
5. Do not invent evidence outside this chunk.

Field-space catalog:
{field_catalog}

Current chunk:
{chunk_text}
""".strip()


REPAIR_RULE_PROMPT = """
Repair the previous rule extraction output.
Return only a JSON array with valid field-level rules.

Requirements:
- Every item needs f, C, A, M, E, action_type.
- M must be one of: MUST, MUST NOT, SHOULD, SHOULD NOT.
- action_type must be one of: {action_types}.
- Evidence E must be supported by the current chunk.
- Drop MAY and out-of-scope items.

Field-space catalog:
{field_catalog}

Current chunk:
{chunk_text}

Previous output:
{raw_response}
""".strip()


def resolve_field_reference(ref: str, fields: list[FieldEntry], chunk_id: str = "") -> tuple[str, str, str]:
    ref_norm = normalize_text(ref).lower()
    if not ref_norm:
        return "", "", "empty field reference"
    exact = [f for f in fields if f.field_id.lower() == ref_norm]
    exact.extend([f for f in fields if f.canonical_name.lower() == ref_norm])
    exact.extend([f for f in fields if ref_norm in {a.lower() for a in f.aliases}])
    # Prefer same source chunk and non-ambiguous entries.
    exact = sorted(
        {f.field_id: f for f in exact}.values(),
        key=lambda f: (
            0 if chunk_id and chunk_id in f.source_chunks else 1,
            1 if f.ambiguous else 0,
            f.canonical_name.lower(),
        ),
    )
    if not exact:
        return "", normalize_text(ref), "field reference does not resolve to field space"
    if len(exact) > 1:
        same_chunk = [f for f in exact if chunk_id and chunk_id in f.source_chunks]
        candidates = same_chunk or exact
        if len(candidates) > 1 and candidates[0].canonical_name.lower() == candidates[1].canonical_name.lower():
            return candidates[0].field_id, candidates[0].canonical_name, "ambiguous same-name field resolved conservatively to first source-compatible entry"
        return candidates[0].field_id, candidates[0].canonical_name, ""
    return exact[0].field_id, exact[0].canonical_name, ""


def normalize_rule_record(
    row: dict[str, Any],
    fields: list[FieldEntry],
    chunk_text: str,
    chunk_id: str,
    index: int,
) -> FieldRule:
    field_ref = first_text(row, "f", "field", "field_name", "variable_name")
    field_id, field_name, field_error = resolve_field_reference(field_ref, fields, chunk_id)
    if not field_name:
        field_name = normalize_text(field_ref)

    action = first_text(row, "A", "action", "change_action", "constraint")
    modality = _normalize_modality(first_text(row, "M", "modality", "normative_modality"))
    action_type = first_text(row, "action_type", "action_family").lower()
    if action_type not in ACTION_TYPES:
        action_type = infer_action_type(action)

    evidence = first_text(row, "E", "evidence", "source_evidence")
    errors: list[str] = []
    if field_error:
        errors.append(field_error)
    if not field_name:
        errors.append("missing field")
    if not first_text(row, "C", "condition", "change_condition"):
        errors.append("missing condition")
    if not action:
        errors.append("missing action")
    if modality not in MODALITIES:
        errors.append("unsupported or missing modality")
    if not evidence:
        errors.append("missing evidence")
    elif not evidence_supported(evidence, chunk_text):
        errors.append("evidence not found in source chunk")

    return FieldRule(
        rule_id=f"rule_{index:05d}",
        f=field_name,
        C=first_text(row, "C", "condition", "change_condition"),
        A=action,
        M=modality,
        E=evidence,
        action_type=action_type,
        source_location=first_text(row, "source_location", "source_locations", "section"),
        source_chunk_id=chunk_id,
        field_id=field_id,
        explicit_or_inferred=first_text(row, "explicit_or_inferred") or "explicit",
        note=first_text(row, "note", "notes"),
        validation_errors=errors,
    )


def heuristic_extract_rules(chunks: list[dict[str, str]], fields: list[FieldEntry]) -> list[FieldRule]:
    rules: list[FieldRule] = []
    normative_re = re.compile(r"\b(MUST NOT|SHOULD NOT|MUST|SHOULD)\b(.{0,500})", re.I)
    field_names = sorted([f.canonical_name for f in fields], key=len, reverse=True)
    idx = 1
    for chunk in chunks:
        chunk_text = chunk["chunk_text"]
        for m in normative_re.finditer(chunk_text):
            modality = _normalize_modality(m.group(1))
            sentence_start = max(0, chunk_text.rfind(".", 0, m.start()) + 1)
            sentence_end = chunk_text.find(".", m.end())
            if sentence_end < 0:
                sentence_end = min(len(chunk_text), m.end() + 300)
            sentence = chunk_text[sentence_start : sentence_end + 1].strip()
            if " MAY " in f" {sentence.upper()} ":
                continue
            field_name = ""
            low_sentence = sentence.lower()
            for candidate in field_names:
                if candidate.lower() in low_sentence:
                    field_name = candidate
                    break
            if not field_name:
                # Last resort: use the noun immediately before the keyword.
                before = chunk_text[max(0, m.start() - 100) : m.start()]
                names = re.findall(r"\b[A-Za-z][A-Za-z0-9_.\-]{2,60}\b", before)
                field_name = names[-1] if names else ""
            if not field_name:
                continue
            row = {
                "f": field_name,
                "C": "When the normative sentence applies",
                "A": sentence,
                "M": modality,
                "E": sentence[:500],
                "action_type": infer_action_type(sentence),
                "note": "heuristic extraction",
            }
            rules.append(normalize_rule_record(row, fields, chunk_text, chunk["chunk_id"], idx))
            idx += 1
    return [r for r in rules if not r.validation_errors]


def extract_rules(chunks: list[dict[str, str]], fields: list[FieldEntry], client: OpenAICompatClient | None, out_dir: Path, max_rules: int = 0) -> list[FieldRule]:
    if client is None:
        rules = heuristic_extract_rules(chunks, fields)
        if max_rules > 0:
            rules = rules[:max_rules]
        write_json(out_dir / "02_field_rules.json", {"rules": [asdict(r) for r in rules], "mode": "heuristic"})
        return rules

    rules: list[FieldRule] = []
    invalid: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    next_index = 1
    for idx, chunk in enumerate(chunks, start=1):
        catalog = field_space_catalog(fields, chunk["chunk_id"])
        prompt = (
            RULE_EXTRACTION_PROMPT.replace("{field_catalog}", catalog)
            .replace("{chunk_text}", chunk["chunk_text"])
        )
        try:
            raw = client.chat(prompt)
            rows = extract_json_array(raw)
            parsed = [
                normalize_rule_record(row, fields, chunk["chunk_text"], chunk["chunk_id"], next_index + i)
                for i, row in enumerate(rows)
            ]
            if rows and not [p for p in parsed if not p.validation_errors]:
                repair_prompt = (
                    REPAIR_RULE_PROMPT.replace("{action_types}", ", ".join(sorted(ACTION_TYPES)))
                    .replace("{field_catalog}", catalog)
                    .replace("{chunk_text}", chunk["chunk_text"])
                    .replace("{raw_response}", raw)
                )
                raw = client.chat(repair_prompt)
                rows = extract_json_array(raw)
                parsed = [
                    normalize_rule_record(row, fields, chunk["chunk_text"], chunk["chunk_id"], next_index + i)
                    for i, row in enumerate(rows)
                ]
        except Exception as exc:  # noqa: BLE001
            raw = f"ERROR: {exc}"
            parsed = []
        valid = [p for p in parsed if not p.validation_errors]
        invalid.extend([asdict(p) for p in parsed if p.validation_errors])
        rules.extend(valid)
        next_index += len(parsed)
        logs.append({"chunk_id": chunk["chunk_id"], "valid": len(valid), "invalid": len(parsed) - len(valid), "raw_response": raw[:4000]})
        if max_rules > 0 and len(rules) >= max_rules:
            rules = rules[:max_rules]
            break
        if idx % 25 == 0:
            print(f"[{now_ts()}] rule extraction chunks {idx}/{len(chunks)}")

    dedup: dict[tuple[str, str, str, str], FieldRule] = {}
    for rule in rules:
        key = (rule.f.lower(), rule.C.lower(), rule.A.lower(), rule.M)
        dedup.setdefault(key, rule)
    rules = list(dedup.values())
    write_json(out_dir / "02_field_rules.json", {"rules": [asdict(r) for r in rules], "invalid": invalid, "logs": logs})
    return rules


class CodeIndex:
    def __init__(self, repo_root: Path, max_files: int, max_file_size: int, max_chunks: int) -> None:
        self.repo_root = repo_root
        self.files = collect_files(repo_root, max_files=max_files)
        self.symbols_by_file, self.symbols_by_name = build_symbol_index(self.files, max_file_size=max_file_size)
        self.chunks = build_semantic_chunks(self.files, self.symbols_by_file, max_chunks=max_chunks, max_file_size=max_file_size)


def rule_aliases(rule: FieldRule, fields_by_id: dict[str, FieldEntry]) -> list[str]:
    aliases = [rule.f]
    entry = fields_by_id.get(rule.field_id)
    if entry:
        aliases.extend(entry.aliases)
        if entry.parent:
            aliases.append(f"{entry.parent}.{entry.canonical_name}")
    expanded = expand_var_aliases(parse_var_names(aliases) or aliases)
    return _dedupe_text(aliases + expanded)


def rule_tokens(rule: FieldRule, aliases: list[str]) -> set[str]:
    text = " ".join([rule.f, rule.C, rule.A, rule.M, rule.E, rule.action_type])
    tokens = set(tokenize(text))
    for alias in aliases:
        tokens.update(t for t in split_identifier(alias) if len(t) >= 3)
    return {t for t in tokens if len(t) >= 3}


def collect_hits(repo_root: Path, aliases: list[str], max_hits: int = 500) -> list[Hit]:
    patterns: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        variants = [alias]
        if re.search(r"[\s.\-]", alias):
            variants.append(alias.replace(" ", "_").replace("-", "_").replace(".", "_"))
        for variant in variants:
            if not variant.strip():
                continue
            pat = rf"\b{re.escape(variant)}\b"
            if pat in seen:
                continue
            seen.add(pat)
            patterns.append(pat)
    hits = run_rg_json(repo_root, patterns, max_hits=max_hits)
    return hits or fallback_text_search(repo_root, aliases, max_hits=max_hits)


def candidate_from_range(index: CodeIndex, file: str, start: int, end: int, symbol: str, score: float, source: str, reason: str, cid: int, aliases: list[str], max_lines: int) -> CodeCandidate | None:
    try:
        snippet = render_snippet(file, [(start, end)], max_lines=max_lines)
    except Exception:
        return None
    variable_hits = []
    low = snippet.lower()
    for alias in aliases:
        if alias and re.search(rf"\b{re.escape(alias.lower())}\b", low):
            variable_hits.append(alias)
    return CodeCandidate(
        candidate_id=f"cand_{cid:03d}",
        file=file,
        symbol=symbol,
        start_line=start,
        end_line=end,
        score=score,
        source_tags=[source],
        reason=reason,
        snippet=snippet,
        variable_hits=_dedupe_text(variable_hits),
    )


def candidate_bonus(snippet: str, action_type: str) -> float:
    low = snippet.lower()
    bonus = 0.0
    if any(k in low for k in ["if", "switch", "case", "check", "valid", "verify", "parse"]):
        bonus += 0.9
    if any(k in low for k in ["error", "fatal", "abort", "reject", "return 0", "return -", "close"]):
        bonus += 1.0
    if any(k in low for k in ["=", "memcpy", "copy", "set", "store", "clear"]):
        bonus += 0.4
    if action_type == "reject" and any(k in low for k in ["error", "fatal", "abort", "close", "reject"]):
        bonus += 1.2
    if action_type == "range-check" and any(k in low for k in ["<", ">", "<=", ">=", "length", "size"]):
        bonus += 1.0
    if action_type == "compare" and any(k in low for k in ["==", "!=", "memcmp", "compare", "match"]):
        bonus += 1.0
    return bonus


def score_context(snippet: str, aliases: list[str], query_tokens: set[str], action_type: str, exact_bonus: float = 5.0, var_weight: float = 0.9, rule_weight: float = 0.28) -> float:
    low = snippet.lower()
    snippet_tokens = set(tokenize(snippet))
    alias_tokens = set()
    exact = 0
    for alias in aliases:
        alias_tokens.update(t for t in split_identifier(alias) if len(t) >= 3)
        if alias and re.search(rf"\b{re.escape(alias.lower())}\b", low):
            exact = 1
    score = exact_bonus * exact
    score += var_weight * len(snippet_tokens & alias_tokens)
    score += rule_weight * len(snippet_tokens & query_tokens)
    score += candidate_bonus(snippet, action_type)
    if exact == 0:
        score = min(score * 0.35, 2.2)
    return score


def rank_files(index: CodeIndex, rule: FieldRule, aliases: list[str], query_tokens: set[str], top_files: int, client: OpenAICompatClient | None = None) -> list[str]:
    path_scores: dict[str, float] = defaultdict(float)
    hits = collect_hits(index.repo_root, aliases, max_hits=800)
    for hit in hits:
        path_scores[hit.file] += 4.0 + classify_line_kind(hit.text, aliases)[1]
    for chunk in index.chunks:
        overlap = len(chunk.tokens & query_tokens)
        if overlap:
            path_scores[chunk.file] += min(5.0, overlap * 0.2)
    ranked = [f for f, _ in sorted(path_scores.items(), key=lambda x: (-x[1], x[0]))[:top_files]]
    if ranked or client is None:
        return ranked
    return index.files[:top_files]


def localize_variables(index: CodeIndex, rule: FieldRule, aliases: list[str], query_tokens: set[str], files: list[str], top_variables: int) -> list[dict[str, Any]]:
    scores: dict[str, float] = defaultdict(float)
    reasons: dict[str, list[str]] = defaultdict(list)
    alias_lows = {a.lower() for a in aliases}
    alias_tokens = set()
    for alias in aliases:
        alias_tokens.update(t for t in split_identifier(alias) if len(t) >= 2)
    for file in files:
        for sym in index.symbols_by_file.get(file, []):
            tokens = set(split_identifier(sym.name))
            overlap = len(tokens & alias_tokens) + len(tokens & query_tokens)
            if sym.name.lower() in alias_lows:
                overlap += 5
            if overlap <= 0:
                continue
            scores[sym.name] += overlap
            reasons[sym.name].append(f"symbol {sym.name} in {Path(file).name}")
        try:
            text = Path(file).read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for ident in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{1,63}\b", text):
            low = ident.lower()
            if low in GENERIC_IDENTS:
                continue
            tokens = set(split_identifier(ident))
            score = 0.0
            if low in alias_lows:
                score += 5.0
            score += len(tokens & alias_tokens) * 1.5
            score += len(tokens & query_tokens) * 0.3
            if score <= 0:
                continue
            scores[ident] += score
            if len(reasons[ident]) < 3:
                reasons[ident].append(f"identifier overlap in {Path(file).name}")
    ranked = sorted(scores.items(), key=lambda x: (-x[1], x[0].lower()))[:top_variables]
    max_score = ranked[0][1] if ranked else 1.0
    return [
        {"name": name, "score": round(score / max_score, 3), "reason": "; ".join(reasons[name][:3])}
        for name, score in ranked
    ]


LLM_CONTEXT_FILTER_PROMPT = """
Select code evidence for this field-level protocol rule.

Rule:
{rule_json}

Candidates:
{candidate_json}

Return strict JSON only:
{
  "selected_context_ids": ["cand_001"],
  "ranked_variables": [{"name": "", "score": 0.0, "reason": ""}],
  "summary": "",
  "missing_links": ["caller/helper/macro/config/error path still needed"]
}
""".strip()


def llm_filter_contexts(rule: FieldRule, candidates: list[CodeCandidate], ranked_vars: list[dict[str, Any]], client: OpenAICompatClient | None) -> tuple[list[CodeCandidate], list[dict[str, Any]], list[str], str]:
    if client is None or not candidates:
        return candidates, ranked_vars, [], "LLM filter not used; heuristic ranking retained."
    compact = [
        {
            "id": c.candidate_id,
            "file": c.file,
            "symbol": c.symbol,
            "score": round(c.score, 3),
            "reason": c.reason,
            "snippet": c.snippet[:2200],
        }
        for c in candidates[:20]
    ]
    prompt = LLM_CONTEXT_FILTER_PROMPT.replace("{rule_json}", json.dumps(asdict(rule), ensure_ascii=False, indent=2)).replace(
        "{candidate_json}", json.dumps(compact, ensure_ascii=False, indent=2)
    )
    try:
        raw = client.chat(prompt)
        obj = json.loads(raw[raw.find("{") : raw.rfind("}") + 1])
        ids = set(obj.get("selected_context_ids", []))
        selected = [c for c in candidates if c.candidate_id in ids] or candidates
        rv = obj.get("ranked_variables", ranked_vars)
        missing = obj.get("missing_links", [])
        summary = normalize_text(obj.get("summary")) or "LLM semantic filter selected contexts."
        if isinstance(rv, list):
            ranked_vars = [v for v in rv if isinstance(v, dict)] or ranked_vars
        return selected, ranked_vars, [normalize_text(x) for x in missing if normalize_text(x)], summary
    except Exception as exc:  # noqa: BLE001
        return candidates, ranked_vars, [f"LLM context filter failed: {exc}"], "LLM filter failed; heuristic ranking retained."


def align_rule_to_code(index: CodeIndex, fields_by_id: dict[str, FieldEntry], rule: FieldRule, config: PipelineConfig, client: OpenAICompatClient | None) -> EvidenceBundle:
    aliases = rule_aliases(rule, fields_by_id)
    qtokens = rule_tokens(rule, aliases)
    top_files = rank_files(index, rule, aliases, qtokens, config.top_files, client)
    ranked_vars = localize_variables(index, rule, aliases, qtokens, top_files, config.top_variables)

    candidates: list[CodeCandidate] = []
    cid = 1
    hits = [h for h in collect_hits(index.repo_root, aliases, max_hits=800) if h.file in set(top_files)]
    for hit in hits[:300]:
        sym = symbol_at_line(index.symbols_by_file.get(hit.file, []), hit.line)
        start, end, symbol = (sym.start_line, sym.end_line, sym.name) if sym else (max(1, hit.line - config.context_window), hit.line + config.context_window, "")
        cand = candidate_from_range(index, hit.file, start, end, symbol, 0.0, "exact", f"exact hit at line {hit.line}", cid, aliases, config.max_snippet_lines)
        if cand:
            cand.score = score_context(cand.snippet, aliases, qtokens, rule.action_type)
            candidates.append(cand)
            cid += 1

    for chunk in index.chunks:
        if chunk.file not in set(top_files):
            continue
        try:
            snippet = render_snippet(chunk.file, [(chunk.start_line, chunk.end_line)], max_lines=config.max_snippet_lines)
        except Exception:
            snippet = chunk.text[:4000]
        score = score_context(snippet, aliases, qtokens, rule.action_type)
        if score <= 0:
            continue
        candidates.append(
            CodeCandidate(
                candidate_id=f"cand_{cid:03d}",
                file=chunk.file,
                symbol=chunk.symbol,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                score=score,
                source_tags=["semantic-window"],
                reason="formula score from exact/variable/rule/action signals",
                snippet=snippet,
                variable_hits=[a for a in aliases if a.lower() in snippet.lower()],
            )
        )
        cid += 1

    dedup: dict[tuple[str, int, int, str], CodeCandidate] = {}
    for cand in candidates:
        key = (cand.file, cand.start_line, cand.end_line, cand.symbol)
        if key not in dedup or cand.score > dedup[key].score:
            dedup[key] = cand
    candidates = sorted(dedup.values(), key=lambda c: (-c.score, c.file, c.start_line))[: max(config.top_snippets, 20)]
    for i, cand in enumerate(candidates, start=1):
        cand.candidate_id = f"cand_{i:03d}"

    selected, ranked_vars, missing, summary = llm_filter_contexts(rule, candidates[: config.top_snippets], ranked_vars, client if config.use_llm else None)
    contexts = []
    for cand in selected[: config.top_snippets]:
        category, category_reason = infer_category(cand.snippet, [v["name"] for v in ranked_vars if "name" in v])
        contexts.append(
            {
                **asdict(cand),
                "category_guess": category,
                "category_reason": category_reason,
            }
        )
    return EvidenceBundle(
        rule_id=rule.rule_id,
        field_rule=rule,
        ranked_variables=ranked_vars[: config.top_variables],
        contexts=contexts,
        candidate_snippets=[asdict(c) for c in candidates[: config.top_snippets]],
        missing_links=missing,
        alignment_summary=summary,
    )


REASON_PROMPT = """
You judge whether implementation evidence satisfies a field-level protocol rule.

Return strict JSON:
{
  "y": "CONSISTENT|INCONSISTENT|INSUFFICIENT",
  "E": {"document": {}, "code": []},
  "U": ["missing evidence items"],
  "T": {},
  "R": "inconsistency reason when y is INCONSISTENT",
  "confidence": 0.0
}

Rule:
{rule_json}

Evidence bundle:
{bundle_json}
""".strip()


def heuristic_reason(bundle: EvidenceBundle, round_index: int) -> ReasoningResult:
    rule = bundle.field_rule
    text = "\n".join(str(c.get("snippet", "")) for c in bundle.contexts).lower()
    action = rule.A.lower()
    y = "INSUFFICIENT"
    reason = ""
    missing: list[str] = []
    if not bundle.contexts:
        missing.append("no code context retrieved")
    else:
        reject_present = any(k in text for k in ["error", "fatal", "abort", "close", "reject", "return 0", "return -"])
        compare_present = any(k in text for k in ["==", "!=", "<=", ">=", "<", ">", "memcmp", "compare", "match"])
        state_present = any(k in text for k in ["=", "set", "store", "clear", "update", "state"])
        if rule.action_type == "reject":
            if reject_present:
                y = "CONSISTENT"
                reason = "retrieved code contains error/rejection handling near the field evidence"
            else:
                y = "INCONSISTENT" if any(a in action for a in ["reject", "abort", "fail", "close"]) else "INSUFFICIENT"
                reason = "no explicit rejection evidence was found in the retrieved context"
        elif rule.action_type in {"compare", "range-check"}:
            if compare_present and (reject_present or state_present):
                y = "CONSISTENT"
                reason = "retrieved code contains comparison/range-check-like evidence"
            else:
                missing.append("validation helper or comparison/error path")
        elif rule.action_type in {"assign", "derive", "select", "state-update"}:
            if state_present:
                y = "CONSISTENT"
                reason = "retrieved code contains assignment/state-update-like evidence"
            else:
                missing.append("assignment or state update path")
        elif rule.action_type in {"require-present", "require-absent"}:
            if compare_present or reject_present:
                y = "CONSISTENT"
                reason = "retrieved code contains presence/absence check-like evidence"
            else:
                missing.append("presence/absence validation path")
    if y == "INSUFFICIENT" and round_index >= 1 and bundle.contexts:
        reason = "available context remains incomplete after evidence completion"
    return ReasoningResult(
        y=y,
        E={
            "document": {"field": rule.f, "condition": rule.C, "action": rule.A, "modality": rule.M, "evidence": rule.E},
            "code": [
                {k: c.get(k) for k in ["file", "symbol", "start_line", "end_line", "reason"]}
                for c in bundle.contexts
            ],
        },
        U=_dedupe_text(missing + bundle.missing_links),
        T={},
        R=reason if y == "INCONSISTENT" else "",
        confidence=0.62 if y in DETERMINATE_LABELS else 0.35,
        round_index=round_index,
    )


def reason_with_llm(bundle: EvidenceBundle, client: OpenAICompatClient | None, round_index: int) -> ReasoningResult:
    if client is None:
        return heuristic_reason(bundle, round_index)
    prompt = REASON_PROMPT.replace("{rule_json}", json.dumps(asdict(bundle.field_rule), ensure_ascii=False, indent=2)).replace(
        "{bundle_json}", json.dumps(asdict(bundle), ensure_ascii=False, indent=2)[:30000]
    )
    try:
        raw = client.chat(prompt)
        obj = json.loads(raw[raw.find("{") : raw.rfind("}") + 1])
        y = normalize_text(obj.get("y")).upper()
        if y not in ALL_LABELS:
            raise ValueError(f"bad label {y}")
        return ReasoningResult(
            y=y,
            E=obj.get("E", {}),
            U=[normalize_text(x) for x in obj.get("U", []) if normalize_text(x)] if isinstance(obj.get("U", []), list) else [],
            T=obj.get("T", {}) if isinstance(obj.get("T", {}), dict) else {},
            R=normalize_text(obj.get("R")),
            confidence=float(obj.get("confidence", 0.0) or 0.0),
            round_index=round_index,
            raw_response=raw,
        )
    except Exception as exc:  # noqa: BLE001
        rr = heuristic_reason(bundle, round_index)
        rr.U.append(f"LLM reasoning failed: {exc}")
        return rr


def context_request(missing: list[str], rule: FieldRule) -> list[str]:
    terms = [rule.f, rule.action_type]
    for item in missing:
        low = item.lower()
        for hint in EVIDENCE_COMPLETION_HINTS:
            if hint in low:
                terms.append(hint)
        terms.extend(tokenize(item)[:6])
    return _dedupe_text(terms)


def retrieve_additional_context(index: CodeIndex, bundle: EvidenceBundle, queries: list[str], config: PipelineConfig) -> list[dict[str, Any]]:
    aliases = _dedupe_text([bundle.field_rule.f] + queries)
    hits = collect_hits(index.repo_root, aliases, max_hits=200)
    new_contexts: list[dict[str, Any]] = []
    existing = {(c["file"], c["start_line"], c["end_line"]) for c in bundle.contexts if "file" in c}
    for hit in hits:
        sym = symbol_at_line(index.symbols_by_file.get(hit.file, []), hit.line)
        start, end, symbol = (sym.start_line, sym.end_line, sym.name) if sym else (max(1, hit.line - config.context_window), hit.line + config.context_window, "")
        if (hit.file, start, end) in existing:
            continue
        cand = candidate_from_range(index, hit.file, start, end, symbol, 1.0, "evidence-completion", f"context request hit at line {hit.line}", len(new_contexts) + 1, aliases, config.max_snippet_lines)
        if cand:
            new_contexts.append(asdict(cand))
        if len(new_contexts) >= 6:
            break
    return new_contexts


def evidence_driven_reasoning(index: CodeIndex, bundle: EvidenceBundle, config: PipelineConfig, client: OpenAICompatClient | None) -> list[ReasoningResult]:
    results: list[ReasoningResult] = []
    current = bundle
    for round_index in range(max(1, config.max_rounds)):
        result = reason_with_llm(current, client if config.use_llm else None, round_index)
        results.append(result)
        if result.y in DETERMINATE_LABELS:
            return results
        queries = context_request(result.U, current.field_rule)
        additions = retrieve_additional_context(index, current, queries, config)
        if not additions:
            return results
        existing_keys = {(c["file"], c["start_line"], c["end_line"]) for c in current.contexts if "file" in c}
        for ctx in additions:
            key = (ctx["file"], ctx["start_line"], ctx["end_line"])
            if key not in existing_keys:
                current.contexts.append(ctx)
                existing_keys.add(key)
    return results


VALIDATION_PLAN_PROMPT = """
Create one validation test plan for this suspected protocol conformance inconsistency.
Return strict JSON:
{
  "name": "",
  "execution_mode": "runtime|static_trace",
  "steps": [],
  "expected": "",
  "oracle": "",
  "commands": []
}

Rule:
{rule_json}

Reasoning:
{reason_json}
""".strip()


def run_validation_agent(rule: FieldRule, reasoning: ReasoningResult, bundle: EvidenceBundle, config: PipelineConfig, client: OpenAICompatClient | None, artifact_dir: Path) -> dict[str, Any]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    plan = {
        "name": f"validate_{rule.rule_id}_{rule.f}",
        "execution_mode": "static_trace",
        "steps": [
            "Inspect selected code contexts.",
            "Check whether concrete code evidence implements the expected field rule.",
        ],
        "expected": rule.A,
        "oracle": f"Implementation behavior should satisfy {rule.M} rule for {rule.f}.",
        "commands": config.validation_commands,
    }
    raw = ""
    if client is not None and config.use_llm:
        prompt = VALIDATION_PLAN_PROMPT.replace("{rule_json}", json.dumps(asdict(rule), ensure_ascii=False, indent=2)).replace(
            "{reason_json}", json.dumps(asdict(reasoning), ensure_ascii=False, indent=2)
        )
        try:
            raw = client.chat(prompt)
            obj = json.loads(raw[raw.find("{") : raw.rfind("}") + 1])
            if isinstance(obj, dict):
                plan.update(obj)
        except Exception as exc:  # noqa: BLE001
            plan["plan_warning"] = f"LLM validation planning failed: {exc}"

    command_results = []
    for raw_cmd in plan.get("commands", []) or []:
        if not raw_cmd:
            continue
        try:
            cp = subprocess.run(
                shlex.split(raw_cmd),
                cwd=str(Path(config.repo_root).resolve(strict=False)),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
            )
            command_results.append({"command": raw_cmd, "returncode": cp.returncode, "stdout": cp.stdout[-4000:], "stderr": cp.stderr[-4000:]})
        except Exception as exc:  # noqa: BLE001
            command_results.append({"command": raw_cmd, "error": str(exc)})

    if command_results:
        observed = "validation commands executed; inspect command_results"
        result = "pass" if any(r.get("returncode") == 0 for r in command_results) else "fail"
    else:
        decisive = reasoning.y == "INCONSISTENT" and bool(bundle.contexts)
        observed = reasoning.R or "static trace records available evidence and uncertainty"
        result = "fail" if decisive else "inconclusive"
    validation = {
        "input": plan,
        "oracle": plan.get("oracle", ""),
        "expected": plan.get("expected", ""),
        "observed": observed,
        "result": result,
        "command_results": command_results,
        "raw_response": raw,
    }
    write_json(artifact_dir / f"{rule.rule_id}_validation.json", validation)
    return validation


def report_markdown(rule: FieldRule, bundle: EvidenceBundle, reasoning: ReasoningResult, validation: dict[str, Any]) -> str:
    lines = [
        f"# {reasoning.y}: {rule.f}",
        "",
        "## Standard Rule",
        "",
        f"- Rule ID: `{rule.rule_id}`",
        f"- Field: `{rule.f}`",
        f"- Condition: {rule.C}",
        f"- Action: {rule.A}",
        f"- Modality: `{rule.M}`",
        f"- Source: {rule.source_location or rule.source_chunk_id}",
        "",
        "> " + rule.E.replace("\n", " "),
        "",
        "## Code Evidence",
        "",
    ]
    for ctx in bundle.contexts[:6]:
        lines.extend(
            [
                f"- `{ctx.get('file')}` lines {ctx.get('start_line')}-{ctx.get('end_line')} symbol `{ctx.get('symbol', '')}`",
                f"  - {ctx.get('reason', '')}",
            ]
        )
    lines.extend(
        [
            "",
            "## Judgment",
            "",
            f"- Result: `{reasoning.y}`",
            f"- Confidence: {reasoning.confidence:.2f}",
            f"- Reason: {reasoning.R or bundle.alignment_summary}",
        ]
    )
    if reasoning.U:
        lines.extend(["", "## Missing Or Uncertain Evidence", ""])
        lines.extend([f"- {item}" for item in reasoning.U])
    if validation:
        lines.extend(
            [
                "",
                "## Validation",
                "",
                f"- Mode: `{validation.get('input', {}).get('execution_mode', '')}`",
                f"- Expected: {validation.get('expected', '')}",
                f"- Observed: {validation.get('observed', '')}",
                f"- Result: `{validation.get('result', '')}`",
            ]
        )
    return "\n".join(lines) + "\n"


def generate_reports(
    judgments: list[dict[str, Any]],
    out_dir: Path,
) -> None:
    report_dir = out_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    index_lines = ["# SpecField Reports", ""]
    for item in judgments:
        rule = FieldRule(**item["rule"])
        bundle = EvidenceBundle(
            rule_id=item["bundle"]["rule_id"],
            field_rule=rule,
            ranked_variables=item["bundle"].get("ranked_variables", []),
            contexts=item["bundle"].get("contexts", []),
            candidate_snippets=item["bundle"].get("candidate_snippets", []),
            missing_links=item["bundle"].get("missing_links", []),
            alignment_summary=item["bundle"].get("alignment_summary", ""),
        )
        reasoning = ReasoningResult(**item["reasoning"][-1])
        validation = item.get("validation", {})
        filename = f"{rule.rule_id}_{reasoning.y.lower()}_{re.sub(r'[^A-Za-z0-9_]+', '_', rule.f)[:60]}.md"
        write_text(report_dir / filename, report_markdown(rule, bundle, reasoning, validation))
        index_lines.append(f"- [{rule.rule_id} {reasoning.y} {rule.f}](reports/{filename})")
    write_text(out_dir / "report_index.md", "\n".join(index_lines) + "\n")


def run_pipeline(config: PipelineConfig) -> dict[str, Any]:
    out_dir = Path(config.output_dir).resolve(strict=False)
    out_dir.mkdir(parents=True, exist_ok=True)
    client = make_client(config)

    print(f"[{now_ts()}] preprocess standard")
    _text, chunks = run_preprocess(config.standard_doc, str(out_dir), config.chunk_size, config.max_chunks)

    print(f"[{now_ts()}] construct field space")
    fields = extract_field_space(chunks, client, out_dir)
    fields_by_id = {f.field_id: f for f in fields}

    print(f"[{now_ts()}] extract field rules")
    rules = extract_rules(chunks, fields, client, out_dir, config.max_rules)

    print(f"[{now_ts()}] build implementation index")
    index = CodeIndex(Path(config.repo_root).resolve(strict=False), config.max_files, config.max_file_size, config.max_code_chunks)

    judgments: list[dict[str, Any]] = []
    validation_dir = out_dir / "validation_artifacts"
    for i, rule in enumerate(rules, start=1):
        print(f"[{now_ts()}] align/reason {i}/{len(rules)} {rule.rule_id} {rule.f}")
        bundle = align_rule_to_code(index, fields_by_id, rule, config, client)
        reasoning_rounds = evidence_driven_reasoning(index, bundle, config, client)
        final = reasoning_rounds[-1]
        validation = {}
        if config.run_validation and final.y == "INCONSISTENT":
            validation = run_validation_agent(rule, final, bundle, config, client, validation_dir)
            final.T = validation
        judgments.append(
            {
                "rule": asdict(rule),
                "bundle": asdict(bundle),
                "reasoning": [asdict(r) for r in reasoning_rounds],
                "validation": validation,
            }
        )

    write_json(out_dir / "03_alignments_and_judgments.json", {"judgments": judgments})
    generate_reports(judgments, out_dir)
    summary = summarize_pipeline(judgments)
    write_json(out_dir / "summary.json", summary)
    return summary


def summarize_pipeline(judgments: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(item["reasoning"][-1]["y"] for item in judgments if item.get("reasoning"))
    validation_counts = Counter((item.get("validation") or {}).get("result", "not_run") for item in judgments)
    return {
        "generated_at": now_ts(),
        "rule_count": len(judgments),
        "judgment_counts": dict(counts),
        "validation_counts": dict(validation_counts),
        "submitted_candidates": counts.get("INCONSISTENT", 0),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the complete SpecField pipeline.")
    parser.add_argument("--standard-doc", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output-dir", default="output/specfield_full")
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--base-url", default="https://api.bltcy.ai/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--chunk-size", type=int, default=6000)
    parser.add_argument("--max-chunks", type=int, default=0)
    parser.add_argument("--max-rules", type=int, default=0)
    parser.add_argument("--max-files", type=int, default=20000)
    parser.add_argument("--max-file-size", type=int, default=600000)
    parser.add_argument("--max-code-chunks", type=int, default=6000)
    parser.add_argument("--top-files", type=int, default=15)
    parser.add_argument("--top-variables", type=int, default=8)
    parser.add_argument("--top-snippets", type=int, default=12)
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument("--no-validation", action="store_true")
    parser.add_argument("--validation-command", action="append", default=[])
    args = parser.parse_args()

    config = PipelineConfig(
        standard_doc=args.standard_doc,
        repo_root=args.repo_root,
        output_dir=args.output_dir,
        api_key=args.api_key,
        base_url=args.base_url,
        model=args.model,
        chunk_size=args.chunk_size,
        max_chunks=args.max_chunks,
        max_rules=args.max_rules,
        max_files=args.max_files,
        max_file_size=args.max_file_size,
        max_code_chunks=args.max_code_chunks,
        top_files=args.top_files,
        top_variables=args.top_variables,
        top_snippets=args.top_snippets,
        max_rounds=args.max_rounds,
        use_llm=args.use_llm,
        run_validation=not args.no_validation,
        validation_commands=args.validation_command,
    )
    summary = run_pipeline(config)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
