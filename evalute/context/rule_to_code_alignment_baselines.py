#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from utils.variable_context_pipeline import (  # noqa: E402
    Chunk,
    Hit,
    build_anchor_var_names,
    build_semantic_chunks,
    build_symbol_index,
    build_var_tokens,
    call_chat_completions,
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

METHOD_EXACT = "exact-match"
METHOD_BM25 = "bm25"
METHOD_EMBEDDING = "embedding"
METHOD_LLM_DIRECT = "llm-direct"
METHODS = (METHOD_EXACT, METHOD_BM25, METHOD_EMBEDDING, METHOD_LLM_DIRECT)

IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{1,}\b")
GENERIC_IDENTIFIERS = {
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

LLM_DIRECT_PROMPT = """
You are evaluating rule-to-code alignment for a protocol implementation.

Field-level rule:
{rule_json}

Below are generic retrieved code snippets. They may contain relevant code, nearby but irrelevant code, or comments.
Select the implementation variables and code contexts most relevant to checking this rule.

Return strict JSON only:
{{
  "ranked_variables": [
    {{
      "name": "identifier from snippets",
      "score": 0.0,
      "reason": "short evidence-based reason"
    }}
  ],
  "contexts": [
    {{
      "candidate_id": "cand_001",
      "file": "path copied from candidates",
      "symbol": "symbol copied from candidates",
      "start_line": 1,
      "end_line": 1,
      "score": 0.0,
      "reason": "why this code helps decide the rule"
    }}
  ],
  "summary": "short summary",
  "missing_links": ["caller, macro, helper, or branch still needed"]
}}

Rules:
- Do not invent variables that are absent from the snippets.
- Prefer variables/fields manipulated by parsing, validation, comparison, state update, or error handling code.
- Prefer code that can decide whether the rule behavior is implemented.
- If evidence is weak, lower the score and say why.

Candidates:
{candidate_json}
""".strip()


@dataclass
class Candidate:
    id: str
    file: str
    symbol: str
    start_line: int
    end_line: int
    score: float
    source: str
    reason: str
    snippet: str


def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def first_text(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = normalize_text(row.get(key))
        if value:
            return value
    return ""


def load_rules(path: str) -> list[dict[str, Any]]:
    obj = read_json(path)
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if not isinstance(obj, dict):
        raise ValueError(f"Unsupported JSON input: {path}")
    for key in ("rules", "changes", "alignments", "items"):
        items = obj.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    raise ValueError(f"Cannot find rules/changes list in {path}")


def rule_field_name(rule: dict[str, Any]) -> str:
    return first_text(rule, "variable_name", "f", "field", "field_name", "canonical_name")


def rule_description(rule: dict[str, Any]) -> str:
    parts = [
        first_text(rule, "change_condition", "C", "condition"),
        first_text(rule, "change_action", "A", "action", "constraint"),
        first_text(rule, "related_state_or_step", "state", "step"),
        first_text(rule, "evidence", "E", "source_evidence"),
        first_text(rule, "note"),
    ]
    return " ".join(p for p in parts if p).strip()


def rule_to_query_text(rule: dict[str, Any]) -> str:
    field = rule_field_name(rule)
    return " ".join(
        p
        for p in [
            field,
            rule_description(rule),
            first_text(rule, "modality", "M"),
            first_text(rule, "action_type"),
        ]
        if p
    )


def rule_to_public_json(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "field": rule_field_name(rule),
        "condition": first_text(rule, "change_condition", "C", "condition"),
        "action": first_text(rule, "change_action", "A", "action", "constraint"),
        "modality": first_text(rule, "modality", "M"),
        "evidence": first_text(rule, "evidence", "E", "source_evidence"),
    }


def build_aliases(field: str, rule: dict[str, Any]) -> list[str]:
    raw: list[str] = []
    if field:
        raw.append(field)
    for key in ("aliases", "alias"):
        value = rule.get(key)
        if isinstance(value, list):
            raw.extend(normalize_text(v) for v in value)
        elif value:
            raw.append(normalize_text(value))
    parsed = parse_var_names(raw)
    aliases = expand_var_aliases(parsed or raw)
    out: list[str] = []
    seen: set[str] = set()
    for alias in aliases + raw:
        a = alias.strip()
        if not a:
            continue
        key = a.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out


def build_query_tokens(rule: dict[str, Any], aliases: list[str]) -> set[str]:
    tokens = set(tokenize(rule_to_query_text(rule)))
    for alias in aliases:
        tokens.update(t for t in split_identifier(alias) if len(t) >= 3)
    return {t for t in tokens if len(t) >= 3}


def collect_exact_hits(repo_root: Path, aliases: list[str], max_hits: int) -> list[Hit]:
    patterns: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        if not alias.strip():
            continue
        variants = [alias]
        if re.search(r"[\s\-.]", alias):
            variants.append(alias.replace(" ", "_").replace("-", "_").replace(".", "_"))
        for value in variants:
            pat = rf"\b{re.escape(value)}\b"
            if pat in seen:
                continue
            seen.add(pat)
            patterns.append(pat)
    hits = run_rg_json(repo_root, patterns, max_hits=max_hits)
    if hits:
        return hits
    return fallback_text_search(repo_root, aliases, max_hits=max_hits)


def candidate_from_hit(
    hit: Hit,
    symbols_by_file: dict[str, list[Any]],
    aliases: list[str],
    context_window: int,
    max_snippet_lines: int,
    index: int,
) -> Candidate | None:
    file_symbols = symbols_by_file.get(hit.file, [])
    symbol = symbol_at_line(file_symbols, hit.line)
    if symbol:
        start, end, sym_name = symbol.start_line, symbol.end_line, symbol.name
    else:
        start, end, sym_name = max(1, hit.line - context_window), hit.line + context_window, ""
    try:
        snippet = render_snippet(hit.file, [(start, end), (max(1, hit.line - context_window), hit.line + context_window)], max_lines=max_snippet_lines)
    except Exception:
        return None
    _, line_score = classify_line_kind(hit.text, aliases)
    return Candidate(
        id=f"cand_{index:03d}",
        file=hit.file,
        symbol=sym_name,
        start_line=start,
        end_line=end,
        score=1.0 + line_score,
        source=METHOD_EXACT,
        reason=f"exact lexical hit at line {hit.line}",
        snippet=snippet,
    )


def dedupe_candidates(candidates: list[Candidate], limit: int) -> list[Candidate]:
    merged: dict[tuple[str, int, int, str], Candidate] = {}
    for cand in candidates:
        key = (cand.file, cand.start_line, cand.end_line, cand.symbol)
        existing = merged.get(key)
        if existing is None or cand.score > existing.score:
            merged[key] = cand
        elif existing:
            existing.reason = f"{existing.reason}; {cand.reason}"
            existing.source = f"{existing.source}+{cand.source}" if cand.source not in existing.source.split("+") else existing.source
    out = list(merged.values())
    out.sort(key=lambda c: (-c.score, c.file, c.start_line))
    for i, cand in enumerate(out[:limit], start=1):
        cand.id = f"cand_{i:03d}"
    return out[:limit]


def exact_match_candidates(
    repo_root: Path,
    aliases: list[str],
    symbols_by_file: dict[str, list[Any]],
    max_hits: int,
    top_k: int,
    context_window: int,
    max_snippet_lines: int,
) -> list[Candidate]:
    hits = collect_exact_hits(repo_root, aliases, max_hits=max_hits)
    candidates: list[Candidate] = []
    for idx, hit in enumerate(hits, start=1):
        cand = candidate_from_hit(hit, symbols_by_file, aliases, context_window, max_snippet_lines, idx)
        if cand is not None:
            candidates.append(cand)
    return dedupe_candidates(candidates, top_k)


def chunk_term_counts(chunk: Chunk) -> Counter[str]:
    return Counter(tokenize(chunk.text))


def bm25_candidates(
    chunks: list[Chunk],
    query_tokens: set[str],
    top_k: int,
    max_snippet_lines: int,
    method_name: str = METHOD_BM25,
) -> list[Candidate]:
    if not chunks or not query_tokens:
        return []
    doc_terms = [chunk_term_counts(ch) for ch in chunks]
    doc_lens = [sum(cnt.values()) for cnt in doc_terms]
    avg_len = sum(doc_lens) / max(1, len(doc_lens))
    df: Counter[str] = Counter()
    for cnt in doc_terms:
        for tok in cnt.keys():
            df[tok] += 1
    n_docs = len(chunks)
    k1 = 1.5
    b = 0.75
    scored: list[tuple[float, Chunk]] = []
    for ch, cnt, doc_len in zip(chunks, doc_terms, doc_lens):
        score = 0.0
        for tok in query_tokens:
            tf = cnt.get(tok, 0)
            if tf <= 0:
                continue
            idf = math.log(1 + (n_docs - df[tok] + 0.5) / (df[tok] + 0.5))
            denom = tf + k1 * (1 - b + b * doc_len / max(1.0, avg_len))
            score += idf * (tf * (k1 + 1)) / denom
        if score > 0:
            scored.append((score, ch))
    scored.sort(key=lambda x: (-x[0], x[1].file, x[1].start_line))
    candidates: list[Candidate] = []
    for idx, (score, ch) in enumerate(scored[:top_k], start=1):
        try:
            snippet = render_snippet(ch.file, [(ch.start_line, ch.end_line)], max_lines=max_snippet_lines)
        except Exception:
            snippet = ch.text[:4000]
        candidates.append(
            Candidate(
                id=f"cand_{idx:03d}",
                file=ch.file,
                symbol=ch.symbol,
                start_line=ch.start_line,
                end_line=ch.end_line,
                score=score,
                source=method_name,
                reason=f"{method_name} sparse lexical score={score:.3f}",
                snippet=snippet,
            )
        )
    return candidates


def hash_embedding(text: str, dims: int = 384) -> list[float]:
    vec = [0.0] * dims
    for tok in tokenize(text):
        digest = hashlib.blake2b(tok.encode("utf-8", errors="ignore"), digest_size=8).digest()
        bucket = int.from_bytes(digest[:4], "little") % dims
        sign = 1.0 if digest[4] & 1 else -1.0
        vec[bucket] += sign
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [v / norm for v in vec]
    return vec


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


def normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


def call_embeddings(
    api_key: str,
    base_url: str,
    model: str,
    inputs: list[str],
    timeout_sec: int,
) -> list[list[float]]:
    endpoint = f"{normalize_base_url(base_url)}/embeddings"
    req = request.Request(
        endpoint,
        data=json.dumps({"model": model, "input": inputs}, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout_sec) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"embedding HTTP {exc.code}: {body}") from exc
    obj = json.loads(body)
    data = obj.get("data", [])
    vectors: list[list[float]] = []
    for item in data:
        emb = item.get("embedding")
        if isinstance(emb, list):
            vectors.append([float(v) for v in emb])
    if len(vectors) != len(inputs):
        raise RuntimeError(f"embedding response count mismatch: expected {len(inputs)}, got {len(vectors)}")
    return vectors


def batched(items: list[str], batch_size: int) -> list[list[str]]:
    return [items[i : i + batch_size] for i in range(0, len(items), batch_size)]


def embedding_candidates(
    chunks: list[Chunk],
    query_text: str,
    top_k: int,
    max_snippet_lines: int,
    embedding_mode: str,
    embedding_api_key: str,
    embedding_base_url: str,
    embedding_model: str,
    embedding_batch_size: int,
    timeout_sec: int,
) -> tuple[list[Candidate], str]:
    if not chunks or not query_text.strip():
        return [], "none"

    chunk_texts = [f"{ch.symbol}\n{ch.text[:4000]}" for ch in chunks]
    mode_used = embedding_mode
    if embedding_mode == "auto":
        mode_used = "api" if embedding_api_key else "local"

    if mode_used == "api":
        query_vec = call_embeddings(embedding_api_key, embedding_base_url, embedding_model, [query_text], timeout_sec)[0]
        chunk_vecs: list[list[float]] = []
        for batch in batched(chunk_texts, max(1, embedding_batch_size)):
            chunk_vecs.extend(call_embeddings(embedding_api_key, embedding_base_url, embedding_model, batch, timeout_sec))
    elif mode_used == "local":
        query_vec = hash_embedding(query_text)
        chunk_vecs = [hash_embedding(text) for text in chunk_texts]
    else:
        raise ValueError("--embedding-mode must be auto, api, or local")

    scored = [(cosine(query_vec, vec), ch) for vec, ch in zip(chunk_vecs, chunks)]
    scored = [(s, ch) for s, ch in scored if s > 0]
    scored.sort(key=lambda x: (-x[0], x[1].file, x[1].start_line))
    candidates: list[Candidate] = []
    for idx, (score, ch) in enumerate(scored[:top_k], start=1):
        try:
            snippet = render_snippet(ch.file, [(ch.start_line, ch.end_line)], max_lines=max_snippet_lines)
        except Exception:
            snippet = ch.text[:4000]
        candidates.append(
            Candidate(
                id=f"cand_{idx:03d}",
                file=ch.file,
                symbol=ch.symbol,
                start_line=ch.start_line,
                end_line=ch.end_line,
                score=score,
                source=METHOD_EMBEDDING,
                reason=f"dense embedding cosine={score:.3f} ({mode_used})",
                snippet=snippet,
            )
        )
    return candidates, mode_used


def extract_identifiers(snippet: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for ident in IDENT_RE.findall(snippet):
        low = ident.lower()
        if low in GENERIC_IDENTIFIERS or ident.isupper() and len(ident) > 18:
            continue
        if low in seen:
            continue
        seen.add(low)
        out.append(ident)
    return out


def rank_variables(candidates: list[Candidate], aliases: list[str], query_tokens: set[str], top_k: int) -> list[dict[str, Any]]:
    alias_lows = {a.lower() for a in aliases}
    alias_tokens = set()
    for alias in aliases:
        alias_tokens.update(t for t in split_identifier(alias) if len(t) >= 2)

    scores: dict[str, float] = defaultdict(float)
    reasons: dict[str, list[str]] = defaultdict(list)
    for rank, cand in enumerate(candidates, start=1):
        rank_weight = 1.0 / rank
        for ident in extract_identifiers(cand.snippet):
            ident_low = ident.lower()
            ident_tokens = set(split_identifier(ident))
            score = 0.0
            if ident_low in alias_lows:
                score += 4.0
            overlap_alias = len(ident_tokens & alias_tokens)
            overlap_query = len(ident_tokens & query_tokens)
            score += overlap_alias * 1.2
            score += overlap_query * 0.45
            if score <= 0:
                continue
            final_score = score * rank_weight
            scores[ident] += final_score
            if len(reasons[ident]) < 3:
                reasons[ident].append(f"{cand.id}: token/alias overlap in {Path(cand.file).name}")

    ranked = sorted(scores.items(), key=lambda x: (-x[1], x[0].lower()))[:top_k]
    max_score = ranked[0][1] if ranked else 1.0
    return [
        {
            "name": name,
            "score": round(score / max_score, 3),
            "reason": "; ".join(reasons[name]),
        }
        for name, score in ranked
    ]


def candidate_to_context(cand: Candidate) -> dict[str, Any]:
    category, category_reason = infer_category(cand.snippet, [cand.symbol] if cand.symbol else [])
    return {
        "candidate_id": cand.id,
        "file": cand.file,
        "symbol": cand.symbol,
        "start_line": cand.start_line,
        "end_line": cand.end_line,
        "score": round(float(cand.score), 3),
        "source": cand.source,
        "category_guess": category,
        "reason": f"{cand.reason}; {category_reason}",
        "snippet": cand.snippet,
    }


def llm_direct_result(
    rule: dict[str, Any],
    candidates: list[Candidate],
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    timeout_sec: int,
) -> tuple[dict[str, Any], str]:
    compact = [
        {
            "id": cand.id,
            "file": cand.file,
            "symbol": cand.symbol,
            "start_line": cand.start_line,
            "end_line": cand.end_line,
            "score": round(float(cand.score), 3),
            "source": cand.source,
            "reason": cand.reason,
            "snippet": cand.snippet[:2500],
        }
        for cand in candidates
    ]
    prompt = LLM_DIRECT_PROMPT.format(
        rule_json=json.dumps(rule_to_public_json(rule), ensure_ascii=False, indent=2),
        candidate_json=json.dumps(compact, ensure_ascii=False, indent=2),
    )
    raw = call_chat_completions(
        api_key=api_key,
        base_url=base_url,
        model=model,
        prompt=prompt,
        temperature=temperature,
        timeout_sec=timeout_sec,
    )
    parsed = extract_json_object(raw)
    return parsed, raw


def extract_json_object(text: str) -> dict[str, Any]:
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        raise ValueError("cannot parse JSON object from LLM output")
    obj = json.loads(m.group(0))
    if not isinstance(obj, dict):
        raise ValueError("LLM output is not a JSON object")
    return obj


def run_alignment_for_rule(
    method: str,
    rule: dict[str, Any],
    repo_root: Path,
    symbols_by_file: dict[str, list[Any]],
    chunks: list[Chunk],
    args: argparse.Namespace,
) -> dict[str, Any]:
    field = rule_field_name(rule)
    aliases = build_aliases(field, rule)
    query_tokens = build_query_tokens(rule, aliases)
    query_text = rule_to_query_text(rule)

    embedding_mode_used = ""
    raw_model_output = ""
    llm_warning = ""

    if method == METHOD_EXACT:
        candidates = exact_match_candidates(
            repo_root=repo_root,
            aliases=aliases,
            symbols_by_file=symbols_by_file,
            max_hits=args.max_exact_hits,
            top_k=args.top_snippets,
            context_window=args.context_window,
            max_snippet_lines=args.max_snippet_lines,
        )
    elif method == METHOD_BM25:
        candidates = bm25_candidates(chunks, query_tokens, args.top_snippets, args.max_snippet_lines)
    elif method == METHOD_EMBEDDING:
        candidates, embedding_mode_used = embedding_candidates(
            chunks=chunks,
            query_text=query_text,
            top_k=args.top_snippets,
            max_snippet_lines=args.max_snippet_lines,
            embedding_mode=args.embedding_mode,
            embedding_api_key=args.embedding_api_key or args.api_key,
            embedding_base_url=args.embedding_base_url,
            embedding_model=args.embedding_model,
            embedding_batch_size=args.embedding_batch_size,
            timeout_sec=args.timeout_sec,
        )
    elif method == METHOD_LLM_DIRECT:
        exact = exact_match_candidates(
            repo_root=repo_root,
            aliases=aliases,
            symbols_by_file=symbols_by_file,
            max_hits=args.max_exact_hits,
            top_k=max(4, args.top_snippets // 2),
            context_window=args.context_window,
            max_snippet_lines=args.max_snippet_lines,
        )
        sparse = bm25_candidates(
            chunks,
            query_tokens,
            top_k=max(args.top_snippets, args.llm_candidate_snippets),
            max_snippet_lines=args.max_snippet_lines,
            method_name=METHOD_BM25,
        )
        candidates = dedupe_candidates(exact + sparse, args.llm_candidate_snippets)
    else:
        raise ValueError(f"Unsupported method: {method}")

    ranked_variables = rank_variables(candidates, aliases, query_tokens, args.top_variables)
    contexts = [candidate_to_context(c) for c in candidates[: args.top_snippets]]
    result: dict[str, Any] = {
        "ranked_variables": ranked_variables,
        "contexts": contexts,
        "summary": f"{method} returned {len(contexts)} contexts and {len(ranked_variables)} variables.",
        "missing_links": [],
    }

    if method == METHOD_LLM_DIRECT:
        if not args.api_key:
            raise ValueError("--api-key is required for --method llm-direct")
        try:
            result, raw_model_output = llm_direct_result(
                rule=rule,
                candidates=candidates,
                api_key=args.api_key,
                base_url=args.base_url,
                model=args.model,
                temperature=args.temperature,
                timeout_sec=args.timeout_sec,
            )
        except Exception as exc:  # noqa: BLE001
            llm_warning = f"LLM Direct failed; fallback to heuristic ranking. error={exc}"
            print(f"[WARN] {llm_warning}", file=sys.stderr)

    out = {
        "rule": rule_to_public_json(rule),
        "aliases": aliases,
        "query_tokens": sorted(query_tokens),
        "method": method,
        "result": result,
        "candidate_snippets": [candidate_to_context(c) for c in candidates],
    }
    if embedding_mode_used:
        out["embedding_mode_used"] = embedding_mode_used
    if raw_model_output:
        out["raw_model_output"] = raw_model_output
    if llm_warning:
        out["llm_warning"] = llm_warning
    return out


def select_rules(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.var_name:
        return [
            {
                "variable_name": args.var_name,
                "change_condition": args.condition,
                "change_action": args.desc,
                "evidence": args.evidence,
            }
        ]
    if not args.changes:
        raise ValueError("Provide either --changes or --var-name/--desc")
    rules = load_rules(args.changes)
    if args.rule_index > 0:
        idx = args.rule_index - 1
        if idx >= len(rules):
            raise ValueError(f"--rule-index {args.rule_index} out of range, total={len(rules)}")
        rules = [rules[idx]]
    else:
        start = max(0, args.start_index - 1)
        rules = rules[start:]
        if args.limit > 0:
            rules = rules[: args.limit]
    return rules


def output_for_method(output: str, method: str, all_methods: bool) -> str:
    path = Path(output)
    if not all_methods:
        return str(path)
    if path.suffix.lower() == ".json":
        return str(path.with_name(f"{path.stem}_{method.replace('-', '_')}{path.suffix}"))
    path.mkdir(parents=True, exist_ok=True)
    return str(path / f"{method.replace('-', '_')}_alignment.json")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run RQ2 rule-to-code alignment baselines: Exact Match, BM25, Embedding, and LLM Direct."
    )
    parser.add_argument("--method", choices=[*METHODS, "all"], required=True)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--changes", default="", help="JSON with `changes` or `rules` list.")
    parser.add_argument("--output", default="output/rule_to_code_alignment_baseline.json")

    parser.add_argument("--var-name", default="", help="Run a single ad-hoc rule.")
    parser.add_argument("--condition", default="")
    parser.add_argument("--desc", default="", help="Rule action/description for single-rule mode.")
    parser.add_argument("--evidence", default="")
    parser.add_argument("--rule-index", type=int, default=0, help="1-based index in --changes.")
    parser.add_argument("--start-index", type=int, default=1, help="1-based start index for batch mode.")
    parser.add_argument("--limit", type=int, default=0, help="0 means no limit.")

    parser.add_argument("--max-files", type=int, default=20000)
    parser.add_argument("--max-file-size", type=int, default=600000)
    parser.add_argument("--max-chunks", type=int, default=6000)
    parser.add_argument("--max-exact-hits", type=int, default=400)
    parser.add_argument("--top-snippets", type=int, default=12)
    parser.add_argument("--top-variables", type=int, default=8)
    parser.add_argument("--context-window", type=int, default=30)
    parser.add_argument("--max-snippet-lines", type=int, default=180)

    parser.add_argument("--embedding-mode", choices=["auto", "api", "local"], default="auto")
    parser.add_argument("--embedding-api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--embedding-base-url", default="https://api.bltcy.ai/v1/")
    parser.add_argument("--embedding-model", default="text-embedding-3-large")
    parser.add_argument("--embedding-batch-size", type=int, default=64)

    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--base-url", default="https://api.bltcy.ai/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--llm-candidate-snippets", type=int, default=24)
    args = parser.parse_args()

    try:
        repo_root = Path(args.repo_root).resolve(strict=False)
        if not repo_root.exists():
            raise ValueError(f"repo root not found: {repo_root}")

        rules = select_rules(args)
        methods = list(METHODS) if args.method == "all" else [args.method]

        print(f"[{now_ts()}] collecting source files")
        files = collect_files(repo_root, max_files=max(1, args.max_files))
        print(f"[{now_ts()}] building symbol index ({len(files)} files)")
        symbols_by_file, _symbols_by_name = build_symbol_index(files, max_file_size=max(1, args.max_file_size))

        print(f"[{now_ts()}] building code chunks")
        chunks = build_semantic_chunks(
            files=files,
            symbols_by_file=symbols_by_file,
            max_chunks=max(1, args.max_chunks),
            max_file_size=max(1, args.max_file_size),
        )

        for method in methods:
            alignments: list[dict[str, Any]] = []
            for idx, rule in enumerate(rules, start=1):
                field = rule_field_name(rule)
                print(f"[{now_ts()}] {method} rule {idx}/{len(rules)} field={field!r}")
                alignment = run_alignment_for_rule(
                    method=method,
                    rule=rule,
                    repo_root=repo_root,
                    symbols_by_file=symbols_by_file,
                    chunks=chunks,
                    args=args,
                )
                alignment["input_index"] = idx
                alignments.append(alignment)

            output_path = Path(output_for_method(args.output, method, args.method == "all"))
            write_json(
                output_path,
                {
                    "meta": {
                        "generated_at": now_ts(),
                        "method": method,
                        "repo_root": str(repo_root),
                        "rule_count": len(rules),
                        "file_count": len(files),
                        "chunk_count": len(chunks),
                        "top_snippets": args.top_snippets,
                        "top_variables": args.top_variables,
                        "model": args.model if method == METHOD_LLM_DIRECT else "",
                        "embedding_model": args.embedding_model if method == METHOD_EMBEDDING else "",
                    },
                    "alignments": alignments,
                },
            )
            print(f"[{now_ts()}] wrote {output_path}")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
