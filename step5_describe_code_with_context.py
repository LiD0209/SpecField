#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import keyword
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib import error, request


SYSTEM_PROMPT = """
You are a code analysis assistant.
Given a target change JSON and multi-file code context, produce a precise implementation-oriented description.

Output JSON only, with this schema:
{
  "summary": "short paragraph",
  "key_points": ["...", "..."],
  "cross_file_relations": [
    {"from_file": "...", "to_file": "...", "relation": "..."}
  ],
  "gaps": ["..."],
  "confidence": "high|medium|low"
}
""".strip()


USER_PROMPT_TEMPLATE = """
Target change JSON:
{target_change}

Seed files:
{seed_files}

Expanded context files:
{expanded_files}

Code snippets:
{snippets}

Task:
1. Explain how this change is likely implemented in the provided code context.
2. Emphasize cross-file relations, not just single-file logic.
3. If context is insufficient, list gaps explicitly.
4. Keep output strict JSON.
""".strip()


CODE_EXTENSIONS = {
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".py",
    ".java",
    ".js",
    ".ts",
    ".go",
    ".rs",
}

SKIP_DIRS = {
    ".git",
    "__pycache__",
    "build",
    "dist",
    "target",
    "node_modules",
    ".idea",
    ".vscode",
}

STOP_TOKENS = {
    "the",
    "and",
    "for",
    "with",
    "this",
    "that",
    "from",
    "into",
    "must",
    "should",
    "when",
    "where",
    "there",
    "their",
    "while",
    "return",
    "false",
    "true",
    "null",
    "none",
    "void",
    "int",
    "char",
    "size_t",
    "const",
    "static",
}

CALL_EXCLUDE = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "defined",
    "case",
    "do",
    "else",
    "catch",
    "new",
}


@dataclass
class ContextNode:
    file: str
    hop: int
    score: float
    reasons: list[str]
    exists: bool


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


def normalize_path(path_text: str, repo_root: Path) -> str:
    p = Path(path_text)
    if not p.is_absolute():
        p = repo_root / p
    return str(p.resolve(strict=False))


def safe_read_text(path: str, max_bytes: int = 1_500_000) -> str:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return ""
    data = p.read_bytes()
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace")


def dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    out: list[str] = []
    for item in items:
        v = item.strip()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def load_step4_tasks(related_files_json: str, repo_root: Path) -> list[dict[str, Any]]:
    data = json.loads(Path(related_files_json).read_text(encoding="utf-8"))
    tasks: list[dict[str, Any]] = []

    if isinstance(data, dict) and isinstance(data.get("results"), list):
        for i, row in enumerate(data["results"]):
            result_obj = row.get("result", {})
            related = result_obj.get("related_files", []) if isinstance(result_obj, dict) else []
            seeds = []
            for item in related:
                if isinstance(item, dict):
                    file_name = str(item.get("file", "")).strip()
                    if file_name:
                        seeds.append(normalize_path(file_name, repo_root))
            task_id = row.get("index", i)
            query = row.get("change", {})
            tasks.append({"task_id": task_id, "query": query, "seed_files": dedupe_keep_order(seeds)})
        return tasks

    if isinstance(data, dict) and isinstance(data.get("result"), dict):
        related = data["result"].get("related_files", [])
        seeds = []
        for item in related:
            if isinstance(item, dict):
                file_name = str(item.get("file", "")).strip()
                if file_name:
                    seeds.append(normalize_path(file_name, repo_root))
        query = data.get("query", {})
        tasks.append({"task_id": 0, "query": query, "seed_files": dedupe_keep_order(seeds)})
        return tasks

    raise ValueError(f"unsupported step4 format: {related_files_json}")


def load_manual_tasks(seed_files: list[str], query_file: str, repo_root: Path) -> list[dict[str, Any]]:
    if not seed_files:
        return []
    query_obj: dict[str, Any] = {}
    if query_file:
        loaded = json.loads(Path(query_file).read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            query_obj = loaded
    seeds = [normalize_path(s, repo_root) for s in seed_files]
    return [{"task_id": 0, "query": query_obj, "seed_files": dedupe_keep_order(seeds)}]


def load_symbols(symbols_csv: str, repo_root: Path) -> tuple[dict[str, set[str]], dict[str, list[str]], set[str]]:
    symbol_to_files: dict[str, set[str]] = defaultdict(set)
    file_to_symbols: dict[str, list[str]] = defaultdict(list)
    source_files: set[str] = set()

    p = Path(symbols_csv)
    if not p.exists():
        return symbol_to_files, file_to_symbols, source_files

    with p.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            file_raw = str(row.get("file", "")).strip()
            symbol_raw = str(row.get("symbol_name", "")).strip()
            if not file_raw:
                continue
            file_path = normalize_path(file_raw, repo_root)
            source_files.add(file_path)
            if not symbol_raw:
                continue
            file_to_symbols[file_path].append(symbol_raw)

            key_set = {symbol_raw.lower()}
            if "." in symbol_raw:
                key_set.add(symbol_raw.rsplit(".", 1)[-1].lower())
            if "::" in symbol_raw:
                key_set.add(symbol_raw.rsplit("::", 1)[-1].lower())
            for key in key_set:
                symbol_to_files[key].add(file_path)

    for path in list(file_to_symbols.keys()):
        file_to_symbols[path] = dedupe_keep_order(file_to_symbols[path])

    return symbol_to_files, file_to_symbols, source_files


def discover_repo_source_files(repo_root: Path, max_files: int) -> set[str]:
    out: set[str] = set()
    count = 0
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        out.add(str(path.resolve(strict=False)))
        count += 1
        if count >= max_files:
            break
    return out


def build_basename_index(files: set[str]) -> dict[str, list[str]]:
    idx: dict[str, list[str]] = defaultdict(list)
    for f in sorted(files):
        idx[Path(f).name.lower()].append(f)
    return idx


def extract_query_keywords(query: dict[str, Any], max_keywords: int = 20) -> list[str]:
    token_score: dict[str, int] = defaultdict(int)

    def add_text(text: str, weight: int) -> None:
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text):
            t = token.lower()
            if t in STOP_TOKENS or keyword.iskeyword(t):
                continue
            token_score[t] += weight

    for key, value in query.items():
        if not isinstance(value, str):
            continue
        weight = 3 if key in {"variable_name", "new_value", "change_action"} else 1
        add_text(value, weight)

    ranked = sorted(token_score.items(), key=lambda kv: (-kv[1], kv[0]))
    return [token for token, _ in ranked[:max_keywords]]


def extract_references_from_code(code: str) -> tuple[list[str], list[str]]:
    includes = re.findall(r'^\s*#\s*include\s*[<"]([^">]+)[">]', code, flags=re.MULTILINE)

    py_imports = re.findall(r"^\s*import\s+([A-Za-z0-9_\.]+)", code, flags=re.MULTILINE)
    py_from = re.findall(r"^\s*from\s+([A-Za-z0-9_\.]+)\s+import\s+", code, flags=re.MULTILINE)
    java_imports = re.findall(r"^\s*import\s+([A-Za-z0-9_\.]+)\s*;", code, flags=re.MULTILINE)

    include_like = includes + py_imports + py_from + java_imports
    include_like = dedupe_keep_order(include_like)

    calls = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code)
    filtered_calls = []
    seen = set()
    for call in calls:
        low = call.lower()
        if low in CALL_EXCLUDE:
            continue
        if call.isupper():
            continue
        if low in seen:
            continue
        seen.add(low)
        filtered_calls.append(call)
    return include_like, filtered_calls


def resolve_include_target(
    raw_ref: str,
    src_file: str,
    repo_root: Path,
    basename_idx: dict[str, list[str]],
) -> list[str]:
    out: list[str] = []
    src_dir = Path(src_file).parent
    ref = raw_ref.strip().replace("\\", "/")
    if not ref:
        return out

    direct_candidates = [
        src_dir / ref,
        repo_root / ref,
    ]
    for c in direct_candidates:
        if c.exists() and c.is_file():
            out.append(str(c.resolve(strict=False)))

    # Python module style: a.b.c
    if "." in ref and "/" not in ref:
        mod_path = ref.replace(".", "/")
        py_candidates = [repo_root / f"{mod_path}.py", repo_root / mod_path / "__init__.py"]
        for c in py_candidates:
            if c.exists() and c.is_file():
                out.append(str(c.resolve(strict=False)))

    # Basename fallback
    base = Path(ref).name.lower()
    if base in basename_idx:
        out.extend(basename_idx[base][:5])

    return dedupe_keep_order(out)


def lookup_symbol_files(
    symbol: str,
    symbol_to_files: dict[str, set[str]],
    max_fanout: int,
) -> list[str]:
    key = symbol.lower()
    files = sorted(symbol_to_files.get(key, set()))
    if len(files) > max_fanout:
        return files[:max_fanout]
    return files


def expand_context_files(
    seed_files: list[str],
    query: dict[str, Any],
    repo_root: Path,
    symbol_to_files: dict[str, set[str]],
    basename_idx: dict[str, list[str]],
    max_hops: int,
    max_files: int,
    per_hop_limit: int,
    symbol_fanout: int,
) -> tuple[list[ContextNode], list[str]]:
    missing_refs: list[str] = []
    query_keywords = set(extract_query_keywords(query))

    nodes: dict[str, ContextNode] = {}
    frontier: list[str] = []

    for f in seed_files:
        normalized = normalize_path(f, repo_root)
        exists = Path(normalized).exists()
        nodes[normalized] = ContextNode(
            file=normalized,
            hop=0,
            score=100.0,
            reasons=["seed_file"],
            exists=exists,
        )
        frontier.append(normalized)

    if len(nodes) >= max_files:
        ordered = sorted(nodes.values(), key=lambda x: (x.hop, -x.score, x.file))
        return ordered[:max_files], missing_refs

    for hop in range(1, max_hops + 1):
        if not frontier:
            break

        candidate_scores: dict[str, float] = defaultdict(float)
        candidate_reasons: dict[str, set[str]] = defaultdict(set)
        next_frontier: list[str] = []

        for src in frontier:
            src_text = safe_read_text(src)
            if not src_text:
                missing_refs.append(f"{src} (cannot read or not found)")
                continue

            includes, calls = extract_references_from_code(src_text)

            for inc in includes:
                targets = resolve_include_target(inc, src, repo_root, basename_idx)
                if not targets:
                    missing_refs.append(f"{Path(src).name} -> include/import `{inc}` unresolved")
                for tgt in targets:
                    if tgt == src:
                        continue
                    reason = f"include/import `{inc}` from {Path(src).name}"
                    if tgt in nodes:
                        if reason not in nodes[tgt].reasons:
                            nodes[tgt].reasons.append(reason)
                            nodes[tgt].score += 0.5
                        continue
                    candidate_scores[tgt] += 8.0
                    candidate_reasons[tgt].add(reason)

            for call in calls:
                fanout_files = lookup_symbol_files(call, symbol_to_files, symbol_fanout)
                if not fanout_files:
                    continue
                for tgt in fanout_files:
                    if tgt == src:
                        continue
                    bonus = 4.0 if call.lower() in query_keywords else 3.0
                    reason = f"symbol `{call}` referenced in {Path(src).name}"
                    if tgt in nodes:
                        if reason not in nodes[tgt].reasons:
                            nodes[tgt].reasons.append(reason)
                            nodes[tgt].score += 0.25
                        continue
                    candidate_scores[tgt] += bonus
                    candidate_reasons[tgt].add(reason)

        if not candidate_scores:
            break

        ranked = sorted(candidate_scores.items(), key=lambda kv: (-kv[1], kv[0]))
        for tgt, score in ranked:
            if len(nodes) >= max_files or len(next_frontier) >= per_hop_limit:
                break
            if tgt in nodes:
                continue
            exists = Path(tgt).exists()
            node = ContextNode(
                file=tgt,
                hop=hop,
                score=round(score, 2),
                reasons=sorted(candidate_reasons[tgt]),
                exists=exists,
            )
            nodes[tgt] = node
            next_frontier.append(tgt)

        frontier = next_frontier

    ordered = sorted(nodes.values(), key=lambda x: (x.hop, -x.score, x.file))
    return ordered[:max_files], missing_refs


def collect_snippet(path: str, keywords: list[str], max_lines: int = 80, context_window: int = 2) -> str:
    text = safe_read_text(path)
    if not text:
        return f"[missing file] {path}"

    lines = text.splitlines()
    if not lines:
        return ""

    key_set = [k.lower() for k in keywords if k]
    hit_indexes: list[int] = []
    if key_set:
        for i, line in enumerate(lines):
            low = line.lower()
            if any(k in low for k in key_set):
                hit_indexes.append(i)

    selected = set()
    if hit_indexes:
        for idx in hit_indexes[:8]:
            start = max(0, idx - context_window)
            end = min(len(lines), idx + context_window + 1)
            for j in range(start, end):
                selected.add(j)
    else:
        for j in range(min(len(lines), max_lines)):
            selected.add(j)

    selected_sorted = sorted(selected)[:max_lines]
    formatted = []
    for j in selected_sorted:
        formatted.append(f"{j + 1:5d}: {lines[j]}")
    return "\n".join(formatted)


def extract_json_object(text: str) -> dict[str, Any]:
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        raise ValueError("cannot extract JSON object from model output")
    obj = json.loads(match.group(0))
    if not isinstance(obj, dict):
        raise ValueError("model output is not a JSON object")
    return obj


def call_chat_completions(
    api_key: str,
    base_url: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    timeout_sec: int,
) -> str:
    endpoint = f"{normalize_base_url(base_url)}/chat/completions"
    payload = {
        "model": model,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }

    req = request.Request(
        endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=timeout_sec) as resp:
            body = resp.read().decode("utf-8")
    except error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTPError {e.code}: {body}") from e
    except error.URLError as e:
        raise RuntimeError(f"URLError: {e}") from e

    data = json.loads(body)
    choices = data.get("choices", [])
    if not choices:
        raise RuntimeError(f"model response has no choices: {body}")
    content = choices[0].get("message", {}).get("content", "")
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(str(item))
        content = "\n".join(parts)
    return str(content).strip()


def build_local_description(
    query: dict[str, Any],
    nodes: list[ContextNode],
    file_to_symbols: dict[str, list[str]],
    missing_refs: list[str],
) -> dict[str, Any]:
    seed_count = len([n for n in nodes if n.hop == 0])
    expanded_count = len([n for n in nodes if n.hop > 0])
    variable = str(query.get("variable_name", "")).strip()
    action = str(query.get("change_action", "")).strip()

    if variable or action:
        summary = f"Target logic centers on `{variable}` with action `{action}`. Context expansion added {expanded_count} cross-file candidates from {seed_count} seed file(s)."
    else:
        summary = f"Context expansion added {expanded_count} cross-file candidates from {seed_count} seed file(s)."

    key_points: list[str] = []
    for node in nodes[:6]:
        symbol_list = file_to_symbols.get(node.file, [])
        symbol_preview = ", ".join(symbol_list[:3]) if symbol_list else "no indexed symbols"
        key_points.append(
            f"{Path(node.file).name}: hop={node.hop}, score={node.score}, symbols={symbol_preview}"
        )

    cross_file_relations: list[dict[str, str]] = []
    seed_nodes = [n for n in nodes if n.hop == 0]
    seed_name = Path(seed_nodes[0].file).name if seed_nodes else ""
    for node in nodes:
        if node.hop == 0:
            continue
        relation = "; ".join(node.reasons[:2]) if node.reasons else "context expansion"
        cross_file_relations.append(
            {
                "from_file": seed_name,
                "to_file": Path(node.file).name,
                "relation": relation,
            }
        )

    gaps = []
    if not cross_file_relations:
        gaps.append("No additional related file was found beyond seed files.")
    if missing_refs:
        gaps.extend(missing_refs[:10])

    confidence = "high"
    if expanded_count == 0 or missing_refs:
        confidence = "medium"
    if expanded_count == 0 and len(missing_refs) >= 3:
        confidence = "low"

    return {
        "summary": summary,
        "key_points": key_points,
        "cross_file_relations": cross_file_relations,
        "gaps": gaps,
        "confidence": confidence,
    }


def build_llm_description(
    query: dict[str, Any],
    seed_files: list[str],
    nodes: list[ContextNode],
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    timeout_sec: int,
) -> dict[str, Any]:
    keywords = extract_query_keywords(query)
    expanded_files = [
        {
            "file": node.file,
            "hop": node.hop,
            "score": node.score,
            "reasons": node.reasons,
            "exists": node.exists,
        }
        for node in nodes
    ]

    snippets_obj = []
    for node in nodes[:6]:
        snippet = collect_snippet(node.file, keywords, max_lines=80, context_window=2)
        snippets_obj.append({"file": node.file, "snippet": snippet})

    user_prompt = USER_PROMPT_TEMPLATE.format(
        target_change=json.dumps(query, ensure_ascii=False, indent=2),
        seed_files=json.dumps(seed_files, ensure_ascii=False, indent=2),
        expanded_files=json.dumps(expanded_files, ensure_ascii=False, indent=2),
        snippets=json.dumps(snippets_obj, ensure_ascii=False, indent=2),
    )

    raw = call_chat_completions(
        api_key=api_key,
        base_url=base_url,
        model=model,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        temperature=temperature,
        timeout_sec=timeout_sec,
    )
    obj = extract_json_object(raw)
    return {
        "summary": str(obj.get("summary", "")).strip(),
        "key_points": obj.get("key_points", []) if isinstance(obj.get("key_points"), list) else [],
        "cross_file_relations": (
            obj.get("cross_file_relations", [])
            if isinstance(obj.get("cross_file_relations"), list)
            else []
        ),
        "gaps": obj.get("gaps", []) if isinstance(obj.get("gaps"), list) else [],
        "confidence": str(obj.get("confidence", "medium")).strip() or "medium",
        "raw_model_output": raw,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Step5: multi-hop context expansion and code description generation"
    )
    parser.add_argument("--related-files-json", default="", help="step4 output JSON path")
    parser.add_argument("--seed-files", nargs="*", default=[], help="manual seed files")
    parser.add_argument("--query-file", default="", help="optional target query JSON for manual mode")

    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--symbols-csv", default="symbols.csv")
    parser.add_argument("--scan-repo", action="store_true", help="scan repo source files for include resolution")
    parser.add_argument("--max-index-files", type=int, default=30000)

    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--max-items", type=int, default=0, help="0 means all")
    parser.add_argument("--max-hops", type=int, default=2)
    parser.add_argument("--max-files", type=int, default=12)
    parser.add_argument("--per-hop-limit", type=int, default=6)
    parser.add_argument("--symbol-fanout", type=int, default=8)

    parser.add_argument("--use-llm", action="store_true", help="use LLM for final description")
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--base-url", default="https://api.zhizengzeng.com/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout-sec", type=int, default=120)

    parser.add_argument("--output", default="output/05_code_descriptions.json")
    parser.add_argument("--include-snippets", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        repo_root = Path(args.repo_root).resolve(strict=False)
        if not repo_root.exists():
            raise ValueError(f"repo root not found: {repo_root}")

        print(f"[{now_ts()}] loading tasks")
        tasks = []
        if args.related_files_json:
            tasks.extend(load_step4_tasks(args.related_files_json, repo_root))
        if args.seed_files:
            tasks.extend(load_manual_tasks(args.seed_files, args.query_file, repo_root))
        if not tasks:
            raise ValueError("no tasks loaded, provide --related-files-json or --seed-files")

        print(f"[{now_ts()}] loading symbols")
        symbol_to_files, file_to_symbols, source_files = load_symbols(args.symbols_csv, repo_root)

        if args.scan_repo:
            print(f"[{now_ts()}] scanning repo files")
            scanned = discover_repo_source_files(repo_root, args.max_index_files)
            source_files.update(scanned)

        for task in tasks:
            for f in task["seed_files"]:
                source_files.add(normalize_path(f, repo_root))

        basename_idx = build_basename_index(source_files)

        start = max(0, args.start_index)
        end = len(tasks) if args.max_items <= 0 else min(len(tasks), start + args.max_items)
        if start >= len(tasks):
            raise ValueError(f"start-index {start} out of range (total tasks={len(tasks)})")

        if args.use_llm and not args.api_key:
            raise ValueError("missing API key: provide --api-key or OPENAI_API_KEY")

        if args.dry_run:
            print(f"tasks={len(tasks)}, run_range=[{start}, {end})")
            for i in range(start, min(end, start + 3)):
                t = tasks[i]
                print(f"- task_id={t['task_id']} seeds={len(t['seed_files'])}")
            return 0

        output_items: list[dict[str, Any]] = []
        for i in range(start, end):
            task = tasks[i]
            seed_files = task["seed_files"]
            if not seed_files:
                continue

            print(f"[{now_ts()}] task {i + 1}/{len(tasks)} (id={task['task_id']})")
            nodes, missing_refs = expand_context_files(
                seed_files=seed_files,
                query=task.get("query", {}),
                repo_root=repo_root,
                symbol_to_files=symbol_to_files,
                basename_idx=basename_idx,
                max_hops=max(0, args.max_hops),
                max_files=max(1, args.max_files),
                per_hop_limit=max(1, args.per_hop_limit),
                symbol_fanout=max(1, args.symbol_fanout),
            )

            if args.use_llm:
                description = build_llm_description(
                    query=task.get("query", {}),
                    seed_files=seed_files,
                    nodes=nodes,
                    api_key=args.api_key,
                    base_url=args.base_url,
                    model=args.model,
                    temperature=args.temperature,
                    timeout_sec=args.timeout_sec,
                )
            else:
                description = build_local_description(
                    query=task.get("query", {}),
                    nodes=nodes,
                    file_to_symbols=file_to_symbols,
                    missing_refs=missing_refs,
                )

            item: dict[str, Any] = {
                "task_index": i,
                "task_id": task.get("task_id", i),
                "query": task.get("query", {}),
                "seed_files": seed_files,
                "context_files": [
                    {
                        "file": n.file,
                        "hop": n.hop,
                        "score": n.score,
                        "reasons": n.reasons,
                        "exists": n.exists,
                    }
                    for n in nodes
                ],
                "description": description,
            }

            if args.include_snippets:
                keywords = extract_query_keywords(task.get("query", {}))
                snippets = []
                for n in nodes[:6]:
                    snippets.append({"file": n.file, "snippet": collect_snippet(n.file, keywords)})
                item["snippets"] = snippets

            output_items.append(item)

        out = {
            "meta": {
                "generated_at": now_ts(),
                "repo_root": str(repo_root),
                "task_total": len(tasks),
                "task_start": start,
                "task_end_exclusive": end,
                "processed_count": len(output_items),
                "mode": "llm" if args.use_llm else "local",
                "max_hops": args.max_hops,
                "max_files": args.max_files,
                "per_hop_limit": args.per_hop_limit,
                "symbol_fanout": args.symbol_fanout,
                "symbols_csv": args.symbols_csv,
                "scan_repo": args.scan_repo,
            },
            "items": output_items,
        }

        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[{now_ts()}] done -> {out_path}")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
