#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import keyword
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib import error, request


SOURCE_EXTS = {
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".java",
    ".py",
    ".js",
    ".ts",
    ".go",
    ".rs",
}

SKIP_DIRS = {
    ".git",
    ".github",
    ".idea",
    ".vscode",
    "certs",
    "doc",
    "docs",
    "examples",
    "tests",
    "benchmark",
    "wrapper",
    "ide",
    "node_modules",
    "build",
    "dist",
    "target",
    "output",
    "document",
    "linuxkm",
    "__pycache__",
    ".venv",
    "venv",
}

SKIP_DIRS_LOWER = {d.lower() for d in SKIP_DIRS}

CATEGORIES = [
    "definition",
    "init_or_default",
    "assignment_or_update",
    "read_or_use",
    "validation_or_condition",
    "config_source",
    "persistence_or_api_transfer",
]

STOP_WORDS = {
    "the",
    "and",
    "for",
    "with",
    "this",
    "that",
    "from",
    "into",
    "when",
    "where",
    "while",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "to",
    "of",
    "in",
    "on",
    "at",
    "by",
    "as",
    "or",
    "if",
    "then",
    "else",
    "true",
    "false",
    "null",
    "none",
    "not",
    "value",
    "values",
    "variable",
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
    "throw",
}

SEMANTIC_HINTS = {
    "define",
    "definition",
    "default",
    "init",
    "initialize",
    "assign",
    "update",
    "validate",
    "check",
    "config",
    "env",
    "quota",
    "limit",
    "upload",
    "storage",
    "persist",
    "database",
    "db",
    "api",
    "request",
    "response",
}

GENERIC_VAR_TOKENS = {
    "key",
    "label",
    "len",
    "length",
    "id",
    "idx",
    "index",
    "name",
    "data",
    "value",
    "values",
    "type",
    "state",
    "step",
    "new",
    "old",
    "change",
    "condition",
    "action",
    "result",
    "file",
    "line",
    "score",
    "text",
    "api",
    "http",
    "current",
    "secret",
}

GENERIC_VAR_NAMES = {
    "i",
    "j",
    "k",
    "idx",
    "index",
    "tmp",
    "ret",
    "result",
    "rc",
    "err",
    "error",
    "status",
    "code",
    "value",
    "values",
    "data",
    "name",
    "type",
    "label",
    "key",
    "len",
    "length",
    "extension",
    "extensions",
    "current",
    "secret",
}

NOISY_QUERY_TOKENS = {
    "tls",
    "ssl",
    "dtls",
    "client",
    "server",
    "hello",
    "parse",
    "read",
    "write",
    "get",
    "set",
    "find",
    "check",
    "verify",
    "handle",
    "handler",
    "callback",
    "call",
    "return",
    "extension",
    "extensions",
    "current",
    "secret",
}

PROMPT_TEMPLATE = """
You are a codebase analysis assistant.

Target variable(s): {var_name}
Business description: {desc}

Below are recalled candidate snippets from the repository.
Please do the following:
1. Classify snippets as strongly related / weakly related / unrelated.
2. Keep the most important context snippets.
3. Label each snippet with one category:
   - definition
   - init_or_default
   - assignment_or_update
   - read_or_use
   - validation_or_condition
   - config_source
   - persistence_or_api_transfer
4. Output strict JSON:
{{
  "relevant_snippets": [
    {{
      "file": "...",
      "symbol": "...",
      "category": "...",
      "score": 0-1,
      "reason": "...",
      "snippet": "..."
    }}
  ],
  "summary": "...",
  "missing_links": ["..."]
}}

Candidates:
{candidate_json}
""".strip()


try:
    from tree_sitter import Language, Parser
    import tree_sitter_c as tsc
    import tree_sitter_java as tsjava

    _TS_AVAILABLE = True
except Exception:  # noqa: BLE001
    Language = None  # type: ignore[assignment]
    Parser = None  # type: ignore[assignment]
    tsc = None  # type: ignore[assignment]
    tsjava = None  # type: ignore[assignment]
    _TS_AVAILABLE = False


@dataclass
class Hit:
    file: str
    line: int
    col: int
    text: str
    kind: str
    score: float


@dataclass
class Symbol:
    file: str
    name: str
    sym_type: str
    start_line: int
    end_line: int


@dataclass
class Chunk:
    file: str
    symbol: str
    start_line: int
    end_line: int
    text: str
    tokens: set[str]


@dataclass
class Candidate:
    file: str
    symbol: str
    start_line: int
    end_line: int
    score: float
    source_tags: set[str]
    hit_lines: set[int]
    reason_parts: list[str]


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


def _is_generic_name(name: str) -> bool:
    low = name.strip().lower()
    if not low:
        return True
    if low in GENERIC_VAR_NAMES:
        return True
    if low in {"this", "self"}:
        return True
    return False


def parse_var_names(raw_values: list[str] | None) -> list[str]:
    if not raw_values:
        return []
    out_all: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        for part in re.split(r"[,\s;，；]+", (raw or "").strip()):
            name = part.strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            out_all.append(name)

    out_filtered = [name for name in out_all if not _is_generic_name(name)]
    if out_filtered:
        return out_filtered
    return out_all


def expand_var_aliases(var_names: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        n = name.strip()
        if not n:
            return
        k = n.lower()
        if k in seen:
            return
        seen.add(k)
        out.append(n)

    for raw_name in var_names:
        add(raw_name)
        tokens = split_identifier(raw_name)
        if not tokens:
            continue
        semantic_tokens = [t for t in tokens if t not in GENERIC_VAR_TOKENS and t not in NOISY_QUERY_TOKENS]
        if not semantic_tokens:
            continue
        if re.search(r"(?:->|::|\.)", raw_name):
            tail = re.split(r"(?:->|::|\.)", raw_name)[-1].strip()
            tail_low = tail.lower()
            if (
                tail
                and tail_low not in GENERIC_VAR_TOKENS
                and tail_low not in NOISY_QUERY_TOKENS
                and not _is_generic_name(tail)
            ):
                add(tail)
            continue
        if len(tokens) > 6:
            continue
        snake = "_".join(tokens)
        concat = "".join(tokens)
        camel = tokens[0] + "".join(t[:1].upper() + t[1:] for t in tokens[1:])
        pascal = "".join(t[:1].upper() + t[1:] for t in tokens)
        add(snake)
        add(concat)
        add(camel)
        add(pascal)
    return out


def split_identifier(name: str) -> list[str]:
    if not name:
        return []
    parts = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+", name)
    if not parts:
        parts = re.split(r"[_\-\s]+", name)
    return [p.lower() for p in parts if p]


def tokenize(text: str) -> list[str]:
    out = []
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,}", text):
        low = tok.lower()
        if low in STOP_WORDS:
            continue
        if keyword.iskeyword(low):
            continue
        out.append(low)
    return out


def build_var_tokens(var_names: list[str]) -> set[str]:
    out: set[str] = set()
    for name in var_names:
        for tok in split_identifier(name):
            if len(tok) < 3:
                continue
            if tok in GENERIC_VAR_TOKENS:
                continue
            if tok in NOISY_QUERY_TOKENS:
                continue
            out.add(tok)
        low_name = name.strip().lower()
        if re.fullmatch(r"[a-z0-9_]{3,}", low_name):
            if low_name not in GENERIC_VAR_TOKENS and low_name not in NOISY_QUERY_TOKENS:
                out.add(low_name)
    return out


def build_anchor_var_names(var_names: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for name in var_names:
        if _is_generic_name(name):
            continue
        tokens = [t for t in split_identifier(name) if t not in GENERIC_VAR_TOKENS and t not in NOISY_QUERY_TOKENS]
        if len(tokens) < 2 and not re.search(r"(?:->|::|\.)", name):
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    return out


def collect_files(repo_root: Path, max_files: int) -> list[str]:
    files: list[str] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part.lower() in SKIP_DIRS_LOWER for part in path.parts):
            continue
        if path.suffix.lower() not in SOURCE_EXTS:
            continue
        files.append(str(path.resolve(strict=False)))
        if len(files) >= max_files:
            break
    return files


def run_rg_json(repo_root: Path, patterns: list[str], max_hits: int) -> list[Hit]:
    hits: list[Hit] = []
    if not patterns:
        return hits

    cmd = ["rg", "--json", "--line-number", "--column"]
    for skip_dir in sorted(SKIP_DIRS_LOWER):
        cmd.extend(["--glob", f"!**/{skip_dir}/**"])
    for p in patterns:
        cmd.extend(["-e", p])
    cmd.append(str(repo_root))

    try:
        proc = subprocess.run(
            cmd,
            check=False,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return hits

    if proc.returncode not in {0, 1}:
        return hits

    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") != "match":
            continue
        data = obj.get("data", {})
        path = data.get("path", {}).get("text", "")
        line_no = int(data.get("line_number", 0) or 0)
        submatches = data.get("submatches", [])
        col = int(submatches[0].get("start", 0) + 1) if submatches else 1
        text = data.get("lines", {}).get("text", "").rstrip("\n")
        if not path or line_no <= 0:
            continue
        abs_path = str(Path(path).resolve(strict=False))
        hits.append(Hit(file=abs_path, line=line_no, col=col, text=text, kind="text", score=1.0))
        if len(hits) >= max_hits:
            break
    return hits


def fallback_text_search(repo_root: Path, var_names: list[str], max_hits: int) -> list[Hit]:
    pats = [re.compile(rf"\b{re.escape(v)}\b") for v in var_names if v.strip()]
    if not pats:
        return []
    hits: list[Hit] = []
    for file in collect_files(repo_root, max_files=20000):
        try:
            lines = Path(file).read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:  # noqa: BLE001
            continue
        for i, line in enumerate(lines, start=1):
            for pat in pats:
                m = pat.search(line)
                if not m:
                    continue
                hits.append(Hit(file=file, line=i, col=m.start() + 1, text=line, kind="text", score=1.0))
                if len(hits) >= max_hits:
                    return hits
                break
    return hits


def _classify_line_kind_single(line: str, var_name: str) -> tuple[str, float]:
    s = line.strip()
    low = s.lower()
    var = re.escape(var_name.lower())
    if re.search(rf"\b(class|struct|interface|enum)\b.*\b{var}\b", low):
        return "definition", 1.0
    if re.search(rf"\b(const|let|var|int|long|short|float|double|bool|char|string|size_t|auto)\b[^;]*\b{var}\b", low):
        return "definition", 1.0
    if re.search(rf"\b{var}\b\s*=", low):
        if re.search(r"default|fallback|init|initialize", low):
            return "init_or_default", 0.95
        return "assignment_or_update", 0.9
    if re.search(rf"\bif\b.*\b{var}\b|\b{var}\b.*[<>!=]=?", low):
        return "validation_or_condition", 0.88
    if re.search(rf'"{var}"|\'{var}\'|\b(env|config|setting)\b', low):
        return "config_source", 0.84
    if re.search(r"\b(db|database|save|insert|update|redis|sql|http|request|response|api)\b", low):
        return "persistence_or_api_transfer", 0.8
    if re.search(rf"\b{var}\b", low):
        return "read_or_use", 0.75
    return "read_or_use", 0.6


def classify_line_kind(line: str, var_names: list[str]) -> tuple[str, float]:
    best = ("read_or_use", 0.6)
    for var_name in var_names:
        cand = _classify_line_kind_single(line, var_name)
        if cand[1] > best[1]:
            best = cand
    return best


def _walk_node(node):
    yield node
    for child in node.children:
        yield from _walk_node(child)


def tree_sitter_symbol_hits(
    files: list[str],
    var_names: list[str],
    max_file_size: int,
    max_files: int = 500,
) -> list[Hit]:
    if not _TS_AVAILABLE:
        return []

    c_parser = Parser(Language(tsc.language()))
    java_parser = Parser(Language(tsjava.language()))
    parser_by_ext = {
        ".c": c_parser,
        ".h": c_parser,
        ".cc": c_parser,
        ".cpp": c_parser,
        ".hpp": c_parser,
        ".java": java_parser,
    }
    needles = {v.strip() for v in var_names if v.strip()}
    if not needles:
        return []

    hits: list[Hit] = []
    for file in files[:max_files]:
        ext = Path(file).suffix.lower()
        parser = parser_by_ext.get(ext)
        if parser is None:
            continue
        try:
            if Path(file).stat().st_size > max_file_size:
                continue
            source = Path(file).read_bytes()
            tree = parser.parse(source)
        except Exception:  # noqa: BLE001
            continue

        for node in _walk_node(tree.root_node):
            if node.type not in {"identifier", "field_identifier"}:
                continue
            text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
            if text not in needles:
                continue
            line = node.start_point[0] + 1
            col = node.start_point[1] + 1
            line_text = ""
            try:
                line_text = Path(file).read_text(encoding="utf-8", errors="replace").splitlines()[line - 1]
            except Exception:  # noqa: BLE001
                pass
            hits.append(Hit(file=file, line=line, col=col, text=line_text, kind="symbol_tree", score=1.25))

    return hits


def find_block_end_brace(lines: list[str], start_line: int, max_span: int = 400) -> int:
    i = max(1, start_line)
    brace = 0
    seen_open = False
    n = len(lines)
    end_limit = min(n, start_line + max_span)
    for ln in range(i, end_limit + 1):
        line = lines[ln - 1]
        opens = line.count("{")
        closes = line.count("}")
        if opens > 0:
            seen_open = True
        brace += opens - closes
        if seen_open and brace <= 0:
            return ln
    return min(n, start_line + 80)


def parse_symbols_in_file(path: str) -> list[Symbol]:
    p = Path(path)
    ext = p.suffix.lower()
    text = p.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    symbols: list[Symbol] = []

    if ext == ".py":
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    end = int(getattr(node, "end_lineno", node.lineno))
                    symbols.append(Symbol(path, node.name, "function", node.lineno, end))
                elif isinstance(node, ast.ClassDef):
                    end = int(getattr(node, "end_lineno", node.lineno))
                    symbols.append(Symbol(path, node.name, "class", node.lineno, end))
            return symbols
        except Exception:  # noqa: BLE001
            pass

    class_pat = re.compile(r"^\s*(?:export\s+)?(?:class|struct|interface)\s+([A-Za-z_]\w*)")
    py_class_pat = re.compile(r"^\s*class\s+([A-Za-z_]\w*)")
    py_def_pat = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
    c_func_pat = re.compile(
        r"^\s*(?!if\b|for\b|while\b|switch\b|return\b)(?:[A-Za-z_][\w:<>\*\s,&~]+?\s+)?([A-Za-z_]\w*)\s*\([^;]*\)\s*\{"
    )
    js_func_pat = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_]\w*)\s*\(")
    js_arrow_pat = re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{")
    java_method_pat = re.compile(
        r"^\s*(?:public|private|protected|static|final|synchronized|abstract|\s)+[\w<>\[\],\s]+\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{"
    )

    for i, line in enumerate(lines, start=1):
        m = class_pat.search(line) or py_class_pat.search(line)
        if m:
            name = m.group(1)
            end = find_block_end_brace(lines, i)
            symbols.append(Symbol(path, name, "class", i, end))
            continue

        m = py_def_pat.search(line)
        if m:
            name = m.group(1)
            end = len(lines)
            base_indent = len(line) - len(line.lstrip(" "))
            for j in range(i + 1, len(lines) + 1):
                l2 = lines[j - 1]
                if not l2.strip():
                    continue
                ind = len(l2) - len(l2.lstrip(" "))
                if ind <= base_indent and re.match(r"^\s*(?:def|class|async\s+def)\s+", l2):
                    end = j - 1
                    break
            symbols.append(Symbol(path, name, "function", i, end))
            continue

        m = js_func_pat.search(line) or js_arrow_pat.search(line) or java_method_pat.search(line) or c_func_pat.search(line)
        if m:
            name = m.group(1)
            if name in CALL_EXCLUDE:
                continue
            end = find_block_end_brace(lines, i)
            symbols.append(Symbol(path, name, "function", i, end))

    return symbols


def build_symbol_index(files: list[str], max_file_size: int) -> tuple[dict[str, list[Symbol]], dict[str, list[Symbol]]]:
    by_file: dict[str, list[Symbol]] = defaultdict(list)
    by_name: dict[str, list[Symbol]] = defaultdict(list)
    for file in files:
        try:
            if Path(file).stat().st_size > max_file_size:
                continue
            syms = parse_symbols_in_file(file)
        except Exception:  # noqa: BLE001
            continue
        for s in syms:
            by_file[file].append(s)
            by_name[s.name.lower()].append(s)
    for f in list(by_file.keys()):
        by_file[f].sort(key=lambda x: (x.start_line, x.end_line))
    return by_file, by_name


def symbol_at_line(symbols: list[Symbol], line_no: int) -> Symbol | None:
    in_scope = [s for s in symbols if s.start_line <= line_no <= s.end_line]
    if not in_scope:
        return None
    in_scope.sort(key=lambda x: (x.end_line - x.start_line, x.start_line))
    return in_scope[0]


def build_chunks_from_symbols(file: str, text: str, symbols: list[Symbol]) -> list[Chunk]:
    lines = text.splitlines()
    chunks: list[Chunk] = []
    if symbols:
        for s in symbols:
            start = max(1, s.start_line)
            end = min(len(lines), s.end_line)
            if end < start:
                continue
            snippet = "\n".join(lines[start - 1 : end])
            tokens = set(tokenize(snippet))
            chunks.append(Chunk(file=file, symbol=s.name, start_line=start, end_line=end, text=snippet, tokens=tokens))
        return chunks

    size = 90
    step = 60
    for start in range(1, len(lines) + 1, step):
        end = min(len(lines), start + size - 1)
        snippet = "\n".join(lines[start - 1 : end])
        tokens = set(tokenize(snippet))
        chunks.append(Chunk(file=file, symbol="", start_line=start, end_line=end, text=snippet, tokens=tokens))
        if end >= len(lines):
            break
    return chunks


def build_semantic_chunks(
    files: list[str],
    symbols_by_file: dict[str, list[Symbol]],
    max_chunks: int,
    max_file_size: int,
) -> list[Chunk]:
    out: list[Chunk] = []
    for file in files:
        try:
            if Path(file).stat().st_size > max_file_size:
                continue
            text = Path(file).read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        chunks = build_chunks_from_symbols(file, text, symbols_by_file.get(file, []))
        out.extend(chunks)
        if len(out) >= max_chunks:
            break
    return out[:max_chunks]


def score_chunk(
    chunk: Chunk,
    var_names: list[str],
    anchor_var_names: list[str],
    query_tokens: set[str],
    var_tokens: set[str],
) -> float:
    low_text = chunk.text.lower()
    score = 0.0
    exact_hits = 0
    anchor_hits = 0
    for var_name in var_names:
        if re.search(rf"\b{re.escape(var_name.lower())}\b", low_text):
            exact_hits += 1
    for var_name in anchor_var_names:
        if re.search(rf"\b{re.escape(var_name.lower())}\b", low_text):
            anchor_hits += 1
    overlap = len(chunk.tokens & query_tokens)
    token_overlap = len(chunk.tokens & var_tokens)

    if exact_hits > 0:
        score += 5.0 + min(3.0, (exact_hits - 1) * 0.8)
    elif token_overlap == 0:
        return 0.0

    score += overlap * 0.28
    score += token_overlap * 0.9

    if any(k in low_text for k in ["default", "init", "initialize", "fallback", "config"]):
        score += 0.8
    if any(k in low_text for k in ["if", "validate", "check", "must", "limit", "quota"]):
        score += 0.7
    if any(k in low_text for k in ["db", "database", "save", "insert", "update", "http", "request", "response", "api"]):
        score += 0.6

    # Keep semantic-only chunks as auxiliary evidence unless they anchor on exact variable names.
    if exact_hits == 0:
        score = min(score * 0.35, 2.2)
    elif anchor_var_names and anchor_hits == 0:
        # If only broad variable names hit (e.g., binder), treat as weak evidence.
        if token_overlap < 2:
            score = min(score * 0.25, 3.0)
        else:
            score = min(score * 0.45, 4.2)
    return score


def candidate_path_bias(path: str, desc_tokens: set[str], var_tokens: set[str]) -> float:
    low = path.lower().replace("\\", "/")
    bias = 0.0
    tls_context = bool({"tls", "psk", "binder", "identity", "handshake"} & desc_tokens)

    if any(seg in low for seg in ["/src/", "/wolfssl/"]):
        bias += 0.45
    if "/wolfcrypt/" in low:
        bias += 0.1
    if any(seg in low for seg in ["/.github/", "/certs/", "/linuxkm/", "/tools/", "/utils/"]):
        bias -= 1.2
    if tls_context and "/wolfcrypt/" in low:
        bias -= 2.2
    if tls_context and "dtls" not in desc_tokens and low.endswith("/dtls.c"):
        bias -= 0.7
    if tls_context and (low.endswith("/tls13.c") or low.endswith("/tls.c") or low.endswith("/internal.h")):
        bias += 0.9

    stem_tokens = set(split_identifier(Path(path).stem))
    if stem_tokens:
        bias += min(0.9, 0.22 * len(stem_tokens & desc_tokens))
        bias += min(0.9, 0.28 * len(stem_tokens & var_tokens))
    return bias


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    ranges = sorted(ranges, key=lambda x: (x[0], x[1]))
    out = [ranges[0]]
    for s, e in ranges[1:]:
        ls, le = out[-1]
        if s <= le + 1:
            out[-1] = (ls, max(le, e))
        else:
            out.append((s, e))
    return out


def render_snippet(path: str, ranges: list[tuple[int, int]], max_lines: int) -> str:
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    n = len(lines)
    normalized = []
    for s, e in ranges:
        s = max(1, s)
        e = min(n, e)
        if e >= s:
            normalized.append((s, e))
    merged = merge_ranges(normalized)

    selected: list[int] = []
    for s, e in merged:
        for i in range(s, e + 1):
            selected.append(i)
    selected = selected[:max_lines]

    out = []
    for i in selected:
        out.append(f"{i:5d}: {lines[i - 1]}")
    return "\n".join(out)


def _infer_category_single(snippet_text: str, var_name: str) -> tuple[str, str]:
    low = snippet_text.lower()
    var = re.escape(var_name.lower())
    if re.search(rf"\b(const|let|var|int|long|float|double|bool|string|size_t)\b.*\b{var}\b", low):
        return "definition", "looks like declaration/definition"
    if re.search(rf"\b{var}\b\s*=", low):
        if re.search(r"default|init|initialize|fallback", low):
            return "init_or_default", "looks like init/default assignment"
        return "assignment_or_update", "looks like assignment/update"
    if re.search(rf"\bif\b.*\b{var}\b|\b{var}\b.*[<>!=]=?", low):
        return "validation_or_condition", "appears in condition/validation"
    if re.search(rf'"{var}"|\'{var}\'|\b(config|env|setting)\b', low):
        return "config_source", "looks config/env related"
    if re.search(r"\b(db|database|save|insert|update|http|request|response|api|redis)\b", low):
        return "persistence_or_api_transfer", "looks persistence/API transfer related"
    return "read_or_use", "looks like read/use"


def infer_category(snippet_text: str, var_names: list[str]) -> tuple[str, str]:
    best = ("read_or_use", "looks like read/use")
    priority = {
        "definition": 7,
        "init_or_default": 6,
        "assignment_or_update": 5,
        "validation_or_condition": 4,
        "config_source": 3,
        "persistence_or_api_transfer": 2,
        "read_or_use": 1,
    }
    for var_name in var_names:
        cand = _infer_category_single(snippet_text, var_name)
        if priority.get(cand[0], 0) > priority.get(best[0], 0):
            best = cand
    return best


def extract_calls(snippet: str, top_n: int = 12, anchor_tokens: set[str] | None = None) -> list[str]:
    calls = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", snippet)
    out = []
    seen = set()
    for c in calls:
        low = c.lower()
        if low in CALL_EXCLUDE or c.isupper():
            continue
        if anchor_tokens:
            parts = set(split_identifier(c))
            if not (parts & anchor_tokens):
                continue
        if low in seen:
            continue
        seen.add(low)
        out.append(c)
        if len(out) >= top_n:
            break
    return out


def call_chat_completions(
    api_key: str,
    base_url: str,
    model: str,
    prompt: str,
    temperature: float,
    timeout_sec: int,
) -> str:
    endpoint = f"{normalize_base_url(base_url)}/chat/completions"
    payload_base = {
        "model": model,
        "temperature": temperature,
        "messages": [
            {"role": "user", "content": prompt},
        ],
    }
    payloads = [
        {**payload_base, "response_format": {"type": "json_object"}},
        payload_base,
    ]
    body = ""
    last_exc: Exception | None = None
    for idx, payload in enumerate(payloads):
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
            break
        except error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            # Some compatible providers may not support response_format.
            if idx == 0 and e.code in (400, 404, 422):
                low = body.lower()
                if "response_format" in low or "json_object" in low or "unsupported" in low:
                    continue
            last_exc = RuntimeError(f"HTTPError {e.code}: {body}")
            break
        except error.URLError as e:
            last_exc = RuntimeError(f"URLError: {e}")
            break
    if not body:
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("empty response body from model endpoint")

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


def extract_json_object(text: str) -> dict[str, Any]:
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        raise ValueError("cannot parse JSON object from model output")
    obj = json.loads(m.group(0))
    if not isinstance(obj, dict):
        raise ValueError("model output is not JSON object")
    return obj


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Variable-context pipeline: text recall + symbol recall + semantic recall + context expansion + optional LLM filtering."
    )
    parser.add_argument("--repo-root", default=".")
    parser.add_argument(
        "--var-name",
        required=True,
        action="append",
        help="Target variable name. For multiple variables, repeat this option or use comma-separated values.",
    )
    parser.add_argument("--desc", required=True)
    parser.add_argument("--output", default="output/variable_context_result.json")

    parser.add_argument("--max-files", type=int, default=20000)
    parser.add_argument("--max-file-size", type=int, default=600000)
    parser.add_argument("--max-text-hits", type=int, default=300)
    parser.add_argument("--max-semantic-chunks", type=int, default=6000)
    parser.add_argument("--top-semantic", type=int, default=80)
    parser.add_argument("--top-candidates", type=int, default=25)
    parser.add_argument("--context-window", type=int, default=30)
    parser.add_argument("--max-snippet-lines", type=int, default=220)
    parser.add_argument("--max-related-calls", type=int, default=1)

    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--base-url", default="https://api.bltcy.ai/v1/")
    parser.add_argument("--model", default="claude-opus-4-7")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        repo_root = Path(args.repo_root).resolve(strict=False)
        if not repo_root.exists():
            raise ValueError(f"repo root not found: {repo_root}")

        input_var_names = parse_var_names(args.var_name)
        if not input_var_names:
            raise ValueError("var-name cannot be empty")
        var_names = expand_var_aliases(input_var_names)
        var_name = ", ".join(input_var_names)
        desc = args.desc.strip()

        print(f"[{now_ts()}] collecting files")
        files = collect_files(repo_root, max_files=max(1, args.max_files))
        if not files:
            raise ValueError("no source files found under repo root")

        print(f"[{now_ts()}] building symbol index")
        symbols_by_file, symbols_by_name = build_symbol_index(files, max_file_size=max(1, args.max_file_size))

        print(f"[{now_ts()}] text recall")
        var_tokens = build_var_tokens(input_var_names)
        anchor_var_names = build_anchor_var_names(var_names)
        desc_tokens = {t for t in tokenize(desc) if len(t) >= 3}
        query_tokens = set(var_tokens)
        query_tokens.update(desc_tokens)
        query_tokens.update(t for t in SEMANTIC_HINTS if t not in NOISY_QUERY_TOKENS)
        query_tokens = {
            t
            for t in query_tokens
            if len(t) >= 3 and t not in GENERIC_VAR_TOKENS and t not in NOISY_QUERY_TOKENS
        }

        search_var_names = [n for n in var_names if not _is_generic_name(n)]
        if not search_var_names:
            search_var_names = var_names

        patterns: list[str] = []
        seen_patterns: set[str] = set()
        for name in search_var_names:
            for pat in (
                rf"\b{re.escape(name)}\b",
                rf"['\"]{re.escape(name)}['\"]",
            ):
                if pat not in seen_patterns:
                    seen_patterns.add(pat)
                    patterns.append(pat)
        text_hits = run_rg_json(repo_root, patterns, max_hits=max(1, args.max_text_hits))
        if not text_hits:
            text_hits = fallback_text_search(repo_root, search_var_names, max_hits=max(1, args.max_text_hits))

        print(f"[{now_ts()}] symbol recall (tree-sitter)")
        symbol_hits = tree_sitter_symbol_hits(
            files=files,
            var_names=search_var_names,
            max_file_size=max(1, args.max_file_size),
            max_files=500,
        )
        text_hits.extend(symbol_hits)

        for h in text_hits:
            _, line_score = classify_line_kind(h.text, search_var_names)
            h.score = max(h.score, line_score)

        print(f"[{now_ts()}] semantic recall")
        chunks = build_semantic_chunks(
            files=files,
            symbols_by_file=symbols_by_file,
            max_chunks=max(100, args.max_semantic_chunks),
            max_file_size=max(1, args.max_file_size),
        )

        scored_chunks: list[tuple[float, Chunk]] = []
        for ch in chunks:
            s = score_chunk(ch, search_var_names, anchor_var_names, query_tokens, var_tokens)
            if s > 0:
                scored_chunks.append((s, ch))
        scored_chunks.sort(key=lambda x: (-x[0], x[1].file, x[1].start_line))
        scored_chunks = scored_chunks[: max(1, args.top_semantic)]

        print(f"[{now_ts()}] merging candidates")
        candidate_map: dict[tuple[str, int, int, str], Candidate] = {}

        def add_candidate(
            file: str,
            symbol: str,
            start_line: int,
            end_line: int,
            score: float,
            source_tag: str,
            hit_line: int | None,
            reason: str,
        ) -> None:
            adjusted_score = score + candidate_path_bias(file, desc_tokens=desc_tokens, var_tokens=var_tokens)
            key = (file, start_line, end_line, symbol)
            if key not in candidate_map:
                candidate_map[key] = Candidate(
                    file=file,
                    symbol=symbol,
                    start_line=start_line,
                    end_line=end_line,
                    score=adjusted_score,
                    source_tags={source_tag},
                    hit_lines={hit_line} if hit_line else set(),
                    reason_parts=[reason] if reason else [],
                )
            else:
                c = candidate_map[key]
                c.score = max(c.score, adjusted_score)
                c.source_tags.add(source_tag)
                if hit_line:
                    c.hit_lines.add(hit_line)
                if reason:
                    c.reason_parts.append(reason)

        grouped_hits: dict[str, list[Hit]] = defaultdict(list)
        for h in text_hits:
            grouped_hits[h.file].append(h)

        for file, hits in grouped_hits.items():
            syms = symbols_by_file.get(file, [])
            for h in hits:
                sym = symbol_at_line(syms, h.line)
                if sym:
                    add_candidate(
                        file=file,
                        symbol=sym.name,
                        start_line=sym.start_line,
                        end_line=sym.end_line,
                        score=3.0 + h.score,
                        source_tag="text",
                        hit_line=h.line,
                        reason=f"text hit at line {h.line}",
                    )
                else:
                    add_candidate(
                        file=file,
                        symbol="",
                        start_line=max(1, h.line - args.context_window),
                        end_line=h.line + args.context_window,
                        score=2.2 + h.score,
                        source_tag="text",
                        hit_line=h.line,
                        reason=f"text hit window at line {h.line}",
                    )

        for vn in search_var_names:
            exact_syms = symbols_by_name.get(vn.lower(), [])
            for s in exact_syms:
                add_candidate(
                    file=s.file,
                    symbol=s.name,
                    start_line=s.start_line,
                    end_line=s.end_line,
                    score=4.8,
                    source_tag="symbol",
                    hit_line=s.start_line,
                    reason=f"exact symbol name match: {vn}",
                )

        for name, syms in symbols_by_name.items():
            name_tokens = set(split_identifier(name))
            if not name_tokens:
                continue
            overlap = len(name_tokens & query_tokens)
            anchor_overlap = len(name_tokens & var_tokens)
            if anchor_overlap < 1:
                continue
            if overlap < 1:
                continue
            for s in syms[:2]:
                add_candidate(
                    file=s.file,
                    symbol=s.name,
                    start_line=s.start_line,
                    end_line=s.end_line,
                    score=1.8 + overlap * 0.3 + anchor_overlap * 0.9,
                    source_tag="symbol",
                    hit_line=s.start_line,
                    reason=f"semantic symbol overlap={overlap}, anchor_overlap={anchor_overlap}",
                )

        for s, ch in scored_chunks:
            add_candidate(
                file=ch.file,
                symbol=ch.symbol,
                start_line=ch.start_line,
                end_line=ch.end_line,
                score=1.5 + s,
                source_tag="semantic",
                hit_line=ch.start_line,
                reason=f"semantic score={round(s, 3)}",
            )

        candidates = list(candidate_map.values())
        candidates.sort(key=lambda c: (-c.score, c.file, c.start_line))
        candidates = candidates[: max(1, args.top_candidates)]

        if args.dry_run:
            print(f"files={len(files)} text_hits={len(text_hits)} chunks={len(chunks)} candidates={len(candidates)}")
            return 0

        print(f"[{now_ts()}] context expansion")
        candidate_payload: list[dict[str, Any]] = []
        for idx, c in enumerate(candidates, start=1):
            try:
                all_lines = Path(c.file).read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:  # noqa: BLE001
                continue
            n = len(all_lines)
            ranges = [(c.start_line, c.end_line)]
            for hl in sorted(c.hit_lines):
                ranges.append((max(1, hl - args.context_window), min(n, hl + args.context_window)))

            snippet = render_snippet(c.file, ranges, max_lines=max(20, args.max_snippet_lines))
            category, reason_category = infer_category(snippet, search_var_names)

            related = []
            if args.max_related_calls > 0:
                call_names = extract_calls(snippet, top_n=20, anchor_tokens=var_tokens)
                used = 0
                for call in call_names:
                    defs = symbols_by_name.get(call.lower(), [])
                    for d in defs:
                        if d.file == c.file:
                            continue
                        try:
                            rel_text = render_snippet(d.file, [(d.start_line, min(d.end_line, d.start_line + 40))], max_lines=45)
                        except Exception:  # noqa: BLE001
                            continue
                        related.append(
                            {
                                "file": d.file,
                                "symbol": d.name,
                                "start_line": d.start_line,
                                "end_line": d.end_line,
                                "snippet": rel_text,
                            }
                        )
                        used += 1
                        if used >= args.max_related_calls:
                            break
                    if used >= args.max_related_calls:
                        break

            candidate_payload.append(
                {
                    "id": f"cand_{idx:03d}",
                    "file": c.file,
                    "symbol": c.symbol,
                    "start_line": c.start_line,
                    "end_line": c.end_line,
                    "score_raw": round(c.score, 3),
                    "source_tags": sorted(c.source_tags),
                    "category_guess": category,
                    "reason": " ; ".join(c.reason_parts[:6] + [reason_category]),
                    "snippet": snippet,
                    "related_snippets": related,
                }
            )

        relevant_heuristic = []
        for cand in candidate_payload:
            score = min(1.0, max(0.0, cand["score_raw"] / 10.0))
            relevant_heuristic.append(
                {
                    "file": cand["file"],
                    "symbol": cand["symbol"],
                    "category": cand["category_guess"],
                    "score": round(score, 3),
                    "reason": cand["reason"],
                    "snippet": cand["snippet"][:3000],
                }
            )
        relevant_heuristic.sort(key=lambda x: (-x["score"], x["file"]))

        result_obj: dict[str, Any] = {
            "relevant_snippets": relevant_heuristic[:15],
            "summary": "Heuristic ranking result (LLM not used).",
            "missing_links": [],
        }
        raw_model_output = ""
        llm_warning = ""

        if args.use_llm:
            if not args.api_key:
                raise ValueError("missing API key for --use-llm")
            print(f"[{now_ts()}] LLM filtering")
            compact_candidates = []
            for cand in candidate_payload[: max(10, min(len(candidate_payload), 20))]:
                compact_candidates.append(
                    {
                        "id": cand["id"],
                        "file": cand["file"],
                        "symbol": cand["symbol"],
                        "start_line": cand["start_line"],
                        "end_line": cand["end_line"],
                        "score_raw": cand["score_raw"],
                        "source_tags": cand["source_tags"],
                        "category_guess": cand["category_guess"],
                        "reason": cand["reason"],
                        "snippet": cand["snippet"][:2200],
                    }
                )

            prompt = PROMPT_TEMPLATE.format(
                var_name=var_name,
                desc=desc,
                candidate_json=json.dumps(compact_candidates, ensure_ascii=False, indent=2),
            )
            try:
                raw_model_output = call_chat_completions(
                    api_key=args.api_key,
                    base_url=args.base_url,
                    model=args.model,
                    prompt=prompt,
                    temperature=args.temperature,
                    timeout_sec=args.timeout_sec,
                )
                parsed = extract_json_object(raw_model_output)
                if isinstance(parsed, dict):
                    result_obj = parsed
            except Exception as llm_e:  # noqa: BLE001
                llm_warning = (
                    "LLM filtering failed; fallback to heuristic ranking. "
                    f"error={llm_e}"
                )
                print(f"[WARN] {llm_warning}", file=sys.stderr)

        output = {
            "meta": {
                "generated_at": now_ts(),
                "repo_root": str(repo_root),
                "var_name": var_name,
                "var_names": input_var_names,
                "var_name_aliases": var_names,
                "search_var_names": search_var_names,
                "anchor_var_names": anchor_var_names,
                "desc": desc,
                "use_llm": args.use_llm,
                "model": args.model if args.use_llm else "",
            },
            "recall_stats": {
                "file_count": len(files),
                "text_hit_count": len(text_hits),
                "symbol_hit_count": len(symbol_hits),
                "semantic_chunk_count": len(chunks),
                "semantic_top_count": len(scored_chunks),
                "candidate_count": len(candidate_payload),
            },
            "candidate_snippets": candidate_payload,
            "result": result_obj,
        }
        if raw_model_output:
            output["raw_model_output"] = raw_model_output
        if llm_warning:
            output["llm_warning"] = llm_warning

        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[{now_ts()}] done -> {out_path}")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
