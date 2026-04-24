#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib import error, request

SYSTEM_PROMPT = """
You are a code-retrieval assistant.
Given a target JSON object and a list of candidate file paths, return the most relevant files only from candidates.

Rules:
1. You must select files only from the provided candidate list.
2. Score relevance from 0 to 100.
3. Keep reason short and evidence-based.
4. If evidence is weak, lower score and state uncertainty in reason.
5. Output must be strict JSON only.
""".strip()

USER_PROMPT_TEMPLATE = """
Find top {top_k} relevant files for the target JSON.

Return strict JSON in this shape:
{{
  "related_files": [
    {{
      "file": "one file from candidate list",
      "score": 0,
      "reason": "short reason"
    }}
  ]
}}

Constraints:
- `file` must be from candidate file list
- sort by score descending
- if none is relevant, return {{ "related_files": [] }}

Candidate files:
{file_list}

Target JSON:
{target_json}
""".strip()

VARIABLE_SYSTEM_PROMPT = """
You are a code-variable extraction assistant.
Given a target change JSON and code snippets from related files, extract the variable/field names that best match the change.

Rules:
1. Prefer concrete variable/field names over function/type names.
2. Variable names must come from provided snippet text.
3. Keep the primary target variable as the semantic anchor.
4. A change may map to one or multiple variables, but avoid generic helper locals.
5. Do NOT output generic locals such as: label, key, len, length, idx, i, j, k, ret, tmp, buf, data, protocol.
6. If uncertain, return fewer names.
7. Output must be strict JSON only.
""".strip()

VARIABLE_USER_PROMPT_TEMPLATE = """
Extract up to {max_variables} variable names for this target change.

Return strict JSON in this shape:
{{
  "variables": ["var_a", "var_b"]
}}

Constraints:
- Keep order by relevance (most relevant first).
- Variables should be present in snippet text.
- Keep primary variable semantic focus: `{primary_variable}`.
- Prefer identifiers semantically tied to focus terms: {focus_terms}.
- If no confident match, return {{ "variables": [] }}.

Target change JSON:
{target_json}

Related files:
{related_files}

Candidate identifiers from snippets:
{identifier_candidates}

Code snippets:
{snippets}
""".strip()

KEYWORD_STOP_WORDS = {
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
    "must",
    "should",
    "could",
    "would",
    "may",
    "might",
    "can",
    "cannot",
    "true",
    "false",
    "null",
    "none",
    "set",
    "value",
    "values",
    "change",
    "condition",
    "action",
    "related",
    "state",
    "step",
    "evidence",
    "note",
    "explicit",
    "inferred",
}

GENERIC_IDENTIFIER_EXCLUDE = {
    "label",
    "key",
    "len",
    "length",
    "idx",
    "index",
    "tmp",
    "ret",
    "result",
    "rc",
    "err",
    "error",
    "buf",
    "buffer",
    "data",
    "value",
    "values",
    "size",
    "count",
    "num",
    "protocol",
    "status",
    "extension",
    "extensions",
    "okm",
    "prk",
    "elabel",
    "i",
    "j",
    "k",
}


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


def load_json_data(json_file: str, json_text: str) -> Any:
    if json_text:
        return json.loads(json_text)
    if json_file:
        return json.loads(Path(json_file).read_text(encoding="utf-8"))
    raise ValueError("must provide --json-file or --json-text")


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    out: list[str] = []
    for item in items:
        v = item.strip()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _load_candidates_from_csv(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8")
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        return []

    reader = csv.DictReader(lines)
    headers = reader.fieldnames or []
    header_map = {h.lower().strip(): h for h in headers if h}
    preferred = ["file", "path", "filename", "file_path", "filepath"]

    selected_header = ""
    for key in preferred:
        if key in header_map:
            selected_header = header_map[key]
            break

    candidates: list[str] = []
    if selected_header:
        for row in reader:
            value = str(row.get(selected_header, "")).strip()
            if value:
                candidates.append(value)
        return _dedupe_keep_order(candidates)

    # fallback: use first column if no common header name exists
    first_header = headers[0] if headers else ""
    if not first_header:
        return []
    for row in reader:
        value = str(row.get(first_header, "")).strip()
        if value:
            candidates.append(value)
    return _dedupe_keep_order(candidates)


def load_candidate_files(files: list[str], files_from: str) -> list[str]:
    candidates = [f.strip() for f in files if f.strip()]
    if files_from:
        path = Path(files_from)
        suffix = path.suffix.lower()
        if suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise ValueError("--files-from JSON must be a string array")
            candidates.extend(str(x).strip() for x in data if str(x).strip())
        elif suffix == ".csv":
            candidates.extend(_load_candidates_from_csv(path))
        else:
            raw = path.read_text(encoding="utf-8")
            for line in raw.splitlines():
                v = line.strip()
                if v:
                    candidates.append(v)
    return _dedupe_keep_order(candidates)


def build_user_prompt(file_names: list[str], target_json_obj: Any, top_k: int) -> str:
    file_list = "\n".join(f"- {name}" for name in file_names)
    target_json = json.dumps(target_json_obj, ensure_ascii=False, indent=2)
    return USER_PROMPT_TEMPLATE.format(top_k=top_k, file_list=file_list, target_json=target_json)


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


def sanitize_result(raw_obj: dict[str, Any], candidates: list[str], top_k: int) -> dict[str, Any]:
    related = raw_obj.get("related_files", [])
    if not isinstance(related, list):
        related = []

    allowed = set(candidates)
    cleaned: list[dict[str, Any]] = []
    seen = set()
    for item in related:
        if not isinstance(item, dict):
            continue
        file_name = str(item.get("file", "")).strip()
        if not file_name or file_name not in allowed or file_name in seen:
            continue
        seen.add(file_name)
        try:
            score = int(float(item.get("score", 0)))
        except (TypeError, ValueError):
            score = 0
        score = max(0, min(100, score))
        reason = str(item.get("reason", "")).strip()
        cleaned.append({"file": file_name, "score": score, "reason": reason})

    cleaned.sort(key=lambda x: x["score"], reverse=True)
    return {"related_files": cleaned[:top_k]}


def normalize_path(path_text: str, repo_root: Path) -> str:
    p = Path(path_text)
    if not p.is_absolute():
        p = repo_root / p
    return str(p.resolve(strict=False))


def safe_read_text(path: str, max_bytes: int) -> str:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return ""
    data = p.read_bytes()
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace")


def _split_identifier_tokens(name: str) -> list[str]:
    if not name:
        return []
    words: list[str] = []
    for chunk in re.split(r"[^A-Za-z0-9_]+", name):
        if not chunk:
            continue
        parts = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+", chunk)
        if parts:
            words.extend(p.lower() for p in parts if p)
        else:
            words.append(chunk.lower())
    return words


def _extract_primary_variable(change_obj: Any) -> str:
    if not isinstance(change_obj, dict):
        return ""
    return str(change_obj.get("variable_name", "")).strip()


def _build_anchor_tokens(terms: list[str]) -> set[str]:
    out: set[str] = set()
    for term in terms:
        for tok in _split_identifier_tokens(term):
            if len(tok) < 3:
                continue
            if tok in KEYWORD_STOP_WORDS:
                continue
            if tok in GENERIC_IDENTIFIER_EXCLUDE:
                continue
            out.add(tok)
    return out


def _extract_focus_terms(change_obj: Any, primary_variable: str, max_terms: int = 20) -> list[str]:
    fields: list[str] = []
    if isinstance(change_obj, dict):
        for key in ("change_condition", "change_action", "old_value", "new_value", "related_state_or_step", "evidence", "note"):
            fields.append(str(change_obj.get(key, "")))

    primary_tokens = _build_anchor_tokens([primary_variable])
    out: list[str] = []
    seen: set[str] = set()

    def _add(term: str) -> None:
        t = term.strip()
        if not t:
            return
        low = t.lower()
        if low in seen:
            return
        seen.add(low)
        out.append(t)

    _add(primary_variable)
    for tok in _split_identifier_tokens(primary_variable):
        if len(tok) >= 3 and tok not in GENERIC_IDENTIFIER_EXCLUDE:
            _add(tok)

    for text in fields:
        for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,63}", text):
            low = ident.lower()
            if len(low) < 3:
                continue
            if low in KEYWORD_STOP_WORDS:
                continue
            if low in GENERIC_IDENTIFIER_EXCLUDE:
                continue
            if primary_tokens:
                ident_tokens = set(_split_identifier_tokens(ident))
                if not (ident_tokens & primary_tokens):
                    continue
            _add(ident)
            if len(out) >= max_terms:
                return out
    return out


def _extract_change_keywords(change_obj: Any, focus_terms: list[str], max_keywords: int = 40) -> list[str]:
    raw = json.dumps(change_obj, ensure_ascii=False)
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,63}", raw)
    focus_tokens = _build_anchor_tokens(focus_terms)

    out: list[str] = []
    seen: set[str] = set()

    for t in focus_terms:
        low = t.strip().lower()
        if not low or low in seen:
            continue
        seen.add(low)
        out.append(t.strip())
        if len(out) >= max_keywords:
            return out

    for tok in tokens:
        low = tok.lower()
        if len(low) < 3:
            continue
        if low in KEYWORD_STOP_WORDS:
            continue
        if low in GENERIC_IDENTIFIER_EXCLUDE:
            continue
        if low in seen:
            continue
        if focus_tokens:
            tok_parts = set(_split_identifier_tokens(tok))
            if not (tok_parts & focus_tokens):
                continue
        seen.add(low)
        out.append(tok)
        if len(out) >= max_keywords:
            break
    return out


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    ranges.sort(key=lambda x: (x[0], x[1]))
    out = [ranges[0]]
    for s, e in ranges[1:]:
        ls, le = out[-1]
        if s <= le + 1:
            out[-1] = (ls, max(le, e))
        else:
            out.append((s, e))
    return out


def _build_snippet_from_file(
    file_path: str,
    keywords: list[str],
    context_lines: int,
    max_lines_per_file: int,
    max_file_bytes: int,
    max_hit_lines: int = 24,
) -> str:
    text = safe_read_text(file_path, max_bytes=max_file_bytes)
    if not text:
        return ""

    lines = text.splitlines()
    if not lines:
        return ""

    patterns: list[re.Pattern[str]] = []
    for k in keywords:
        k = k.strip()
        if not k:
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
            pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(k)}(?![A-Za-z0-9_])", flags=re.IGNORECASE)
        else:
            pat = re.compile(re.escape(k), flags=re.IGNORECASE)
        patterns.append(pat)

    ranges: list[tuple[int, int]] = []
    hit_count = 0
    if patterns:
        for i, line in enumerate(lines, start=1):
            for pat in patterns:
                if pat.search(line):
                    ranges.append((max(1, i - context_lines), min(len(lines), i + context_lines)))
                    hit_count += 1
                    break
            if hit_count >= max_hit_lines:
                break

    if not ranges:
        return ""

    merged = _merge_ranges(ranges)
    selected: list[int] = []
    for s, e in merged:
        for ln in range(s, e + 1):
            selected.append(ln)
            if len(selected) >= max_lines_per_file:
                break
        if len(selected) >= max_lines_per_file:
            break

    if not selected:
        return ""

    out = [f"# file: {file_path}"]
    for ln in selected:
        out.append(f"{ln:5d}: {lines[ln - 1]}")
    return "\n".join(out)


def _extract_identifier_candidates(snippets: list[str], anchor_tokens: set[str], top_n: int = 180) -> list[str]:
    score_map: dict[str, int] = {}
    for snippet in snippets:
        lines = snippet.splitlines()
        for line in lines:
            if line.startswith("# file:"):
                continue
            code = re.sub(r"^\s*\d+:\s*", "", line)
            for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{1,63}\b", code):
                low = token.lower()
                if low in KEYWORD_STOP_WORDS:
                    continue
                if low in GENERIC_IDENTIFIER_EXCLUDE:
                    continue
                score = score_map.get(token, 0) + 1
                if re.search(rf"\b{re.escape(token)}\b\s*=", code):
                    score += 2
                if re.search(rf"->\s*{re.escape(token)}\b|\.\s*{re.escape(token)}\b", code):
                    score += 2
                if re.search(rf"\b{re.escape(token)}\b\s*\(", code):
                    score -= 1
                parts = set(_split_identifier_tokens(token))
                if anchor_tokens and (parts & anchor_tokens):
                    score += 3
                elif anchor_tokens:
                    score -= 1
                score_map[token] = score

    ranked = sorted(score_map.items(), key=lambda x: (-x[1], x[0].lower()))
    return [name for name, s in ranked if s > 0][:top_n]


def build_variable_user_prompt(
    change_obj: Any,
    primary_variable: str,
    focus_terms: list[str],
    related_files: list[str],
    snippets: list[str],
    identifier_candidates: list[str],
    max_variables: int,
) -> str:
    target_json = json.dumps(change_obj, ensure_ascii=False, indent=2)
    files_text = "\n".join(f"- {p}" for p in related_files) if related_files else "(none)"
    ids_text = ", ".join(identifier_candidates) if identifier_candidates else "(none)"
    snippet_text = "\n\n".join(snippets) if snippets else "(no snippet available)"
    return VARIABLE_USER_PROMPT_TEMPLATE.format(
        max_variables=max_variables,
        primary_variable=primary_variable or "(unknown)",
        focus_terms=", ".join(focus_terms) if focus_terms else "(none)",
        target_json=target_json,
        related_files=files_text,
        identifier_candidates=ids_text,
        snippets=snippet_text,
    )


def sanitize_variable_names(
    raw_obj: dict[str, Any],
    max_variables: int,
    primary_variable: str,
    anchor_tokens: set[str],
) -> list[str]:
    items = raw_obj.get("variables", [])
    if not isinstance(items, list):
        return []

    out: list[str] = []
    seen: set[str] = set()
    valid_pat = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|->|::)[A-Za-z_][A-Za-z0-9_]*)*$")
    primary_low = primary_variable.lower().strip()

    def add_name(name: str) -> None:
        low = name.lower()
        if low in seen:
            return
        seen.add(low)
        out.append(name)

    if primary_variable and valid_pat.fullmatch(primary_variable):
        add_name(primary_variable)

    for item in items:
        name = str(item).strip().strip("\"'`")
        if not name:
            continue
        if len(name) > 96:
            continue
        if not valid_pat.fullmatch(name):
            continue
        low = name.lower()
        if low in seen:
            continue
        if low in GENERIC_IDENTIFIER_EXCLUDE and low != primary_low:
            continue
        if anchor_tokens:
            parts = set(_split_identifier_tokens(name))
            if name.lower() != primary_low and not (parts & anchor_tokens):
                continue
        add_name(name)
        if len(out) >= max_variables:
            break
    return out


def _fallback_variables_from_identifiers(
    *,
    identifier_candidates: list[str],
    primary_variable: str,
    anchor_tokens: set[str],
    max_variables: int,
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    primary_low = primary_variable.lower().strip()

    def add(name: str) -> None:
        v = name.strip()
        if not v:
            return
        low = v.lower()
        if low in seen:
            return
        seen.add(low)
        out.append(v)

    if primary_variable:
        add(primary_variable)

    for name in identifier_candidates:
        low = name.lower()
        if low in GENERIC_IDENTIFIER_EXCLUDE and low != primary_low:
            continue
        parts = set(_split_identifier_tokens(name))
        if anchor_tokens and not (parts & anchor_tokens):
            continue
        add(name)
        if len(out) >= max_variables:
            break

    return out[:max_variables]


def run_variable_mode(
    change_obj: Any,
    related_result: dict[str, Any],
    repo_root: Path,
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    timeout_sec: int,
    max_file_bytes: int,
    context_lines: int,
    max_lines_per_file: int,
    max_variables: int,
) -> tuple[list[str], str]:
    related_items = related_result.get("related_files", [])
    related_files: list[str] = []
    if isinstance(related_items, list):
        for item in related_items:
            if not isinstance(item, dict):
                continue
            fp = str(item.get("file", "")).strip()
            if fp:
                related_files.append(normalize_path(fp, repo_root))
    related_files = _dedupe_keep_order(related_files)

    primary_variable = _extract_primary_variable(change_obj)
    focus_terms = _extract_focus_terms(change_obj, primary_variable)
    anchor_tokens = _build_anchor_tokens(focus_terms)
    keywords = _extract_change_keywords(change_obj, focus_terms=focus_terms)
    snippets: list[str] = []
    for fp in related_files:
        snippet = _build_snippet_from_file(
            file_path=fp,
            keywords=keywords,
            context_lines=max(0, context_lines),
            max_lines_per_file=max(20, max_lines_per_file),
            max_file_bytes=max(20_000, max_file_bytes),
        )
        if snippet:
            snippets.append(snippet)

    if not snippets and primary_variable:
        fallback_keywords = [primary_variable] + _split_identifier_tokens(primary_variable)
        for fp in related_files:
            snippet = _build_snippet_from_file(
                file_path=fp,
                keywords=fallback_keywords,
                context_lines=max(3, context_lines),
                max_lines_per_file=max(20, max_lines_per_file),
                max_file_bytes=max(20_000, max_file_bytes),
            )
            if snippet:
                snippets.append(snippet)

    identifier_candidates = _extract_identifier_candidates(snippets, anchor_tokens=anchor_tokens)
    user_prompt = build_variable_user_prompt(
        change_obj=change_obj,
        primary_variable=primary_variable,
        focus_terms=focus_terms,
        related_files=related_files,
        snippets=snippets,
        identifier_candidates=identifier_candidates,
        max_variables=max(1, max_variables),
    )
    raw_text = call_chat_completions(
        api_key=api_key,
        base_url=base_url,
        model=model,
        system_prompt=VARIABLE_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        temperature=temperature,
        timeout_sec=timeout_sec,
    )
    raw_obj = extract_json_object(raw_text)
    variables = sanitize_variable_names(
        raw_obj,
        max_variables=max(1, max_variables),
        primary_variable=primary_variable,
        anchor_tokens=anchor_tokens,
    )

    fallback_variables = _fallback_variables_from_identifiers(
        identifier_candidates=identifier_candidates,
        primary_variable=primary_variable,
        anchor_tokens=anchor_tokens,
        max_variables=max(1, max_variables),
    )
    if not variables:
        variables = fallback_variables
    else:
        seen = {v.lower() for v in variables}
        for name in fallback_variables:
            low = name.lower()
            if low in seen:
                continue
            variables.append(name)
            seen.add(low)
            if len(variables) >= max(1, max_variables):
                break

    if not variables and isinstance(change_obj, dict):
        fallback = str(change_obj.get("variable_name", "")).strip()
        if fallback:
            variables = [fallback]
    return variables, raw_text


def parse_changes(changes_file: str, changes_key: str) -> list[dict[str, Any]]:
    data = json.loads(Path(changes_file).read_text(encoding="utf-8"))
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        node = data.get(changes_key, [])
        if not isinstance(node, list):
            raise ValueError(f"{changes_file} -> key `{changes_key}` is not a list")
        items = node
    else:
        raise ValueError(f"{changes_file} is not a JSON object/array")

    out: list[dict[str, Any]] = []
    for idx, item in enumerate(items):
        if isinstance(item, dict):
            out.append(item)
        else:
            out.append({"_raw": item, "_index": idx})
    return out


def run_single_mode(
    candidates: list[str],
    target_json_obj: Any,
    api_key: str,
    base_url: str,
    model: str,
    top_k: int,
    temperature: float,
    timeout_sec: int,
) -> tuple[dict[str, Any], str]:
    user_prompt = build_user_prompt(candidates, target_json_obj, top_k)
    raw_text = call_chat_completions(
        api_key=api_key,
        base_url=base_url,
        model=model,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        temperature=temperature,
        timeout_sec=timeout_sec,
    )
    raw_obj = extract_json_object(raw_text)
    result = sanitize_result(raw_obj, candidates, top_k)
    return result, raw_text


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Step4: find related files and then extract corresponding variable names.\n"
            "Outputs variable names to console (no JSON file output)."
        )
    )
    parser.add_argument("--repo-root", default=".", help="repo root for resolving relative file paths")
    parser.add_argument("--files", nargs="*", default=[], help="candidate file paths")
    parser.add_argument(
        "--files-from",
        default="",
        help=(
            "candidate file source: .txt(one per line), .json(string list), "
            "or .csv(with file/path/filename column)"
        ),
    )

    # single-target mode
    parser.add_argument("--json-file", default="", help="target JSON file path")
    parser.add_argument("--json-text", default="", help="target JSON text")

    # batch mode
    parser.add_argument("--changes-file", default="", help="JSON file containing changes list")
    parser.add_argument("--changes-key", default="changes", help="list key in changes file")
    parser.add_argument("--start-index", type=int, default=0, help="batch start index (inclusive)")
    parser.add_argument("--max-items", type=int, default=0, help="max number of changes to process, 0=all")

    parser.add_argument("--output", default="", help="deprecated: ignored, kept for backward compatibility")
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--base-url", default="https://api.zhizengzeng.com/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--snippet-max-file-bytes", type=int, default=350000, help="max bytes per related file for snippet extraction")
    parser.add_argument("--snippet-context-lines", type=int, default=2, help="context lines around keyword hit")
    parser.add_argument("--snippet-max-lines-per-file", type=int, default=90, help="max snippet lines per related file")
    parser.add_argument("--max-variables", type=int, default=8, help="max printed variable names per change")
    parser.add_argument("--include-raw", action="store_true", help="print raw model text to console for debugging")
    parser.add_argument("--dry-run", action="store_true", help="print prompts and exit")
    args = parser.parse_args()

    try:
        repo_root = Path(args.repo_root).resolve(strict=False)
        if not repo_root.exists():
            raise ValueError(f"repo root not found: {repo_root}")

        candidates = load_candidate_files(args.files, args.files_from)
        if not candidates:
            raise ValueError("candidate files are empty, provide --files or --files-from")
        top_k = max(1, args.top_k)

        if args.dry_run:
            sample_target: Any
            if args.changes_file:
                changes = parse_changes(args.changes_file, args.changes_key)
                sample_target = changes[0] if changes else {}
            else:
                sample_target = load_json_data(args.json_file, args.json_text)
            print("===== SYSTEM PROMPT =====")
            print(SYSTEM_PROMPT)
            print("\n===== USER PROMPT =====")
            print(build_user_prompt(candidates, sample_target, top_k))
            sample_related_files = [normalize_path(p, repo_root) for p in candidates[:top_k]]
            sample_primary_variable = _extract_primary_variable(sample_target)
            sample_focus_terms = _extract_focus_terms(sample_target, sample_primary_variable)
            sample_anchor_tokens = _build_anchor_tokens(sample_focus_terms)
            sample_keywords = _extract_change_keywords(sample_target, focus_terms=sample_focus_terms)
            sample_snippets = []
            for fp in sample_related_files:
                s = _build_snippet_from_file(
                    file_path=fp,
                    keywords=sample_keywords,
                    context_lines=max(0, args.snippet_context_lines),
                    max_lines_per_file=max(20, args.snippet_max_lines_per_file),
                    max_file_bytes=max(20_000, args.snippet_max_file_bytes),
                )
                if s:
                    sample_snippets.append(s)
            sample_ids = _extract_identifier_candidates(sample_snippets, anchor_tokens=sample_anchor_tokens)
            print("\n===== VARIABLE SYSTEM PROMPT =====")
            print(VARIABLE_SYSTEM_PROMPT)
            print("\n===== VARIABLE USER PROMPT =====")
            print(
                build_variable_user_prompt(
                    change_obj=sample_target,
                    primary_variable=sample_primary_variable,
                    focus_terms=sample_focus_terms,
                    related_files=sample_related_files,
                    snippets=sample_snippets,
                    identifier_candidates=sample_ids,
                    max_variables=max(1, args.max_variables),
                )
            )
            return 0

        if not args.api_key:
            raise ValueError("missing API key, provide --api-key or OPENAI_API_KEY")

        if args.changes_file:
            print(f"[{now_ts()}] batch mode start")
            all_changes = parse_changes(args.changes_file, args.changes_key)
            total = len(all_changes)
            start = max(0, args.start_index)
            end = total if args.max_items <= 0 else min(total, start + args.max_items)
            if start >= total:
                raise ValueError(f"start-index {start} is out of range, total={total}")

            for i in range(start, end):
                change_obj = all_changes[i]
                print(f"[{now_ts()}] processing change {i + 1}/{total}")
                result, raw_related = run_single_mode(
                    candidates=candidates,
                    target_json_obj=change_obj,
                    api_key=args.api_key,
                    base_url=args.base_url,
                    model=args.model,
                    top_k=top_k,
                    temperature=args.temperature,
                    timeout_sec=args.timeout_sec,
                )
                variables, raw_variables = run_variable_mode(
                    change_obj=change_obj,
                    related_result=result,
                    repo_root=repo_root,
                    api_key=args.api_key,
                    base_url=args.base_url,
                    model=args.model,
                    temperature=args.temperature,
                    timeout_sec=args.timeout_sec,
                    max_file_bytes=args.snippet_max_file_bytes,
                    context_lines=args.snippet_context_lines,
                    max_lines_per_file=args.snippet_max_lines_per_file,
                    max_variables=args.max_variables,
                )
                var_text = ", ".join(variables) if variables else "(none)"
                print(f"change[{i}] => {var_text}")
                if args.include_raw:
                    print("----- raw_related_files_model_output -----")
                    print(raw_related)
                    print("----- raw_variable_extraction_model_output -----")
                    print(raw_variables)
            print(f"[{now_ts()}] done, processed={end - start}")
        else:
            print(f"[{now_ts()}] single mode start")
            target_json_obj = load_json_data(args.json_file, args.json_text)
            result, raw_related = run_single_mode(
                candidates=candidates,
                target_json_obj=target_json_obj,
                api_key=args.api_key,
                base_url=args.base_url,
                model=args.model,
                top_k=top_k,
                temperature=args.temperature,
                timeout_sec=args.timeout_sec,
            )
            variables, raw_variables = run_variable_mode(
                change_obj=target_json_obj,
                related_result=result,
                repo_root=repo_root,
                api_key=args.api_key,
                base_url=args.base_url,
                model=args.model,
                temperature=args.temperature,
                timeout_sec=args.timeout_sec,
                max_file_bytes=args.snippet_max_file_bytes,
                context_lines=args.snippet_context_lines,
                max_lines_per_file=args.snippet_max_lines_per_file,
                max_variables=args.max_variables,
            )
            for name in variables:
                print(name)
            if not variables:
                print("(none)")
            if args.include_raw:
                print("----- raw_related_files_model_output -----")
                print(raw_related)
                print("----- raw_variable_extraction_model_output -----")
                print(raw_variables)
            print(f"[{now_ts()}] done")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
