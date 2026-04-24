#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import keyword
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib import error, request


HEADER_PATTERNS = [
    re.compile(r"^RFC\s+8446\b.*August 2018$"),
    re.compile(r"^Rescorla\s+Standards Track\s+\[Page \d+\]$"),
    re.compile(r"^\[Page \d+\]$"),
]

SECTION_PATTERN = re.compile(r"^\d+(?:\.\d+)*\.\s+.+$")
TOKEN_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")
QUOTED_PATTERN = re.compile(r'"([^"]{2,80})"')

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
    "must",
    "should",
    "may",
    "all",
    "any",
    "none",
    "then",
    "else",
    "true",
    "false",
    "null",
    "not",
    "set",
    "value",
    "values",
    "change",
    "changes",
    "field",
    "fields",
}


LLM_SYSTEM_PROMPT = """
You are a standards-context extraction assistant.
Given one TLS change record and candidate context windows from RFC 8446, select the most complete and relevant context.

Rules:
1. You can only use provided candidate windows.
2. Prefer complete normative context (conditions + required actions + nearby definitions).
3. Output strict JSON only.
""".strip()


LLM_USER_PROMPT_TEMPLATE = """
Change record:
{change_json}

Candidate windows:
{candidate_windows_json}

Return strict JSON:
{{
  "selected_window_ids": ["w1", "w2"],
  "merged_context": "full context text",
  "reason": "short reason"
}}
""".strip()


@dataclass
class Paragraph:
    pid: int
    start_line: int
    end_line: int
    section: str
    text: str


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


def read_and_clean_document(path: str) -> tuple[list[tuple[int, str]], list[str]]:
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    raw = raw.replace("\r\n", "\n").replace("\r", "\n").replace("\f", "\n")
    lines = raw.split("\n")

    kept: list[tuple[int, str]] = []
    removed: list[str] = []
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if any(p.match(stripped) for p in HEADER_PATTERNS):
            removed.append(stripped)
            continue
        if stripped and re.fullmatch(r"[-_=]{6,}", stripped):
            removed.append(stripped)
            continue
        kept.append((i, line.rstrip()))
    return kept, removed


def build_paragraphs(cleaned_lines: list[tuple[int, str]]) -> list[Paragraph]:
    paragraphs: list[Paragraph] = []
    cur_lines: list[tuple[int, str]] = []
    current_section = ""
    pid = 0

    def flush() -> None:
        nonlocal pid, cur_lines
        if not cur_lines:
            return
        text = "\n".join(line for _, line in cur_lines).strip()
        if text:
            pid += 1
            paragraphs.append(
                Paragraph(
                    pid=pid,
                    start_line=cur_lines[0][0],
                    end_line=cur_lines[-1][0],
                    section=current_section,
                    text=text,
                )
            )
        cur_lines = []

    for line_no, line in cleaned_lines:
        stripped = line.strip()
        if stripped and SECTION_PATTERN.match(stripped):
            current_section = stripped

        if stripped == "":
            flush()
            continue
        cur_lines.append((line_no, line))

    flush()
    return paragraphs


def tokenize(text: str) -> list[str]:
    out = []
    for t in TOKEN_PATTERN.findall(text):
        low = t.lower()
        if low in STOP_WORDS:
            continue
        if keyword.iskeyword(low):
            continue
        out.append(low)
    return out


def normalize_phrase(phrase: str) -> str:
    phrase = phrase.strip().lower()
    phrase = re.sub(r"\s+", " ", phrase)
    return phrase


def build_change_query(change: dict[str, Any]) -> dict[str, Any]:
    variable_name = str(change.get("variable_name", "")).strip()
    change_action = str(change.get("change_action", "")).strip()
    new_value = str(change.get("new_value", "")).strip()
    condition = str(change.get("change_condition", "")).strip()
    state_step = str(change.get("related_state_or_step", "")).strip()
    evidence = str(change.get("evidence", "")).strip()

    phrases: list[tuple[str, float]] = []
    tokens_score: dict[str, float] = {}

    def add_phrase(v: str, w: float) -> None:
        v = normalize_phrase(v)
        if not v:
            return
        if len(v) > 160:
            return
        phrases.append((v, w))

    def add_tokens(v: str, w: float) -> None:
        for tok in tokenize(v):
            tokens_score[tok] = max(tokens_score.get(tok, 0.0), w)

    add_phrase(variable_name, 8.0)
    add_phrase(variable_name.replace("_", " "), 6.0)
    add_phrase(change_action, 3.0)
    add_phrase(new_value, 4.0)
    add_phrase(state_step, 2.0)

    # quoted terms in condition/evidence are often key protocol terms
    for match in QUOTED_PATTERN.findall(condition + " " + evidence):
        add_phrase(match, 3.5)

    # try a short evidence anchor
    evidence_tokens = tokenize(evidence)
    if evidence_tokens:
        anchor = " ".join(evidence_tokens[: min(12, len(evidence_tokens))])
        add_phrase(anchor, 2.5)

    add_tokens(variable_name, 6.0)
    add_tokens(change_action, 2.0)
    add_tokens(new_value, 3.0)
    add_tokens(condition, 1.5)
    add_tokens(state_step, 1.2)
    add_tokens(evidence, 1.0)

    ranked_tokens = sorted(tokens_score.items(), key=lambda kv: (-kv[1], kv[0]))
    final_tokens = [tok for tok, _ in ranked_tokens[:30]]
    return {"phrases": phrases, "tokens": final_tokens, "token_score": tokens_score}


def build_phrase_regex(phrase: str) -> re.Pattern[str]:
    parts = [re.escape(p) for p in phrase.split(" ") if p]
    if not parts:
        return re.compile(r"$^")
    # allow underscore/hyphen/space variations
    joined = r"[\s_\-]+".join(parts)
    return re.compile(rf"\b{joined}\b", re.IGNORECASE)


def score_paragraph(paragraph: Paragraph, query: dict[str, Any]) -> tuple[float, list[str]]:
    text = paragraph.text
    text_low = text.lower()
    score = 0.0
    reasons: list[str] = []

    # phrase hit score
    for phrase, weight in query["phrases"]:
        pat = build_phrase_regex(phrase)
        m = pat.search(text)
        if m:
            score += weight
            reasons.append(f'phrase "{phrase}"')

    # token overlap score
    token_hits = 0
    token_score_map: dict[str, float] = query["token_score"]
    paragraph_tokens = set(tokenize(text))
    for tok in query["tokens"]:
        if tok in paragraph_tokens:
            token_hits += 1
            score += token_score_map.get(tok, 0.5) * 0.35

    if token_hits > 0:
        reasons.append(f"token_hits={token_hits}")

    # normative language bonus
    norm_hits = len(re.findall(r"\b(MUST|MUST NOT|SHOULD|MAY)\b", text))
    if norm_hits:
        score += min(2.0, norm_hits * 0.3)
        reasons.append("normative_language")

    # structural context bonus
    if any(k in text_low for k in ["struct {", "enum {", "select ("]):
        score += 0.8
        reasons.append("structure_definition")

    return score, reasons


def merge_windows(windows: list[tuple[int, int, float]]) -> list[tuple[int, int, float]]:
    if not windows:
        return []
    windows = sorted(windows, key=lambda x: (x[0], x[1]))
    merged = [windows[0]]
    for start, end, score in windows[1:]:
        last_s, last_e, last_score = merged[-1]
        if start <= last_e + 1:
            merged[-1] = (last_s, max(last_e, end), max(last_score, score))
        else:
            merged.append((start, end, score))
    return merged


def build_context_windows(
    paragraphs: list[Paragraph],
    scored: list[tuple[int, float, list[str]]],
    radius: int,
    max_windows: int,
    min_score: float,
    max_paragraphs_per_window: int,
) -> list[dict[str, Any]]:
    pid_to_idx = {p.pid: idx for idx, p in enumerate(paragraphs)}
    candidate: list[tuple[int, int, float, int]] = []

    for pid, score, _ in scored:
        if score < min_score:
            continue
        idx = pid_to_idx[pid]
        start = max(0, idx - radius)
        end = min(len(paragraphs) - 1, idx + radius)
        candidate.append((start, end, score, idx))

    # Pick by score first, avoid chained mega-merge.
    selected_ranges: list[tuple[int, int, float]] = []
    for start, end, score, center in sorted(candidate, key=lambda x: (-x[2], x[0]))[: max_windows * 6]:
        # Clamp range length to keep contexts callable and compact.
        max_len = max(1, max_paragraphs_per_window)
        cur_len = end - start + 1
        if cur_len > max_len:
            half = max_len // 2
            start = max(0, center - half)
            end = min(len(paragraphs) - 1, start + max_len - 1)
            if end - start + 1 < max_len:
                start = max(0, end - max_len + 1)

        # Skip if heavily overlapping already selected range.
        keep = True
        for s2, e2, _ in selected_ranges:
            overlap = max(0, min(end, e2) - max(start, s2) + 1)
            if overlap >= min(end - start + 1, e2 - s2 + 1):
                keep = False
                break
        if not keep:
            continue

        selected_ranges.append((start, end, score))
        if len(selected_ranges) >= max_windows:
            break

    selected_ranges = sorted(selected_ranges, key=lambda x: x[0])

    windows: list[dict[str, Any]] = []
    for i, (start_idx, end_idx, score) in enumerate(selected_ranges, start=1):
        chunk = paragraphs[start_idx : end_idx + 1]
        text = "\n\n".join(p.text for p in chunk).strip()
        section = chunk[0].section or ""
        windows.append(
            {
                "window_id": f"w{i}",
                "paragraph_ids": [p.pid for p in chunk],
                "start_line": chunk[0].start_line,
                "end_line": chunk[-1].end_line,
                "section": section,
                "score": round(score, 3),
                "text": text,
            }
        )
    return windows


def default_select_windows(windows: list[dict[str, Any]], max_select: int = 2) -> tuple[list[str], str, str]:
    if not windows:
        return [], "", "no windows matched"
    picked = windows[:max_select]
    ids = [w["window_id"] for w in picked]
    merged_context = "\n\n".join(w["text"] for w in picked).strip()
    return ids, merged_context, "selected by regex score"


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
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        raise ValueError("cannot parse JSON object from LLM output")
    obj = json.loads(m.group(0))
    if not isinstance(obj, dict):
        raise ValueError("LLM output is not JSON object")
    return obj


def llm_refine_context(
    change: dict[str, Any],
    windows: list[dict[str, Any]],
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    timeout_sec: int,
) -> tuple[list[str], str, str, str]:
    prompt = LLM_USER_PROMPT_TEMPLATE.format(
        change_json=json.dumps(change, ensure_ascii=False, indent=2),
        candidate_windows_json=json.dumps(windows, ensure_ascii=False, indent=2),
    )
    raw = call_chat_completions(
        api_key=api_key,
        base_url=base_url,
        model=model,
        system_prompt=LLM_SYSTEM_PROMPT,
        user_prompt=prompt,
        temperature=temperature,
        timeout_sec=timeout_sec,
    )
    obj = extract_json_object(raw)
    ids = obj.get("selected_window_ids", [])
    merged_context = str(obj.get("merged_context", "")).strip()
    reason = str(obj.get("reason", "")).strip()
    if not isinstance(ids, list):
        ids = []
    ids = [str(x).strip() for x in ids if str(x).strip()]
    return ids, merged_context, reason, raw


def context_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()


def register_context(
    store: dict[str, dict[str, Any]],
    hash_to_id: dict[str, str],
    context_text: str,
    meta: dict[str, Any],
) -> str:
    h = context_hash(context_text)
    if h in hash_to_id:
        return hash_to_id[h]
    cid = f"ctx_{len(store) + 1:06d}"
    hash_to_id[h] = cid
    store[cid] = {
        "context_id": cid,
        "text": context_text,
        **meta,
    }
    return cid


def extract_change_contexts(
    changes: list[dict[str, Any]],
    paragraphs: list[Paragraph],
    max_windows: int = 4,
    radius: int = 1,
    min_score: float = 1.0,
    max_paragraphs_per_window: int = 10,
    use_llm: bool = False,
    api_key: str = "",
    base_url: str = "",
    model: str = "",
    temperature: float = 0.0,
    timeout_sec: int = 120,
    llm_max_items: int = 0,
) -> dict[str, Any]:
    context_store: dict[str, dict[str, Any]] = {}
    hash_to_id: dict[str, str] = {}
    results: list[dict[str, Any]] = []

    for i, change in enumerate(changes):
        query = build_change_query(change)
        scored: list[tuple[int, float, list[str]]] = []
        for p in paragraphs:
            score, reasons = score_paragraph(p, query)
            if score > 0:
                scored.append((p.pid, score, reasons))

        scored.sort(key=lambda x: (-x[1], x[0]))
        windows = build_context_windows(
            paragraphs=paragraphs,
            scored=scored,
            radius=radius,
            max_windows=max_windows,
            min_score=min_score,
            max_paragraphs_per_window=max_paragraphs_per_window,
        )

        llm_used = False
        llm_raw = ""
        if use_llm and windows:
            if llm_max_items > 0 and i >= llm_max_items:
                selected_ids, merged_text, select_reason = default_select_windows(windows)
            else:
                try:
                    selected_ids, merged_text, select_reason, llm_raw = llm_refine_context(
                        change=change,
                        windows=windows,
                        api_key=api_key,
                        base_url=base_url,
                        model=model,
                        temperature=temperature,
                        timeout_sec=timeout_sec,
                    )
                    llm_used = True
                    if not merged_text:
                        selected_ids, merged_text, select_reason = default_select_windows(windows)
                except Exception as e:  # noqa: BLE001
                    selected_ids, merged_text, select_reason = default_select_windows(windows)
                    select_reason = f"fallback_to_regex: {e}"
        else:
            selected_ids, merged_text, select_reason = default_select_windows(windows)

        selected_window_objs = [w for w in windows if w["window_id"] in set(selected_ids)]
        if not selected_window_objs and windows:
            selected_window_objs = [windows[0]]

        context_id = ""
        if merged_text:
            meta = {
                "selected_window_ids": [w["window_id"] for w in selected_window_objs],
                "windows": selected_window_objs,
                "selection_reason": select_reason,
                "llm_used": llm_used,
            }
            context_id = register_context(context_store, hash_to_id, merged_text, meta)

        top_matches = []
        for pid, score, reasons in scored[:8]:
            p = paragraphs[pid - 1]
            top_matches.append(
                {
                    "paragraph_id": pid,
                    "score": round(score, 3),
                    "start_line": p.start_line,
                    "end_line": p.end_line,
                    "section": p.section,
                    "reasons": reasons[:5],
                    "preview": p.text[:260],
                }
            )

        result_item = {
            "index": i,
            "change": change,
            "keywords": query["tokens"][:15],
            "top_matches": top_matches,
            "candidate_windows": [
                {
                    "window_id": w["window_id"],
                    "paragraph_ids": w["paragraph_ids"],
                    "start_line": w["start_line"],
                    "end_line": w["end_line"],
                    "section": w["section"],
                    "score": w["score"],
                }
                for w in windows
            ],
            "selected_window_ids": [w["window_id"] for w in selected_window_objs],
            "context_id": context_id,
            "selection_reason": select_reason,
        }
        if llm_raw:
            result_item["llm_raw_output"] = llm_raw
        results.append(result_item)

    return {"context_store": context_store, "results": results}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract complete RFC 8446 contexts for each change record using regex prefilter + optional LLM refine."
    )
    parser.add_argument(
        "--changes-file",
        default=r"d:\project\conditionFuzzingPaper\output\02_variable_changes.json",
        help="JSON containing a `changes` list or plain list",
    )
    parser.add_argument("--changes-key", default="changes")
    parser.add_argument(
        "--doc-file",
        default=r"d:\project\conditionFuzzingPaper\document\TLS1.3.txt",
        help="TLS1.3 source text",
    )
    parser.add_argument("--output", default=r"d:\project\conditionFuzzingPaper\output\06_change_contexts.json")
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--max-items", type=int, default=0, help="0 means all")
    parser.add_argument("--radius", type=int, default=1, help="paragraph expansion radius")
    parser.add_argument("--max-windows", type=int, default=4)
    parser.add_argument("--max-paragraphs-per-window", type=int, default=10)
    parser.add_argument("--min-score", type=float, default=1.0)

    parser.add_argument("--use-llm", action="store_true", help="use LLM to refine from candidate windows")
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--base-url", default="https://api.zhizengzeng.com/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--llm-max-items", type=int, default=0, help="limit LLM refine count, 0 means no limit")

    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        print(f"[{now_ts()}] loading document")
        cleaned_lines, _removed = read_and_clean_document(args.doc_file)
        paragraphs = build_paragraphs(cleaned_lines)
        if not paragraphs:
            raise ValueError("no paragraphs parsed from document")

        print(f"[{now_ts()}] loading changes")
        changes_obj = json.loads(Path(args.changes_file).read_text(encoding="utf-8"))
        if isinstance(changes_obj, dict):
            raw_changes = changes_obj.get(args.changes_key, [])
            if not isinstance(raw_changes, list):
                raise ValueError(f"{args.changes_file} key `{args.changes_key}` is not a list")
        elif isinstance(changes_obj, list):
            raw_changes = changes_obj
        else:
            raise ValueError(f"unsupported changes JSON type: {type(changes_obj).__name__}")

        all_changes: list[dict[str, Any]] = []
        for item in raw_changes:
            if isinstance(item, dict):
                all_changes.append(item)
            else:
                all_changes.append({"_raw": item})

        start = max(0, args.start_index)
        end = len(all_changes) if args.max_items <= 0 else min(len(all_changes), start + args.max_items)
        if start >= len(all_changes):
            raise ValueError(f"start-index {start} out of range, total={len(all_changes)}")
        selected_changes = all_changes[start:end]

        if args.use_llm and not args.api_key:
            raise ValueError("missing API key for --use-llm")

        if args.dry_run:
            print(f"paragraphs={len(paragraphs)}, changes_total={len(all_changes)}, run_range=[{start}, {end})")
            preview = build_change_query(selected_changes[0]) if selected_changes else {"tokens": [], "phrases": []}
            print(f"preview_tokens={preview['tokens'][:10]}")
            return 0

        print(f"[{now_ts()}] extracting contexts for {len(selected_changes)} changes")
        extracted = extract_change_contexts(
            changes=selected_changes,
            paragraphs=paragraphs,
            max_windows=max(1, args.max_windows),
            radius=max(0, args.radius),
            min_score=max(0.0, args.min_score),
            max_paragraphs_per_window=max(1, args.max_paragraphs_per_window),
            use_llm=args.use_llm,
            api_key=args.api_key,
            base_url=args.base_url,
            model=args.model,
            temperature=args.temperature,
            timeout_sec=args.timeout_sec,
            llm_max_items=max(0, args.llm_max_items),
        )

        out = {
            "meta": {
                "generated_at": now_ts(),
                "doc_file": str(Path(args.doc_file).resolve(strict=False)),
                "changes_file": str(Path(args.changes_file).resolve(strict=False)),
                "changes_key": args.changes_key,
                "changes_total": len(all_changes),
                "start_index": start,
                "end_index_exclusive": end,
                "processed_count": len(selected_changes),
                "paragraph_count": len(paragraphs),
                "radius": args.radius,
                "max_windows": args.max_windows,
                "max_paragraphs_per_window": args.max_paragraphs_per_window,
                "min_score": args.min_score,
                "use_llm": args.use_llm,
                "model": args.model if args.use_llm else "",
            },
            "context_store": extracted["context_store"],
            "items": extracted["results"],
        }

        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[{now_ts()}] done -> {out_path}")
        print(f"context_count={len(out['context_store'])}, item_count={len(out['items'])}")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
