#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib import error, request


RESULT_SATISFIED = "满足"
RESULT_NOT_SATISFIED = "不满足"
RESULT_INSUFFICIENT = "证据不足"

ALLOWED_RESULTS = {RESULT_SATISFIED, RESULT_NOT_SATISFIED, RESULT_INSUFFICIENT}

SYSTEM_PROMPT = f"""
You are a code-evidence judgment assistant.
Given a description and code snippets, decide whether the snippets satisfy the description.

Rules:
1. Only use provided snippets as evidence.
2. You must output exactly one result: "{RESULT_SATISFIED}", "{RESULT_NOT_SATISFIED}", or "{RESULT_INSUFFICIENT}".
3. If direct support exists, prefer "{RESULT_SATISFIED}".
4. If direct contradiction exists, prefer "{RESULT_NOT_SATISFIED}".
5. If evidence is missing/ambiguous/conflicting, use "{RESULT_INSUFFICIENT}".

Output strict JSON only:
{{
  "result": "{RESULT_SATISFIED}|{RESULT_NOT_SATISFIED}|{RESULT_INSUFFICIENT}",
  "reason": "1-3 concise sentences",
  "confidence": 0.0,
  "desc": "original input description",
  "next_search_suggestions": {{
    "functions_or_methods": ["..."],
    "variables_or_fields": ["..."],
    "focus_for_next_search": "..."
  }}
}}

Important:
- If result is "{RESULT_INSUFFICIENT}", you MUST provide non-empty next_search_suggestions.
- If result is not "{RESULT_INSUFFICIENT}", keep suggestion fields empty.
- next_search_suggestions must avoid generic names like ret/tmp/data/key/len/extension.
- Prefer suggestions that appear in provided snippets and are tightly tied to the description.
""".strip()

USER_PROMPT_TEMPLATE = """
Description:
{desc}

Code snippet evidence:
{snippets_json}

Return strict JSON only.
""".strip()

FOLLOWUP_GENERIC_NAMES = {
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
    "data",
    "value",
    "values",
    "type",
    "name",
    "label",
    "key",
    "len",
    "length",
    "extension",
    "extensions",
    "file",
    "line",
}

DESC_STOP_WORDS = {
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
    "there",
    "which",
    "whose",
    "have",
    "has",
    "had",
    "will",
    "would",
    "could",
    "should",
    "may",
    "might",
    "must",
    "can",
    "cannot",
    "support",
    "supports",
    "supporting",
    "form",
    "attack",
    "cases",
    "case",
    "valid",
    "invalid",
    "solely",
}

NOISY_SNIPPET_PATH_PARTS = {
    "/.github/",
    "\\.github\\",
    "/certs/",
    "\\certs\\",
    "/linuxkm/",
    "\\linuxkm\\",
    "/utils/",
    "\\utils\\",
}


def _split_identifier_tokens(name: str) -> list[str]:
    parts = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+", name)
    if not parts:
        parts = re.split(r"[^A-Za-z0-9_]+", name)
    return [p.lower() for p in parts if p]


def _desc_tokens(desc: str) -> set[str]:
    out: set[str] = set()
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", desc):
        low = tok.lower()
        if low in DESC_STOP_WORDS:
            continue
        out.add(low)
    return out


def _is_generic_followup_name(name: str) -> bool:
    low = name.lower().strip()
    if not low:
        return True
    if low in FOLLOWUP_GENERIC_NAMES:
        return True
    if len(low) <= 2:
        return True
    return False


def normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


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


def parse_snippets_from_test_txt(text: str) -> list[dict[str, str]]:
    pat = re.compile(
        r"===== Snippet\s+(\d+)\s+=====\s*"
        r"(?:Path:\s*(.*?)\s*)?"
        r"\n(.*?)\n-+\s*",
        flags=re.S,
    )
    out: list[dict[str, str]] = []
    for m in pat.finditer(text):
        sid = m.group(1).strip()
        path = (m.group(2) or "").strip()
        snippet = (m.group(3) or "").strip()
        if snippet:
            out.append({"id": f"s{int(sid):03d}", "path": path, "snippet": snippet})

    if out:
        return out

    raw = text.strip()
    if not raw:
        return []
    return [{"id": "s001", "path": "", "snippet": raw}]


def compact_snippets(
    snippets: list[dict[str, str]],
    max_snippets: int,
    max_chars_per_snippet: int,
    max_total_chars: int,
) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    total = 0
    for item in snippets[: max(1, max_snippets)]:
        content = item["snippet"]
        if len(content) > max_chars_per_snippet:
            content = content[:max_chars_per_snippet] + "\n... [truncated]"
        if total + len(content) > max_total_chars:
            break
        out.append({"id": item["id"], "path": item.get("path", ""), "snippet": content})
        total += len(content)
    return out


def _score_snippet_relevance(item: dict[str, str], desc_tokens: set[str], priority_names: list[str]) -> float:
    snippet = str(item.get("snippet", "")).lower()
    path = str(item.get("path", "")).lower()
    score = 0.0

    for tok in desc_tokens:
        if tok in snippet:
            score += 0.55
        if tok in path:
            score += 0.3

    for name in priority_names[:16]:
        low = name.lower()
        if not low:
            continue
        if re.search(rf"\b{re.escape(low)}\b", snippet):
            score += 1.0
        elif low in snippet:
            score += 0.5
        if low in path:
            score += 0.4

    if any(part in path for part in NOISY_SNIPPET_PATH_PARTS):
        score -= 2.0
    if "/src/" in path or "\\src\\" in path:
        score += 0.5
    if path.endswith("tls13.c") or path.endswith("tls.c") or path.endswith("internal.h"):
        score += 0.8
    if "psk" in snippet and "binder" in snippet:
        score += 1.6
    if "identity" in snippet and "binder" in snippet:
        score += 1.3
    if "invalid" in snippet and "binder" in snippet:
        score += 0.8
    return score


def _select_snippets_for_judgment(
    snippets: list[dict[str, str]],
    *,
    desc: str,
    priority_names: list[str],
    max_snippets: int,
    max_chars_per_snippet: int,
    max_total_chars: int,
) -> list[dict[str, str]]:
    if not snippets:
        return []
    desc_tokens = _desc_tokens(desc)
    ranked = sorted(
        snippets,
        key=lambda x: (
            -_score_snippet_relevance(x, desc_tokens=desc_tokens, priority_names=priority_names),
            len(str(x.get("snippet", ""))),
        ),
    )
    return compact_snippets(
        ranked,
        max_snippets=max_snippets,
        max_chars_per_snippet=max_chars_per_snippet,
        max_total_chars=max_total_chars,
    )


def _clean_identifier_list(values: Any, limit: int = 12) -> list[str]:
    if isinstance(values, str):
        values = re.split(r"[,;\n]+", values)
    if not isinstance(values, list):
        return []

    out: list[str] = []
    seen: set[str] = set()
    valid_pat = re.compile(r"^[A-Za-z_][A-Za-z0-9_:\.\->]*$")
    for x in values:
        v = str(x).strip().strip("\"'`")
        if not v or len(v) > 80:
            continue
        if not valid_pat.fullmatch(v):
            continue
        if _is_generic_followup_name(v):
            continue
        key = v.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
        if len(out) >= limit:
            break
    return out


def _fallback_suggestions(desc: str, snippets: list[dict[str, str]]) -> dict[str, Any]:
    call_exclude = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "case",
        "else",
        "do",
        "goto",
    }
    function_score: dict[str, int] = {}
    variable_score: dict[str, int] = {}

    for item in snippets:
        text = item.get("snippet", "")
        for fn in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
            low = fn.lower()
            if low in call_exclude:
                continue
            if _is_generic_followup_name(fn):
                continue
            function_score[fn] = function_score.get(fn, 0) + 1

        for v in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", text):
            low = v.lower()
            if low in call_exclude:
                continue
            if v in function_score:
                continue
            if len(v) <= 2:
                continue
            if _is_generic_followup_name(v):
                continue
            variable_score[v] = variable_score.get(v, 0) + 1

    functions = [k for k, _ in sorted(function_score.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:8]]
    variables = [k for k, _ in sorted(variable_score.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:8]]

    desc_tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", desc)
    if desc_tokens:
        focus_hint = "优先围绕这些关键词定位判断分支与返回路径: " + ", ".join(desc_tokens[:8]) + "。"
    else:
        focus_hint = "优先定位与描述相关的条件分支、错误返回码和调用链上下文，并补充缺失函数实现片段。"

    return {
        "functions_or_methods": functions,
        "variables_or_fields": variables,
        "focus_for_next_search": focus_hint,
    }


def sanitize_result(raw_obj: dict[str, Any], desc: str, snippets: list[dict[str, str]]) -> dict[str, Any]:
    result = str(raw_obj.get("result", "")).strip()
    if result not in ALLOWED_RESULTS:
        result = RESULT_INSUFFICIENT

    reason = str(raw_obj.get("reason", "")).strip()
    if not reason:
        reason = "模型未提供可用原因。"

    try:
        confidence = float(raw_obj.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    raw_suggest = raw_obj.get("next_search_suggestions", {})
    if not isinstance(raw_suggest, dict):
        raw_suggest = {}

    functions = _clean_identifier_list(
        raw_suggest.get("functions_or_methods", raw_suggest.get("function_names", [])),
        limit=12,
    )
    variables = _clean_identifier_list(
        raw_suggest.get("variables_or_fields", raw_suggest.get("variable_names", [])),
        limit=12,
    )
    focus = str(
        raw_suggest.get(
            "focus_for_next_search",
            raw_suggest.get("search_focus", raw_suggest.get("recommended_search_description", "")),
        )
    ).strip()

    if result != RESULT_INSUFFICIENT:
        suggestions = {
            "functions_or_methods": [],
            "variables_or_fields": [],
            "focus_for_next_search": "",
        }
    else:
        if not functions and not variables and not focus:
            suggestions = _fallback_suggestions(desc, snippets)
        else:
            if not focus:
                focus = "继续补充调用链上下文、关键条件分支、以及与描述关键词直接相关的判断/返回代码。"
            suggestions = {
                "functions_or_methods": functions,
                "variables_or_fields": variables,
                "focus_for_next_search": focus,
            }

    return {
        "result": result,
        "reason": reason,
        "confidence": round(confidence, 3),
        "desc": desc,
        "next_search_suggestions": suggestions,
    }


def _build_user_prompt(desc: str, snippets: list[dict[str, str]]) -> str:
    return USER_PROMPT_TEMPLATE.format(
        desc=desc,
        snippets_json=json.dumps(snippets, ensure_ascii=False, indent=2),
    )


def _judge_once(
    *,
    desc: str,
    snippets: list[dict[str, str]],
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    timeout_sec: int,
) -> dict[str, Any]:
    raw = call_chat_completions(
        api_key=api_key,
        base_url=base_url,
        model=model,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=_build_user_prompt(desc, snippets),
        temperature=temperature,
        timeout_sec=timeout_sec,
    )
    parsed_obj = extract_json_object(raw)
    return sanitize_result(parsed_obj, desc=desc, snippets=snippets)


def _merge_dedup_snippets(primary: list[dict[str, str]], secondary: list[dict[str, str]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in primary + secondary:
        snippet = str(item.get("snippet", "")).strip()
        if not snippet:
            continue
        path = str(item.get("path", "")).strip()
        key = (path, snippet)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "id": str(item.get("id", f"s{len(out) + 1:03d}")),
                "path": path,
                "snippet": snippet,
            }
        )
    return out


def _choose_followup_query(
    suggestions: dict[str, Any],
    *,
    base_desc: str,
    snippets: list[dict[str, str]],
) -> tuple[list[str], str]:
    functions = _clean_identifier_list(suggestions.get("functions_or_methods", []), limit=20)
    variables = _clean_identifier_list(suggestions.get("variables_or_fields", []), limit=20)
    focus = str(suggestions.get("focus_for_next_search", "")).strip()

    if not functions and not variables and not focus:
        fallback = _fallback_suggestions(base_desc, snippets)
        functions = _clean_identifier_list(fallback.get("functions_or_methods", []), limit=20)
        variables = _clean_identifier_list(fallback.get("variables_or_fields", []), limit=20)
        focus = str(fallback.get("focus_for_next_search", "")).strip()

    desc_tokens = _desc_tokens(base_desc)
    snippet_text = "\n".join(str(s.get("snippet", "")) for s in snippets).lower()
    merged_raw: list[str] = []
    seen: set[str] = set()
    for name in variables + functions:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        merged_raw.append(name)

    scored: list[tuple[float, str]] = []
    for name in merged_raw:
        low = name.lower()
        tokens = set(_split_identifier_tokens(name))
        score = 0.0
        if tokens & desc_tokens:
            score += 4.0 + 0.8 * len(tokens & desc_tokens)
        if re.search(rf"\b{re.escape(low)}\b", snippet_text):
            score += 3.5
        elif low in snippet_text:
            score += 2.0
        if re.search(r"(?:->|::|\.)", name):
            score += 0.8
        if len(tokens) >= 2:
            score += 0.6
        if _is_generic_followup_name(name):
            score -= 4.0
        scored.append((score, name))

    scored.sort(key=lambda x: (-x[0], x[1].lower()))
    merged = [name for score, name in scored if score > 0.1][:12]
    if not merged:
        merged = [name for _, name in scored if not _is_generic_followup_name(name)][:8]

    if not focus:
        focus = base_desc

    return merged, focus


def _run_variable_context_pipeline(
    *,
    script_path: Path,
    repo_root: Path,
    output_path: Path,
    var_names: list[str],
    desc: str,
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    timeout_sec: int,
    use_llm: bool,
) -> dict[str, Any]:
    if not var_names:
        raise ValueError("follow-up search has empty var names")

    cmd = [
        sys.executable,
        str(script_path),
        "--repo-root",
        str(repo_root),
        "--var-name",
        ",".join(var_names),
        "--desc",
        desc,
        "--output",
        str(output_path),
        "--timeout-sec",
        str(max(10, timeout_sec)),
        "--base-url",
        base_url,
        "--model",
        model,
        "--temperature",
        str(temperature),
        "--top-candidates",
        "35",
        "--top-semantic",
        "120",
        "--max-text-hits",
        "500",
        "--max-related-calls",
        "0",
    ]
    if use_llm:
        cmd.append("--use-llm")
        cmd.extend(["--api-key", api_key])

    proc = subprocess.run(
        cmd,
        check=False,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-6:]
        raise RuntimeError(
            "variable_context_pipeline failed (exit={}): {}".format(
                proc.returncode,
                " | ".join(tail),
            )
        )
    if not output_path.exists():
        raise RuntimeError(f"variable_context_pipeline output not found: {output_path}")

    raw = output_path.read_text(encoding="utf-8", errors="replace")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("variable_context_pipeline output must be JSON object")

    return {
        "output": parsed,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def _extract_snippets_from_pipeline_output(
    payload: dict[str, Any],
    round_idx: int,
    *,
    query_names: list[str],
) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seq = 1
    query_tokens = {t for name in query_names for t in _split_identifier_tokens(name) if len(t) >= 3}

    result_obj = payload.get("result", {})
    if isinstance(result_obj, dict):
        for item in result_obj.get("relevant_snippets", []) or []:
            if not isinstance(item, dict):
                continue
            snippet = str(item.get("snippet", "")).strip()
            if not snippet:
                continue
            out.append(
                {
                    "id": f"r{round_idx:02d}_s{seq:04d}",
                    "path": str(item.get("file", "")).strip(),
                    "snippet": snippet,
                }
            )
            seq += 1
            if len(out) >= 24:
                return out

    ranked_candidates: list[tuple[float, dict[str, Any]]] = []
    for cand in payload.get("candidate_snippets", []) or []:
        if not isinstance(cand, dict):
            continue
        score = float(cand.get("score_raw", 0.0) or 0.0)
        snippet = str(cand.get("snippet", "")).strip()
        if not snippet:
            continue
        low_snippet = snippet.lower()
        low_path = str(cand.get("file", "")).lower()
        if query_tokens:
            overlap = sum(1 for t in query_tokens if t in low_snippet or t in low_path)
            score += overlap * 1.2
        ranked_candidates.append((score, cand))
    ranked_candidates.sort(key=lambda x: -x[0])

    for _, cand in ranked_candidates:
        snippet = str(cand.get("snippet", "")).strip()
        if not snippet:
            continue
        out.append(
            {
                "id": f"r{round_idx:02d}_s{seq:04d}",
                "path": str(cand.get("file", "")).strip(),
                "snippet": snippet,
            }
        )
        seq += 1
        if len(out) >= 45:
            break

    if out:
        return out

    result_obj = payload.get("result", {})
    if isinstance(result_obj, dict):
        for item in result_obj.get("relevant_snippets", []) or []:
            if not isinstance(item, dict):
                continue
            snippet = str(item.get("snippet", "")).strip()
            if not snippet:
                continue
            out.append(
                {
                    "id": f"r{round_idx:02d}_s{seq:04d}",
                    "path": str(item.get("file", "")).strip(),
                    "snippet": snippet,
                }
            )
            seq += 1
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Judge whether snippets in test.txt satisfy a description with LLM."
    )
    parser.add_argument("--input", default="test.txt", help="input text file containing snippets")
    parser.add_argument("--desc", required=True, help="description text to verify")
    parser.add_argument("--repo-root", default=".", help="repository root for follow-up search")
    parser.add_argument(
        "--variable-context-script",
        default="utils/variable_context_pipeline.py",
        help="path to variable_context_pipeline.py",
    )
    parser.add_argument(
        "--max-followup-rounds",
        type=int,
        default=2,
        help="when result is 证据不足, max extra retrieval+judgment rounds",
    )
    parser.add_argument(
        "--pipeline-output-dir",
        default="output/workflow",
        help="directory to store follow-up variable_context_pipeline outputs",
    )
    parser.add_argument(
        "--pipeline-use-llm",
        action="store_true",
        help="enable --use-llm when invoking variable_context_pipeline.py",
    )
    parser.add_argument(
        "--pipeline-no-llm",
        action="store_true",
        help="deprecated: force disable --use-llm for variable_context_pipeline.py",
    )
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--base-url", default="https://api.bltcy.ai/v1/")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--max-snippets", type=int, default=30)
    parser.add_argument("--max-chars-per-snippet", type=int, default=1600)
    parser.add_argument("--max-total-chars", type=int, default=52000)
    parser.add_argument("--dry-run", action="store_true", help="print prompt payload and exit")
    args = parser.parse_args()

    desc = ""
    try:
        in_path = Path(args.input)
        if not in_path.exists():
            raise ValueError(f"input file not found: {in_path}")

        desc = args.desc.strip()
        if not desc:
            raise ValueError("desc cannot be empty")

        raw_text = in_path.read_text(encoding="utf-8", errors="replace")
        parsed = parse_snippets_from_test_txt(raw_text)
        if not parsed:
            raise ValueError("no snippets found in input file")

        snippets_all = _merge_dedup_snippets(parsed, [])
        snippets_for_preview = _select_snippets_for_judgment(
            snippets=snippets_all,
            desc=desc,
            priority_names=[],
            max_snippets=args.max_snippets,
            max_chars_per_snippet=args.max_chars_per_snippet,
            max_total_chars=args.max_total_chars,
        )
        if not snippets_for_preview:
            raise ValueError("snippets become empty after compacting limits")

        if args.dry_run:
            print("===== SYSTEM PROMPT =====")
            print(SYSTEM_PROMPT)
            print("\n===== USER PROMPT =====")
            print(_build_user_prompt(desc, snippets_for_preview))
            print(f"\n[INFO] snippet_count={len(snippets_for_preview)}")
            return 0

        if not args.api_key:
            raise ValueError("missing API key, provide --api-key or OPENAI_API_KEY")

        repo_root = Path(args.repo_root).resolve(strict=False)
        if not repo_root.exists():
            raise ValueError(f"repo root not found: {repo_root}")

        pipeline_script = Path(args.variable_context_script)
        if not pipeline_script.is_absolute():
            pipeline_script = (Path.cwd() / pipeline_script).resolve(strict=False)
        if args.max_followup_rounds > 0 and not pipeline_script.exists():
            raise ValueError(f"variable context script not found: {pipeline_script}")

        output_dir = Path(args.pipeline_output_dir)
        if not output_dir.is_absolute():
            output_dir = (Path.cwd() / output_dir).resolve(strict=False)
        output_dir.mkdir(parents=True, exist_ok=True)

        trace: list[dict[str, Any]] = []
        final_result: dict[str, Any] | None = None
        final_snippets: list[dict[str, str]] = snippets_for_preview
        active_priority_names: list[str] = []
        max_rounds = 1 + max(0, args.max_followup_rounds)
        pipeline_use_llm = bool(args.pipeline_use_llm) and not args.pipeline_no_llm

        for round_idx in range(1, max_rounds + 1):
            final_snippets = _select_snippets_for_judgment(
                snippets=snippets_all,
                desc=desc,
                priority_names=active_priority_names,
                max_snippets=args.max_snippets,
                max_chars_per_snippet=args.max_chars_per_snippet,
                max_total_chars=args.max_total_chars,
            )
            if not final_snippets:
                raise ValueError("snippets become empty after compacting limits")

            judged = _judge_once(
                desc=desc,
                snippets=final_snippets,
                api_key=args.api_key,
                base_url=args.base_url,
                model=args.model,
                temperature=args.temperature,
                timeout_sec=args.timeout_sec,
            )
            final_result = judged

            round_trace: dict[str, Any] = {
                "round": round_idx,
                "snippets_used": len(final_snippets),
                "result": judged["result"],
                "confidence": judged["confidence"],
                "reason": judged["reason"],
            }

            if judged["result"] != RESULT_INSUFFICIENT:
                round_trace["follow_up_triggered"] = False
                trace.append(round_trace)
                break

            if round_idx > args.max_followup_rounds:
                round_trace["follow_up_triggered"] = False
                round_trace["follow_up_stop_reason"] = "reached max_followup_rounds"
                trace.append(round_trace)
                break

            suggestions = judged.get("next_search_suggestions", {})
            if not isinstance(suggestions, dict):
                suggestions = {}
            follow_var_names, follow_desc = _choose_followup_query(
                suggestions=suggestions,
                base_desc=desc,
                snippets=final_snippets,
            )
            if not follow_var_names:
                round_trace["follow_up_triggered"] = False
                round_trace["follow_up_stop_reason"] = "empty follow-up var names"
                trace.append(round_trace)
                break
            active_priority_names = follow_var_names

            pipeline_output_path = output_dir / f"variable_context_result_followup_round{round_idx}.json"
            round_trace["follow_up_triggered"] = True
            round_trace["follow_up_query"] = {
                "var_name": follow_var_names,
                "desc": follow_desc,
                "pipeline_output": str(pipeline_output_path),
            }

            try:
                pipeline_data = _run_variable_context_pipeline(
                    script_path=pipeline_script,
                    repo_root=repo_root,
                    output_path=pipeline_output_path,
                    var_names=follow_var_names,
                    desc=follow_desc,
                    api_key=args.api_key,
                    base_url=args.base_url,
                    model=args.model,
                    temperature=args.temperature,
                    timeout_sec=args.timeout_sec,
                    use_llm=pipeline_use_llm,
                )
            except Exception as follow_e:  # noqa: BLE001
                round_trace["follow_up_error"] = str(follow_e)
                trace.append(round_trace)
                break
            extra_snippets = _extract_snippets_from_pipeline_output(
                pipeline_data["output"],
                round_idx=round_idx,
                query_names=follow_var_names,
            )
            round_trace["follow_up_added_snippets"] = len(extra_snippets)
            stdout_tail = str(pipeline_data.get("stdout", "")).strip().splitlines()[-8:]
            if stdout_tail:
                round_trace["follow_up_pipeline_stdout_tail"] = stdout_tail
            trace.append(round_trace)

            if not extra_snippets:
                break
            snippets_all = _merge_dedup_snippets(extra_snippets, snippets_all)

        if final_result is None:
            raise RuntimeError("no final judgment produced")

        final_result = dict(final_result)
        final_result["follow_up"] = {
            "enabled": args.max_followup_rounds > 0,
            "max_followup_rounds": max(0, args.max_followup_rounds),
            "executed_rounds": len(trace),
            "final_snippets_used": len(final_snippets),
            "total_unique_snippets_collected": len(snippets_all),
            "pipeline_use_llm": pipeline_use_llm,
            "trace": trace,
        }
        print(json.dumps(final_result, ensure_ascii=False, indent=2))

        return 0
    except Exception as e:  # noqa: BLE001
        print(
            json.dumps(
                {
                    "error": str(e),
                    "result": RESULT_INSUFFICIENT,
                    "reason": "脚本执行失败，无法完成判断。",
                    "confidence": 0.0,
                    "desc": desc,
                    "next_search_suggestions": {
                        "functions_or_methods": [],
                        "variables_or_fields": [],
                        "focus_for_next_search": "",
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
