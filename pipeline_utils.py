#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
from xml.etree import ElementTree as ET

DOC_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _extract_text_from_binary_doc(path: Path) -> str:
    data = path.read_bytes()
    chunks: list[str] = []
    seen: set[str] = set()

    for m in re.finditer(rb"(?:[\x20-\x7E]\x00){8,}", data):
        s = m.group(0).decode("utf-16le", errors="ignore")
        s = re.sub(r"\s+", " ", s).strip()
        if len(s) < 8 or s in seen:
            continue
        seen.add(s)
        chunks.append(s)

    for m in re.finditer(rb"[\x20-\x7E]{30,}", data):
        s = m.group(0).decode("latin1", errors="ignore")
        s = re.sub(r"\s+", " ", s).strip()
        if len(s) < 12 or s in seen:
            continue
        seen.add(s)
        chunks.append(s)

    if not chunks:
        raise RuntimeError(f"Failed to extract readable text from binary .doc: {path}")
    return "\n".join(chunks) + "\n"


def _extract_text_from_docx(path: Path) -> str:
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    w = f"{{{ns}}}"
    paras: list[str] = []

    try:
        with zipfile.ZipFile(path, "r") as zf:
            xml = zf.read("word/document.xml")
    except Exception as e:
        raise RuntimeError(f"Failed to open .docx content: {e}") from e

    try:
        root = ET.fromstring(xml)
    except Exception as e:
        raise RuntimeError(f"Invalid .docx XML content: {e}") from e

    for p in root.iter(f"{w}p"):
        parts: list[str] = []
        for node in p.iter():
            if node.tag == f"{w}t":
                parts.append(node.text or "")
            elif node.tag == f"{w}tab":
                parts.append("\t")
            elif node.tag in {f"{w}br", f"{w}cr"}:
                parts.append("\n")
        paragraph = "".join(parts).strip()
        if paragraph:
            paras.append(paragraph)

    if not paras:
        raise RuntimeError(f"No readable text found in .docx: {path}")
    return "\n".join(paras) + "\n"


def _read_word_via_com(path: Path) -> str:
    if os.name != "nt":
        raise RuntimeError("Word document parsing via COM is only supported on Windows")

    src = str(path.resolve(strict=False)).replace("'", "''")
    tmp_path = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name)
    tmp_path.unlink(missing_ok=True)
    out = str(tmp_path.resolve(strict=False)).replace("'", "''")

    ps_script = f"""
$ErrorActionPreference = 'Stop'
$word = $null
$doc = $null
function Invoke-WithRetry([scriptblock]$Action, [int]$MaxTry = 12, [int]$SleepMs = 400) {{
  for ($i = 0; $i -lt $MaxTry; $i++) {{
    try {{
      return & $Action
    }} catch {{
      $hr = $_.Exception.HResult
      if ($hr -eq -2147418111 -or $hr -eq -2147417846) {{
        Start-Sleep -Milliseconds $SleepMs
        continue
      }}
      throw
    }}
  }}
  throw "Word COM busy timeout after retries"
}}
try {{
  $src = '{src}'
  $out = '{out}'
  $word = Invoke-WithRetry {{ New-Object -ComObject Word.Application }}
  Invoke-WithRetry {{ $word.Visible = $false }}
  Invoke-WithRetry {{ $word.DisplayAlerts = 0 }}
  $doc = Invoke-WithRetry {{ $word.Documents.Open($src, $false, $true) }}
  $wdFormatUnicodeText = 7
  Invoke-WithRetry {{ $doc.SaveAs([ref]$out, [ref]$wdFormatUnicodeText) }}
}} finally {{
  if ($doc -ne $null) {{
    try {{ Invoke-WithRetry {{ $doc.Close($false) }} 4 200 }} catch {{ }}
  }}
  if ($word -ne $null) {{
    try {{ Invoke-WithRetry {{ $word.Quit() }} 4 200 }} catch {{ }}
  }}
}}
""".strip()

    cp = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or cp.stdout.strip() or "Word COM conversion failed")

    try:
        return tmp_path.read_text(encoding="utf-16")
    finally:
        tmp_path.unlink(missing_ok=True)


def read_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".doc", ".docx"}:
        try:
            return _read_word_via_com(path)
        except Exception as com_err:
            if suffix == ".doc":
                return _extract_text_from_binary_doc(path)
            try:
                return _extract_text_from_docx(path)
            except Exception as docx_err:
                raise RuntimeError(
                    f"Failed to parse Word document {path}: COM error: {com_err}; docx fallback error: {docx_err}"
                ) from com_err

    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as first_err:
        try:
            return path.read_text(encoding="gb18030")
        except UnicodeDecodeError:
            head = path.read_bytes()[:8]
            if head.startswith(DOC_OLE_MAGIC):
                raise RuntimeError(
                    f"{path} looks like a binary .doc file. "
                    "Please pass .txt/.md or .doc/.docx with Microsoft Word COM available."
                ) from first_err
            raise


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def normalize_alias(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out = [normalize_text(v) for v in value if normalize_text(v)]
        return list(dict.fromkeys(out))
    single = normalize_text(value)
    return [single] if single else []


def normalize_joined_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        parts = [normalize_joined_text(v) for v in value]
        return "; ".join(dict.fromkeys([p for p in parts if p]))
    return normalize_text(value)


def first_text(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = normalize_joined_text(row.get(key))
        if value:
            return value
    return ""


def field_name_from_record(row: dict[str, Any]) -> str:
    return _clean_field_name(first_text(row, "canonical_name", "variable_name", "field_name", "f"))


def aliases_from_record(row: dict[str, Any]) -> list[str]:
    return list(dict.fromkeys(normalize_alias(row.get("aliases")) + normalize_alias(row.get("alias"))))


def parent_from_record(row: dict[str, Any]) -> str:
    return first_text(
        row,
        "parent_message_or_structure",
        "parent_message",
        "parent_structure",
        "parent",
        "message_or_structure",
    )


def allowed_values_from_record(row: dict[str, Any]) -> str:
    return first_text(row, "allowed_values", "initial_value_or_range", "value_range", "range")


def source_locations_from_record(row: dict[str, Any]) -> str:
    return first_text(row, "source_locations", "source_location", "module_or_section", "section")


def source_evidence_from_record(row: dict[str, Any]) -> str:
    return first_text(row, "source_evidence", "evidence", "E")


PACKET_FIELD_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\- /(),]{0,119}$")
PACKET_CONTEXT_KEYWORDS = {
    # generic structured-message terms
    "struct",
    "enum",
    "field",
    "header",
    "payload",
    "flag",
    "code",
    "identifier",
    "option",
    "parameter",
    "table",
    "packet",
    "message",
    "frame",
    "schema",
    "wire format",
    "serialized",
    # protocol-agnostic-but-common terms
    "publish",
    "subscribe",
    "unsubscribe",
    "connect",
    "connack",
    "qos",
    "topic",
    "retain",
    "session",
    "username",
    "password",
    # TLS-specific terms
    "vector",
    "extension",
    "clienthello",
    "serverhello",
    "encryptedextensions",
    "certificaterequest",
    "newsessionticket",
    "record",
    "handshake",
    "uint",
    "opaque",
    "namedgroup",
    "cipher_suite",
}
CONCEPTUAL_NAME_TOKENS = {
    "authentication",
    "confidentiality",
    "integrity",
    "attacker",
    "endpoint",
    "connection",
    "channel",
    "protocol",
    "implementation",
    "security",
    "property",
    "traffic",
    "replay",
    "state machine",
    "state",
}


def _clean_field_name(name: str) -> str:
    n = name.strip().strip("`").strip('"').strip("'")
    if n.lower().endswith(" extension"):
        # keep extension field names like "supported_versions", drop suffix text
        n = n[: -len(" extension")].strip().strip('"').strip("'")
    return n


def is_packet_field_name(name: str) -> bool:
    n = _clean_field_name(normalize_text(name))
    if not n:
        return False
    low = n.lower()
    if "\n" in n or "\r" in n:
        return False
    if low.startswith("http://") or low.startswith("https://") or "mailto:" in low:
        return False
    if re.search(r"_(toc|ref|hlt)\d+$", low):
        return False
    if "mergeformat" in low or "theme" in low or "worddocument" in low:
        return False
    if sum(ch.isalpha() for ch in n) < 2:
        return False
    if any(tok in low for tok in CONCEPTUAL_NAME_TOKENS):
        return False
    return bool(PACKET_FIELD_NAME_RE.fullmatch(n))


def is_packet_field_context(row: dict[str, Any]) -> bool:
    name = field_name_from_record(row).lower()
    text = " ".join(
        [
            normalize_text(row.get("type")),
            normalize_text(row.get("definition")),
            normalize_text(row.get("field_kind")),
            normalize_text(row.get("semantic_role")),
            parent_from_record(row),
            allowed_values_from_record(row),
            source_locations_from_record(row),
            source_evidence_from_record(row),
        ]
    ).lower()
    if any(k in text for k in PACKET_CONTEXT_KEYWORDS):
        return True
    # Fallback: when context fields are sparse, keep clearly field-like names.
    name_hints = {
        "identifier",
        "topic",
        "qos",
        "flag",
        "code",
        "header",
        "payload",
        "length",
        "username",
        "password",
        "session",
        "packet",
    }
    return any(h in name for h in name_hints)


def filter_packet_field_definitions(
    definitions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for row in definitions:
        name = field_name_from_record(row)
        if not is_packet_field_name(name):
            continue
        if not is_packet_field_context(row):
            continue
        row = dict(row)
        aliases = aliases_from_record(row)
        allowed_values = allowed_values_from_record(row)
        source_locations = source_locations_from_record(row)
        source_evidence = source_evidence_from_record(row)

        row["canonical_name"] = name
        row["variable_name"] = name
        row["aliases"] = aliases
        row["alias"] = aliases
        row["parent_message_or_structure"] = parent_from_record(row)
        row["allowed_values"] = allowed_values
        row["source_locations"] = source_locations
        row["source_evidence"] = source_evidence
        row["initial_value_or_range"] = allowed_values
        row["module_or_section"] = source_locations
        row["evidence"] = source_evidence
        filtered.append(row)
    return filtered


def filter_change_records_to_catalog(
    changes: list[dict[str, Any]],
    definitions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    allowed = {
        field_name_from_record(d).lower()
        for d in definitions
        if field_name_from_record(d)
    }
    out: list[dict[str, Any]] = []
    for row in changes:
        name = _clean_field_name(normalize_text(row.get("variable_name")))
        if not name:
            continue
        if name.lower() not in allowed:
            continue
        if not is_packet_field_name(name):
            continue
        row = dict(row)
        row["variable_name"] = name
        out.append(row)
    return out


def extract_json_array(text: str) -> list[dict[str, Any]]:
    candidates: list[str] = []

    raw = text.strip()
    if raw:
        candidates.append(raw)

    fenced = re.findall(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE)
    candidates.extend([c.strip() for c in fenced if c.strip()])

    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch != "[":
            continue
        snippet = text[i:].strip()
        try:
            obj, _ = decoder.raw_decode(snippet)
            if isinstance(obj, list):
                candidates.append(json.dumps(obj, ensure_ascii=False))
        except json.JSONDecodeError:
            continue

    for candidate in candidates:
        try:
            obj = json.loads(candidate)
            if isinstance(obj, list):
                return [x for x in obj if isinstance(x, dict)]
        except json.JSONDecodeError:
            continue

    return []


def merge_definition_records(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for row in items:
        name = field_name_from_record(row)
        if not name:
            continue
        parent = parent_from_record(row)
        key = (name.lower(), parent.lower())
        allowed_values = allowed_values_from_record(row)
        source_locations = source_locations_from_record(row)
        source_evidence = source_evidence_from_record(row)
        existing = merged.get(
            key,
            {
                "canonical_name": name,
                "variable_name": name,
                "aliases": [],
                "alias": [],
                "parent_message_or_structure": parent,
                "field_kind": "",
                "type": "",
                "allowed_values": "",
                "definition": "",
                "semantic_role": "",
                "source_locations": "",
                "source_evidence": "",
                "initial_value_or_range": "",
                "module_or_section": "",
                "evidence": "",
                "source_chunks": [],
            },
        )

        aliases = list(dict.fromkeys(existing["aliases"] + aliases_from_record(row)))
        existing["aliases"] = aliases
        existing["alias"] = aliases

        for field in ["field_kind", "type", "definition", "semantic_role"]:
            if not existing.get(field):
                existing[field] = normalize_joined_text(row.get(field))
        if not existing.get("allowed_values"):
            existing["allowed_values"] = allowed_values
            existing["initial_value_or_range"] = allowed_values
        if not existing.get("source_locations"):
            existing["source_locations"] = source_locations
            existing["module_or_section"] = source_locations
        elif source_locations and source_locations not in existing["source_locations"]:
            existing["source_locations"] = f"{existing['source_locations']}; {source_locations}"
            existing["module_or_section"] = existing["source_locations"]
        if not existing.get("source_evidence"):
            existing["source_evidence"] = source_evidence
            existing["evidence"] = source_evidence

        chunk_id = normalize_text(row.get("source_chunk_id"))
        if chunk_id and chunk_id not in existing["source_chunks"]:
            existing["source_chunks"].append(chunk_id)

        merged[key] = existing

    merged_list = sorted(
        merged.values(),
        key=lambda x: (
            x["canonical_name"].lower(),
            x.get("parent_message_or_structure", "").lower(),
        ),
    )
    return filter_packet_field_definitions(merged_list)


def merge_change_records(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dedup: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for row in items:
        name = normalize_text(row.get("variable_name"))
        cond = normalize_text(row.get("change_condition"))
        action = normalize_text(row.get("change_action"))
        old_v = normalize_text(row.get("old_value"))
        new_v = normalize_text(row.get("new_value"))
        if not name:
            continue
        key = (name.lower(), cond, action, old_v, new_v)
        row2 = {
            "variable_name": name,
            "change_condition": cond,
            "change_action": action,
            "old_value": old_v,
            "new_value": new_v,
            "related_state_or_step": normalize_text(row.get("related_state_or_step")),
            "explicit_or_inferred": normalize_text(row.get("explicit_or_inferred")) or "explicit",
            "evidence": normalize_text(row.get("evidence")),
            "note": normalize_text(row.get("note")),
            "source_chunk_id": normalize_text(row.get("source_chunk_id")),
        }
        if key not in dedup:
            dedup[key] = row2
        else:
            old = dedup[key]
            for field in ["related_state_or_step", "explicit_or_inferred", "evidence", "note"]:
                if not old.get(field):
                    old[field] = row2.get(field, "")
            if row2["source_chunk_id"] and not old.get("source_chunk_id"):
                old["source_chunk_id"] = row2["source_chunk_id"]

    return sorted(dedup.values(), key=lambda x: (x["variable_name"].lower(), x["change_condition"]))


def build_variable_catalog(definitions: list[dict[str, Any]]) -> str:
    if not definitions:
        return "[]"
    rows = []
    for i, row in enumerate(definitions, start=1):
        name = field_name_from_record(row)
        alias = aliases_from_record(row)
        parent = parent_from_record(row)
        vtype = normalize_text(row.get("type"))
        allowed_values = allowed_values_from_record(row)
        source_locations = source_locations_from_record(row)
        parts = [f"{i}. {name}"]
        if alias:
            parts.append(f"aliases={', '.join(alias)}")
        if parent:
            parts.append(f"parent={parent}")
        if vtype:
            parts.append(f"type={vtype}")
        if allowed_values:
            parts.append(f"allowed_values={allowed_values}")
        if source_locations:
            parts.append(f"source_locations={source_locations}")
        rows.append(" | ".join(parts))
    return "\n".join(rows)


@dataclass
class OpenAICompatClient:
    api_key: str
    base_url: str
    model: str
    timeout_sec: int = 120
    max_retries: int = 4

    def chat(self, prompt: str) -> str:
        base = (self.base_url or "").strip()
        if not base.startswith("http://") and not base.startswith("https://"):
            raise RuntimeError(f"Invalid base_url: {self.base_url!r}")
        endpoint = base.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        }
        data = json.dumps(payload).encode("utf-8")

        last_err: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            req = urlrequest.Request(endpoint, data=data, headers=headers, method="POST")
            try:
                with urlrequest.urlopen(req, timeout=self.timeout_sec) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                obj = json.loads(raw)
                content = obj.get("choices", [{}])[0].get("message", {}).get("content", "")
                return content if isinstance(content, str) else str(content)
            except urlerror.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace")
                last_err = RuntimeError(f"HTTP {e.code} @ {endpoint}: {body}")
                if e.code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                    time.sleep(2 * attempt)
                    continue
                raise last_err
            except Exception as e:  # noqa: BLE001
                last_err = RuntimeError(f"{e} @ endpoint={endpoint}")
                if attempt < self.max_retries:
                    time.sleep(2 * attempt)
                    continue
                raise

        if last_err is not None:
            raise last_err
        raise RuntimeError("Unknown API failure")
