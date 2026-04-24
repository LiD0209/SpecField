#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

from pipeline_utils import now_ts, read_text, write_json, write_text


def preprocess_document(raw: str) -> str:
    text = raw.replace("\r\n", "\n").replace("\r", "\n").replace("\f", "\n")
    lines = text.split("\n")
    cleaned: list[str] = []

    header_patterns = [
        re.compile(r"^RFC\s+8446\b.*August 2018$"),
        re.compile(r"^Rescorla\s+Standards Track\s+\[Page \d+\]$"),
        re.compile(r"^\[Page \d+\]$"),
    ]

    for line in lines:
        stripped = line.strip()
        if any(p.match(stripped) for p in header_patterns):
            continue
        if stripped and re.fullmatch(r"[-_=]{6,}", stripped):
            continue
        cleaned.append(line.rstrip())

    text2 = "\n".join(cleaned)
    text2 = re.sub(r"\n{3,}", "\n\n", text2).strip()
    return text2 + "\n"


def split_into_chunks(text: str, max_chars: int) -> list[dict[str, str]]:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks: list[str] = []
    cur: list[str] = []
    cur_len = 0

    def flush() -> None:
        nonlocal cur, cur_len
        if cur:
            chunks.append("\n\n".join(cur))
            cur = []
            cur_len = 0

    for para in paragraphs:
        plen = len(para)
        if plen > max_chars:
            pieces = re.split(r"(?<=[\.\?!;:])\s+", para)
            tmp: list[str] = []
            tlen = 0
            for piece in pieces:
                piece = piece.strip()
                if not piece:
                    continue
                if tlen + len(piece) + 1 > max_chars and tmp:
                    chunks.append(" ".join(tmp))
                    tmp = [piece]
                    tlen = len(piece)
                else:
                    tmp.append(piece)
                    tlen += len(piece) + 1
            if tmp:
                if cur and cur_len + tlen + 2 > max_chars:
                    flush()
                cur.append(" ".join(tmp))
                cur_len += tlen + 2
            continue

        if cur_len + plen + 2 > max_chars and cur:
            flush()
        cur.append(para)
        cur_len += plen + 2

    flush()
    return [{"chunk_id": f"chunk_{i:04d}", "chunk_text": c} for i, c in enumerate(chunks, 1)]


def run_preprocess(doc_path: str, output_dir: str, chunk_size: int = 6000, max_chunks: int = 0) -> tuple[str, list[dict[str, str]]]:
    raw = read_text(Path(doc_path))
    text = preprocess_document(raw)
    chunks = split_into_chunks(text, chunk_size)
    if max_chunks and max_chunks > 0:
        chunks = chunks[:max_chunks]

    out_dir = Path(output_dir)
    write_text(out_dir / "preprocessed_text.txt", text)
    write_json(out_dir / "preprocessed_chunks.json", chunks)
    print(f"[{now_ts()}] preprocess done: {len(chunks)} chunks")
    return text, chunks


def main() -> int:
    parser = argparse.ArgumentParser(description="Step0: preprocess")
    parser.add_argument("--doc", default="document/TLS1.3.txt")
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--chunk-size", type=int, default=6000)
    parser.add_argument("--max-chunks", type=int, default=0)
    args = parser.parse_args()

    run_preprocess(args.doc, args.output_dir, args.chunk_size, args.max_chunks)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
