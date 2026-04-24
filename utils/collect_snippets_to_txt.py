#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def collect_snippets(node: Any, path: str, out: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            next_path = f"{path}.{key}" if path else key
            if key == "snippet" and isinstance(value, str) and value.strip():
                out.append((next_path, value))
            collect_snippets(value, next_path, out)
        return

    if isinstance(node, list):
        for idx, value in enumerate(node):
            collect_snippets(value, f"{path}[{idx}]", out)


def render(snippets: list[tuple[str, str]]) -> str:
    lines: list[str] = [f"Total snippets: {len(snippets)}", ""]
    for i, (path, snippet) in enumerate(snippets, start=1):
        lines.append(f"===== Snippet {i} =====")
        lines.append(f"Path: {path}")
        lines.append("")
        lines.append(snippet)
        lines.append("")
        lines.append("------------------------")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect all `snippet` fields from a JSON file and format them into a text report."
    )
    parser.add_argument(
        "--input",
        default=r"d:\project\conditionFuzzingPaper\output\variable_context_result.json",
        help="Input JSON path",
    )
    parser.add_argument(
        "--output",
        default=r"d:\project\conditionFuzzingPaper\test.txt",
        help="Output text path",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"input file not found: {input_path}")

    data = json.loads(input_path.read_text(encoding="utf-8"))
    snippets: list[tuple[str, str]] = []
    collect_snippets(data, "root", snippets)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render(snippets), encoding="utf-8")
    print(f"Collected {len(snippets)} snippets -> {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

