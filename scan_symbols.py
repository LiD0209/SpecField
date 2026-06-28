from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Optional

from tree_sitter import Language, Parser
import tree_sitter_c as tsc
import tree_sitter_java as tsjava


# ---------- [non-English text removed] ----------

@dataclass
class SymbolRecord:
    file: str
    language: str
    symbol_type: str      # function / method / constructor
    symbol_name: str      # [non-English text removed] foo, App.main, UserService.UserService
    line: int
    column: int


# ---------- Tree-sitter [non-English text removed] ----------
C_LANGUAGE = Language(tsc.language())
JAVA_LANGUAGE = Language(tsjava.language())

C_PARSER = Parser(C_LANGUAGE)
JAVA_PARSER = Parser(JAVA_LANGUAGE)


# ---------- [non-English text removed] ----------

def read_text_bytes(path: Path) -> bytes:
    # Tree-sitter [non-English text removed]
    return path.read_bytes()


def walk(node) -> Iterator:
    yield node
    for child in node.children:
        yield from walk(child)


def text_of(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def find_first_descendant_by_type(node, type_name: str):
    for child in walk(node):
        if child.type == type_name:
            return child
    return None


def extract_identifier_from_c_declarator(node, source: bytes) -> Optional[str]:
    """
    C [non-English text removed] function_definition [non-English text removed]：
    function_declarator / pointer_declarator / parenthesized_declarator ...
    [non-English text removed] identifier。
    """
    ident = find_first_descendant_by_type(node, "identifier")
    if ident is not None:
        return text_of(ident, source)
    return None


def get_java_enclosing_class_name(node, source: bytes) -> Optional[str]:
    """
    [non-English text removed] class_declaration / interface_declaration / enum_declaration / record_declaration。
    [non-English text removed] identifier。
    """
    cur = node.parent
    while cur is not None:
        if cur.type in {
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
            "annotation_type_declaration",
            "record_declaration",
        }:
            name_node = cur.child_by_field_name("name")
            if name_node is None:
                name_node = find_first_descendant_by_type(cur, "identifier")
            if name_node is not None:
                return text_of(name_node, source)
        cur = cur.parent
    return None


# ---------- C [non-English text removed] ----------

def extract_c_symbols(path: Path) -> list[SymbolRecord]:
    source = read_text_bytes(path)
    tree = C_PARSER.parse(source)
    out: list[SymbolRecord] = []

    for node in walk(tree.root_node):
        # tree-sitter-c [non-English text removed] function_definition
        if node.type != "function_definition":
            continue

        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            # [non-English text removed] function_definition [non-English text removed] identifier
            name = extract_identifier_from_c_declarator(node, source)
        else:
            name = extract_identifier_from_c_declarator(declarator, source)

        if not name:
            continue

        out.append(
            SymbolRecord(
                file=str(path),
                language="C",
                symbol_type="function",
                symbol_name=name,
                line=node.start_point[0] + 1,
                column=node.start_point[1] + 1,
            )
        )

    return out


# ---------- Java [non-English text removed] ----------

def extract_java_symbols(path: Path) -> list[SymbolRecord]:
    source = read_text_bytes(path)
    tree = JAVA_PARSER.parse(source)
    out: list[SymbolRecord] = []

    for node in walk(tree.root_node):
        if node.type not in {"method_declaration", "constructor_declaration"}:
            continue

        name_node = node.child_by_field_name("name")
        if name_node is None:
            name_node = find_first_descendant_by_type(node, "identifier")
        if name_node is None:
            continue

        raw_name = text_of(name_node, source)
        class_name = get_java_enclosing_class_name(node, source)

        if class_name:
            full_name = f"{class_name}.{raw_name}"
        else:
            full_name = raw_name

        out.append(
            SymbolRecord(
                file=str(path),
                language="Java",
                symbol_type="constructor" if node.type == "constructor_declaration" else "method",
                symbol_name=full_name,
                line=node.start_point[0] + 1,
                column=node.start_point[1] + 1,
            )
        )

    return out


# ---------- [non-English text removed] ----------
SKIP_DIRS = {".git", "build", "target", "out", ".idea", ".vscode"}
def scan_project(root: Path) -> list[SymbolRecord]:
    results: list[SymbolRecord] = []

    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue

        suffix = path.suffix.lower()

        try:
            if suffix == ".c":
                results.extend(extract_c_symbols(path))
            elif suffix == ".java":
                results.extend(extract_java_symbols(path))
        except Exception as e:
            # [non-English text removed]
            print(f"[WARN] [non-English text removed]: {path} -> {e}", file=sys.stderr)

    return results


def build_file_mapping(records: list[SymbolRecord]) -> dict[str, list[dict]]:
    mapping: dict[str, list[dict]] = {}

    for r in records:
        mapping.setdefault(r.file, []).append({
            "language": r.language,
            "symbol_type": r.symbol_type,
            "symbol_name": r.symbol_name,
            "line": r.line,
            "column": r.column,
        })

    for file_path in mapping:
        mapping[file_path].sort(key=lambda x: (x["line"], x["column"], x["symbol_name"]))

    return mapping


def write_csv(records: list[SymbolRecord], out_path: Path) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["file", "language", "symbol_type", "symbol_name", "line", "column"],
        )
        writer.writeheader()
        for r in records:
            writer.writerow(asdict(r))


def write_json(mapping: dict[str, list[dict]], out_path: Path) -> None:
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(mapping, f, ensure_ascii=False, indent=2)


def print_pretty(mapping: dict[str, list[dict]]) -> None:
    for file_path in sorted(mapping.keys()):
        print(file_path)
        for item in mapping[file_path]:
            print(
                f"  - [{item['language']}] "
                f"{item['symbol_type']}: {item['symbol_name']} "
                f"(line {item['line']}, col {item['column']})"
            )
        print()


def main():
    if len(sys.argv) < 2:
        print("[non-English text removed]: python scan_symbols.py /path/to/project")
        sys.exit(1)

    root = Path(sys.argv[1]).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"[non-English text removed]: {root}")
        sys.exit(1)

    records = scan_project(root)
    records.sort(key=lambda r: (r.file, r.line, r.column, r.symbol_name))

    mapping = build_file_mapping(records)

    print_pretty(mapping)
    write_csv(records, Path("symbols.csv"))
    write_json(mapping, Path("symbols.json"))

    print(f"[non-English text removed]。")
    print("[non-English text removed]: symbols.csv, symbols.json")


if __name__ == "__main__":
    main()