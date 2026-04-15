#!/usr/bin/env python3
"""Pre-commit public-doc quality gate for staged Zig files.

Fail conditions (staged symbols only):
- Missing `///` doc block on touched public declarations.
- For touched `pub fn` declarations:
  - missing contract/precondition wording,
  - missing error wording when function returns an error union (`!`),
  - missing ownership/lifetime wording when declaration has pointer params.

Warn conditions:
- Touched public function has a very short doc block (< 12 words).
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import re
import subprocess
import sys
from typing import Iterable, Sequence


PUBLIC_DECL_RE = re.compile(r"^\s*pub\s+(fn|const|var)\s+([A-Za-z0-9_]+)")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

CONTRACT_KEYWORDS = (
    "precondition",
    "must",
    "requires",
    "assert",
    "caller",
    "expects",
)
ERROR_KEYWORDS = (
    "error",
    "fail",
    "invalid",
    "timeout",
    "returns",
)
LIFETIME_KEYWORDS = (
    "borrow",
    "own",
    "lifetime",
    "alive",
    "valid",
    "deinit",
    "close",
    "release",
)


@dataclasses.dataclass(frozen=True)
class Symbol:
    path: pathlib.Path
    kind: str
    name: str
    decl_line: int
    doc_start_line: int | None
    doc_end_line: int | None
    doc_text: str
    has_pointer_params: bool
    returns_error_union: bool


@dataclasses.dataclass(frozen=True)
class Violation:
    path: pathlib.Path
    line: int
    symbol: str
    rule: str
    message: str


@dataclasses.dataclass(frozen=True)
class WarningNote:
    path: pathlib.Path
    line: int
    symbol: str
    message: str


def git(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.stdout


def staged_zig_files() -> list[pathlib.Path]:
    out = git("diff", "--cached", "--name-only", "--diff-filter=ACMR")
    paths: list[pathlib.Path] = []
    for raw in out.splitlines():
        if not raw.endswith(".zig"):
            continue
        p = pathlib.Path(raw)
        if p.exists():
            paths.append(p)
    return paths


def changed_ranges_for_file(path: pathlib.Path) -> list[tuple[int, int]]:
    out = git("diff", "--cached", "--unified=0", "--", str(path))
    ranges: list[tuple[int, int]] = []
    for line in out.splitlines():
        m = HUNK_RE.match(line)
        if not m:
            continue
        start = int(m.group(1))
        count = int(m.group(2) or "1")
        if count <= 0:
            continue
        end = start + count - 1
        ranges.append((start, end))
    return ranges


def overlaps_any(line_start: int, line_end: int, ranges: Sequence[tuple[int, int]]) -> bool:
    for start, end in ranges:
        if line_start <= end and line_end >= start:
            return True
    return False


def parse_symbols(path: pathlib.Path) -> list[Symbol]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    symbols: list[Symbol] = []
    for idx, line in enumerate(lines):
        m = PUBLIC_DECL_RE.match(line)
        if not m:
            continue

        kind = m.group(1)
        name = m.group(2)

        doc_lines: list[str] = []
        j = idx - 1
        while j >= 0 and lines[j].strip().startswith("///"):
            doc_lines.append(lines[j].strip()[3:].strip())
            j -= 1
        doc_lines.reverse()

        doc_text = " ".join(doc_lines).strip()
        doc_start_line = (j + 2) if doc_lines else None
        doc_end_line = idx if doc_lines else None

        decl = line.strip()
        k = idx + 1
        while k < len(lines) and "{" not in decl and ";" not in decl:
            decl += " " + lines[k].strip()
            if "{" in lines[k] or ";" in lines[k]:
                break
            k += 1

        params_segment = decl.split(")", 1)[0]
        pre_body = decl.split("{", 1)[0].split(";", 1)[0]
        has_pointer_params = "*" in params_segment
        returns_error_union = "!" in pre_body

        symbols.append(
            Symbol(
                path=path,
                kind=kind,
                name=name,
                decl_line=idx + 1,
                doc_start_line=doc_start_line,
                doc_end_line=doc_end_line,
                doc_text=doc_text,
                has_pointer_params=has_pointer_params,
                returns_error_union=returns_error_union,
            )
        )

    return symbols


def has_any_keyword(doc_lower: str, keywords: Iterable[str]) -> bool:
    return any(k in doc_lower for k in keywords)


def lint_touched_symbols(path: pathlib.Path, ranges: Sequence[tuple[int, int]]) -> tuple[list[Violation], list[WarningNote], int]:
    violations: list[Violation] = []
    warnings: list[WarningNote] = []
    touched_count = 0

    for sym in parse_symbols(path):
        start = sym.doc_start_line or sym.decl_line
        end = sym.decl_line
        if sym.doc_end_line is not None:
            end = max(end, sym.doc_end_line)

        if not overlaps_any(start, end, ranges):
            continue

        touched_count += 1
        symbol_name = f"{sym.kind} {sym.name}"

        if not sym.doc_text:
            violations.append(
                Violation(
                    path=path,
                    line=sym.decl_line,
                    symbol=symbol_name,
                    rule="missing-doc",
                    message="Touched public declaration is missing immediate `///` docs.",
                )
            )
            continue

        doc_lower = sym.doc_text.lower()

        if sym.kind == "fn" and sym.returns_error_union and not has_any_keyword(doc_lower, CONTRACT_KEYWORDS):
            violations.append(
                Violation(
                    path=path,
                    line=sym.decl_line,
                    symbol=symbol_name,
                    rule="missing-contract",
                    message="Error-returning function doc should state preconditions/contract (e.g. precondition, must, requires).",
                )
            )

        if sym.kind == "fn" and sym.returns_error_union and not has_any_keyword(doc_lower, ERROR_KEYWORDS):
            violations.append(
                Violation(
                    path=path,
                    line=sym.decl_line,
                    symbol=symbol_name,
                    rule="missing-error-semantics",
                    message="Error-returning function doc should describe failure semantics.",
                )
            )

        if (
            sym.kind == "fn"
            and sym.returns_error_union
            and sym.has_pointer_params
            and not has_any_keyword(doc_lower, LIFETIME_KEYWORDS)
        ):
            violations.append(
                Violation(
                    path=path,
                    line=sym.decl_line,
                    symbol=symbol_name,
                    rule="missing-lifetime",
                    message="Pointer-param error-returning function doc should describe ownership/lifetime expectations.",
                )
            )

        if sym.kind == "fn":
            word_count = len([w for w in sym.doc_text.split() if w])
            if word_count < 12:
                warnings.append(
                    WarningNote(
                        path=path,
                        line=sym.decl_line,
                        symbol=symbol_name,
                        message=f"Doc is short ({word_count} words); consider adding contract/error/lifetime detail.",
                    )
                )

    return violations, warnings, touched_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Check staged public-doc quality for Zig files.")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan all repository Zig files instead of only staged files.",
    )
    args = parser.parse_args()

    if args.all:
        files = sorted(pathlib.Path(".").glob("serval*/**/*.zig"))
        file_ranges: dict[pathlib.Path, list[tuple[int, int]]] = {
            p: [(1, 10**9)] for p in files if p.is_file()
        }
    else:
        files = staged_zig_files()
        if not files:
            print("doc-gate: no staged Zig files; skipping")
            return 0
        file_ranges = {p: changed_ranges_for_file(p) for p in files}

    total_touched = 0
    all_violations: list[Violation] = []
    all_warnings: list[WarningNote] = []

    for path in files:
        ranges = file_ranges.get(path, [])
        if not ranges:
            continue
        violations, warnings, touched = lint_touched_symbols(path, ranges)
        total_touched += touched
        all_violations.extend(violations)
        all_warnings.extend(warnings)

    print(
        f"doc-gate: checked {len(files)} file(s), touched public symbols={total_touched}, "
        f"violations={len(all_violations)}, warnings={len(all_warnings)}"
    )

    for v in all_violations:
        print(f"FAIL {v.path}:{v.line} [{v.rule}] {v.symbol} - {v.message}")

    for w in all_warnings:
        print(f"WARN {w.path}:{w.line} {w.symbol} - {w.message}")

    if all_violations:
        print("doc-gate: failed")
        return 1

    print("doc-gate: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
