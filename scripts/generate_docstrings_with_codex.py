#!/usr/bin/env python3
"""Generate Zig public API docstrings with Codex CLI.

Default mode is dry-run. Use --apply to write changes.

Workflow:
1. Find .zig files.
2. Identify public declarations missing an immediate preceding `///` block.
3. Extract a declaration block (signature + bounded body slice).
4. Ask `codex exec` for a useful `///` doc block.
5. Insert the generated block above the declaration.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PUB_RE = re.compile(r"^(?P<indent>\s*)pub\s+(?P<kind>fn|const|var)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
DOC_RE = re.compile(r"^\s*///")
PLACEHOLDER_RE = re.compile(
    r"^\s*///\s+[A-Za-z_][A-Za-z0-9_]*\s+is\s+(part of the public API|a public constant|a public variable)\.\s*$"
)


@dataclass
class DeclTarget:
    file: Path
    line_index: int
    indent: str
    kind: str
    name: str
    start_offset: int
    end_offset: int


def run(
    cmd: List[str], *, input_text: Optional[str] = None, timeout_seconds: Optional[int] = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout_seconds,
    )


def list_zig_files(paths: List[str]) -> List[Path]:
    if paths:
        out: List[Path] = []
        for raw in paths:
            p = Path(raw)
            if p.is_dir():
                out.extend(sorted(x for x in p.rglob("*.zig") if x.is_file()))
            elif p.is_file() and p.suffix == ".zig":
                out.append(p)
        return out

    cp = run(["rg", "--files", "-g", "*.zig"])
    if cp.returncode != 0:
        raise RuntimeError(f"rg failed: {cp.stderr.strip()}")
    return [Path(line.strip()) for line in cp.stdout.splitlines() if line.strip()]


def line_starts(text: str) -> List[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def is_doc_present(lines: List[str], line_index: int) -> bool:
    i = line_index - 1
    while i >= 0 and lines[i].strip() == "":
        i -= 1
    return i >= 0 and DOC_RE.match(lines[i]) is not None


def should_replace_placeholder(lines: List[str], line_index: int) -> bool:
    i = line_index - 1
    while i >= 0 and lines[i].strip() == "":
        i -= 1
    return i >= 0 and PLACEHOLDER_RE.match(lines[i]) is not None


def find_decl_end(text: str, start_offset: int, max_chars: int) -> int:
    """Find declaration block end using bounded brace matching.

    This is intentionally simple and bounded. It is robust enough for generating
    prompts and avoids unbounded scans.
    """
    n = min(len(text), start_offset + max_chars)
    i = start_offset
    depth = 0
    seen_open = False
    in_str = False
    str_quote = ""

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == str_quote:
                in_str = False
            i += 1
            continue

        if ch in ('"', "'"):
            in_str = True
            str_quote = ch
            i += 1
            continue

        if ch == "/" and nxt == "/":
            nl = text.find("\n", i)
            if nl == -1:
                return n
            i = nl + 1
            continue

        if ch == "{":
            depth += 1
            seen_open = True
            i += 1
            continue

        if ch == "}":
            if depth > 0:
                depth -= 1
            i += 1
            if seen_open and depth == 0:
                return i
            continue

        if ch == ";" and not seen_open:
            return i + 1

        i += 1

    return n


def collect_targets(path: Path, replace_placeholders: bool, max_chars: int) -> List[DeclTarget]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    starts = line_starts(text)
    targets: List[DeclTarget] = []

    for idx, line in enumerate(lines):
        m = PUB_RE.match(line)
        if not m:
            continue

        has_doc = is_doc_present(lines, idx)
        if has_doc and not (replace_placeholders and should_replace_placeholder(lines, idx)):
            continue

        start = starts[idx]
        end = find_decl_end(text, start, max_chars)
        targets.append(
            DeclTarget(
                file=path,
                line_index=idx,
                indent=m.group("indent"),
                kind=m.group("kind"),
                name=m.group("name"),
                start_offset=start,
                end_offset=end,
            )
        )

    return targets


def build_prompt(path: Path, target: DeclTarget, snippet: str) -> str:
    return f"""You are writing production-quality Zig API docs.

Write a useful Zig doc comment block for this declaration.
Requirements:
- Output ONLY lines that start with `///`.
- Be specific: describe behavior, key preconditions, ownership/lifetime where relevant, and error behavior.
- Keep it concise (2-6 lines).
- Do not invent behavior not supported by the code.

File: {path}
Symbol: {target.kind} {target.name}

Declaration block:
```zig
{snippet}
```
"""


def build_batch_prompt(path: Path, batch: List[Tuple[int, DeclTarget, str]]) -> str:
    items = []
    for idx, target, snippet in batch:
        items.append(
            {
                "id": idx,
                "kind": target.kind,
                "name": target.name,
                "declaration": snippet,
            }
        )
    payload = json.dumps({"file": str(path), "items": items}, indent=2)
    return f"""You are writing production-quality Zig API docs.

Generate useful Zig doc comment blocks for each declaration in the input JSON.
Requirements:
- Return valid JSON only (no markdown fences, no prose).
- Output format: {{"items":[{{"id":<int>,"docs":[<string>, ...]}}]}}
- Each docs string must start with `///`.
- 2-6 lines per declaration.
- Be specific: behavior, key preconditions, ownership/lifetime when relevant, and error behavior.
- Do not invent behavior not supported by the declaration.
- Keep declaration IDs exactly as provided.

Input:
{payload}
"""


def extract_json_object(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise RuntimeError("model output did not contain a JSON object")
    return text[start : end + 1]


def generate_doc_block(codex_cmd: List[str], prompt: str, timeout_seconds: int, retries: int) -> List[str]:
    last_error = ""
    for attempt in range(retries + 1):
        try:
            cp = run(codex_cmd + ["-"], input_text=prompt, timeout_seconds=timeout_seconds)
        except subprocess.TimeoutExpired:
            last_error = f"codex exec timed out after {timeout_seconds}s"
            continue

        if cp.returncode != 0:
            last_error = f"codex exec failed: {cp.stderr.strip()}"
            continue

        out = cp.stdout.strip()
        lines = [ln.rstrip() for ln in out.splitlines() if ln.strip()]
        doc_lines = [ln for ln in lines if ln.lstrip().startswith("///")]
        if not doc_lines:
            last_error = "codex did not return any `///` lines"
            continue

        # Normalize leading indentation; caller applies target indentation.
        normalized = []
        for ln in doc_lines:
            cleaned = ln.lstrip()
            if not cleaned.startswith("///"):
                continue
            normalized.append(cleaned)
        if not normalized:
            last_error = "no valid normalized doc lines produced"
            continue
        return normalized

    raise RuntimeError(last_error or "codex exec failed without details")


def generate_doc_blocks_batch(
    codex_cmd: List[str],
    path: Path,
    batch: List[Tuple[int, DeclTarget, str]],
    timeout_seconds: int,
    retries: int,
) -> Dict[int, List[str]]:
    prompt = build_batch_prompt(path, batch)
    last_error = ""

    for _attempt in range(retries + 1):
        try:
            cp = run(codex_cmd + ["-"], input_text=prompt, timeout_seconds=timeout_seconds)
        except subprocess.TimeoutExpired:
            last_error = f"codex exec timed out after {timeout_seconds}s"
            continue

        if cp.returncode != 0:
            last_error = f"codex exec failed: {cp.stderr.strip()}"
            continue

        try:
            parsed = json.loads(extract_json_object(cp.stdout.strip()))
        except Exception as exc:  # noqa: BLE001
            last_error = f"invalid JSON response: {exc}"
            continue

        raw_items = parsed.get("items")
        if not isinstance(raw_items, list):
            last_error = "response JSON missing items[]"
            continue

        docs_by_id: Dict[int, List[str]] = {}
        valid = True
        for item in raw_items:
            if not isinstance(item, dict):
                valid = False
                break
            raw_id = item.get("id")
            raw_docs = item.get("docs")
            if not isinstance(raw_id, int) or not isinstance(raw_docs, list):
                valid = False
                break
            normalized: List[str] = []
            for line in raw_docs:
                if not isinstance(line, str):
                    valid = False
                    break
                cleaned = line.strip()
                if not cleaned.startswith("///"):
                    valid = False
                    break
                normalized.append(cleaned)
            if not valid or not normalized:
                valid = False
                break
            docs_by_id[raw_id] = normalized

        if not valid:
            last_error = "response JSON has invalid item shape/content"
            continue

        expected_ids = {idx for idx, _t, _s in batch}
        if set(docs_by_id.keys()) != expected_ids:
            last_error = "response IDs did not match batch IDs"
            continue

        return docs_by_id

    raise RuntimeError(last_error or "batched codex generation failed without details")


def chunked_list(items: List[Tuple[int, DeclTarget, str]], batch_size: int) -> List[List[Tuple[int, DeclTarget, str]]]:
    if batch_size <= 0:
        return [items]
    chunks: List[List[Tuple[int, DeclTarget, str]]] = []
    for i in range(0, len(items), batch_size):
        chunks.append(items[i : i + batch_size])
    return chunks


def apply_to_file(
    path: Path,
    targets: List[DeclTarget],
    apply: bool,
    codex_cmd: List[str],
    verbose: bool,
    timeout_seconds: int,
    retries: int,
    batch_size: int,
) -> int:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    changed = 0

    if not apply:
        if verbose:
            for t in targets:
                print(f"would update {path}:{t.line_index + 1} {t.kind} {t.name}")
        return len(targets)

    indexed: List[Tuple[int, DeclTarget, str]] = []
    for idx, t in enumerate(sorted(targets, key=lambda x: x.line_index, reverse=True)):
        snippet = text[t.start_offset : t.end_offset].strip()
        indexed.append((idx, t, snippet))

    for batch in chunked_list(indexed, batch_size):
        # Keep the old single-call flow for batch size 1.
        if len(batch) == 1:
            batch_id, target, snippet = batch[0]
            prompt = build_prompt(path, target, snippet)
            docs_by_id = {batch_id: generate_doc_block(codex_cmd, prompt, timeout_seconds, retries)}
        else:
            docs_by_id = generate_doc_blocks_batch(codex_cmd, path, batch, timeout_seconds, retries)

        for batch_id, t, _snippet in batch:
            docs = docs_by_id[batch_id]
            insert_lines = [f"{t.indent}{d}\n" for d in docs]

            # Replace placeholder line if present directly above declaration.
            replace_i = t.line_index - 1
            while replace_i >= 0 and lines[replace_i].strip() == "":
                replace_i -= 1
            if replace_i >= 0 and PLACEHOLDER_RE.match(lines[replace_i] or ""):
                del lines[replace_i]
                t_line = t.line_index - 1
            else:
                t_line = t.line_index

            for il in reversed(insert_lines):
                lines.insert(t_line, il)
            changed += 1

            if verbose:
                print(f"updated {path}:{t.line_index + 1} {t.kind} {t.name}")

    if changed and apply:
        path.write_text("".join(lines), encoding="utf-8")
    return changed


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate Zig public API docstrings using Codex CLI")
    p.add_argument("paths", nargs="*", help="Optional files/directories to scan")
    p.add_argument("--apply", action="store_true", help="Write changes to files (default: dry-run)")
    p.add_argument("--replace-placeholders", action="store_true", help="Replace generated placeholder docs")
    p.add_argument("--limit", type=int, default=0, help="Max declarations to process (0 = all)")
    p.add_argument("--batch-size", type=int, default=8, help="Declarations per Codex call in apply mode")
    p.add_argument("--max-snippet-chars", type=int, default=2400, help="Max chars per declaration snippet")
    p.add_argument("--verbose", action="store_true", help="Print per-symbol updates")
    p.add_argument(
        "--codex-cmd",
        default="codex exec --skip-git-repo-check --sandbox read-only --color never -m gpt-5.4-mini",
        help="Base codex command used for generation",
    )
    p.add_argument("--timeout-seconds", type=int, default=90, help="Per-codex-call timeout in seconds")
    p.add_argument("--retries", type=int, default=1, help="Retries per failed/timed-out codex call")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    codex_cmd = args.codex_cmd.split()

    files = list_zig_files(args.paths)
    all_targets: List[DeclTarget] = []

    for f in files:
        all_targets.extend(collect_targets(f, args.replace_placeholders, args.max_snippet_chars))

    if args.limit > 0:
        all_targets = all_targets[: args.limit]

    if not all_targets:
        print("No matching declarations found.")
        return 0

    grouped: dict[Path, List[DeclTarget]] = {}
    for t in all_targets:
        grouped.setdefault(t.file, []).append(t)

    print(json.dumps({
        "mode": "apply" if args.apply else "dry-run",
        "files": len(grouped),
        "declarations": len(all_targets),
        "replace_placeholders": args.replace_placeholders,
    }))

    total_changed = 0
    for path, targets in grouped.items():
        changed = apply_to_file(
            path,
            targets,
            args.apply,
            codex_cmd,
            args.verbose,
            args.timeout_seconds,
            args.retries,
            args.batch_size,
        )
        total_changed += changed

    if not args.apply:
        print(f"Dry-run complete. Would update {total_changed} declarations.")
    else:
        print(f"Applied updates to {total_changed} declarations.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
