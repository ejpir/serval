#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

python3 - "$ROOT" "$@" <<'PY'
import re
import sys
from pathlib import Path
from collections import defaultdict, Counter

root = Path(sys.argv[1])
requested = sys.argv[2:]

if requested:
    modules = requested
else:
    modules = sorted([p.name for p in root.iterdir() if p.is_dir() and p.name.startswith("serval-")])

fn_re = re.compile(r'^\s*(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(')
std_usage_patterns = {
    "std.time": re.compile(r'\bstd\.time\.'),
    "std.Io.Clock": re.compile(r'\bstd\.Io\.Clock\.'),
    "std.log.debug": re.compile(r'\bstd\.log\.debug\s*\('),
    "std.debug.print": re.compile(r'\bstd\.debug\.print\s*\('),
    "posix.nanosleep": re.compile(r'\b(?:std\.posix|posix)\.nanosleep\b'),
}

# Frequent generic names that are usually OK to repeat.
ignore_names = {
    "init", "deinit", "reset", "close", "read", "write", "get", "put", "matches",
    "onLog", "onError", "onRequest", "onResponse", "selectUpstream",
    "consumeRecvWindow", "consumeSendWindow", "incrementRecvWindow", "incrementSendWindow",
}

fn_modules = defaultdict(set)
fn_locations = defaultdict(list)
std_hits = []

for module in modules:
    module_dir = root / module
    if not module_dir.is_dir():
        continue

    for path in module_dir.rglob("*.zig"):
        rel = path.relative_to(root)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue

        for i, line in enumerate(lines, start=1):
            m = fn_re.match(line)
            if m:
                fn_name = m.group(1)
                fn_modules[fn_name].add(module)
                fn_locations[fn_name].append((module, str(rel), i))

            for label, rx in std_usage_patterns.items():
                if rx.search(line):
                    std_hits.append((module, str(rel), i, label, line.strip()))

print("## Reinvention Candidate Audit")
print()
print("### Scope")
for m in modules:
    print(f"- {m}")

print()
print("### Duplicate Function Name Candidates (cross-module)")
print("| Function | Modules | Count | Sample Locations |")
print("|---|---|---:|---|")

rows = []
for fn_name, mods in fn_modules.items():
    if fn_name in ignore_names:
        continue
    if len(mods) < 2:
        continue
    locs = fn_locations[fn_name][:3]
    sample = "<br>".join([f"`{p}:{ln}`" for _, p, ln in locs])
    rows.append((fn_name, sorted(mods), len(mods), sample))

rows.sort(key=lambda r: (-r[2], r[0]))
if rows:
    for fn_name, mods, count, sample in rows:
        print(f"| `{fn_name}` | {', '.join(mods)} | {count} | {sample} |")
else:
    print("| _none_ |  | 0 |  |")

print()
print("### Low-level API Usage Inventory")
print("| Pattern | Hits |")
print("|---|---:|")

counter = Counter([h[3] for h in std_hits])
for label in std_usage_patterns.keys():
    print(f"| `{label}` | {counter.get(label, 0)} |")

print()
print("### Low-level API Usage Details")
print("| Module | Location | Pattern | Snippet |")
print("|---|---|---|---|")
if std_hits:
    for module, rel, ln, label, snippet in std_hits:
        snippet = snippet.replace("|", "\\|")
        if len(snippet) > 120:
            snippet = snippet[:117] + "..."
        print(f"| {module} | `{rel}:{ln}` | `{label}` | `{snippet}` |")
else:
    print("| _none_ |  |  |  |")
PY
