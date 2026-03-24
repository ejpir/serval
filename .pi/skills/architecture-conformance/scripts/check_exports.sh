#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

python3 - "$ROOT" "$@" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
requested = sys.argv[2:]

if requested:
    modules = requested
else:
    modules = sorted([p.name for p in root.iterdir() if p.is_dir() and p.name.startswith("serval") and "zig-" not in p.name])

pub_const_re = re.compile(r'^\s*pub\s+const\s+([A-Za-z0-9_]+)\s*=\s*(.+);\s*$')
violations = []

for module in modules:
    module_dir = root / module
    if not module_dir.is_dir():
        violations.append(("MAJOR", "Z2", module, "-", "-", f"module path not found: {module}"))
        continue

    mod_path = module_dir / "mod.zig"
    if not mod_path.exists():
        # Not all modules may expose a top-level facade; informational.
        continue

    lines = mod_path.read_text(encoding="utf-8").splitlines()
    for line_no, line in enumerate(lines, start=1):
        m = pub_const_re.match(line)
        if not m:
            continue

        name = m.group(1)
        rhs = m.group(2)
        loc = f"{mod_path.relative_to(root)}:{line_no}"

        if name.startswith("_"):
            violations.append(("MAJOR", "Z2", module, "-", loc, f"underscored symbol exported publicly: {name}"))

        lower_name = name.lower()
        lower_rhs = rhs.lower()

        if "internal" in lower_name:
            violations.append(("MINOR", "Z2", module, "-", loc, f"possible internal symbol exported: {name}"))

        if "internal/" in lower_rhs or ".internal" in lower_rhs or '"_"' in lower_rhs:
            violations.append(("MAJOR", "Z2", module, "-", loc, f"possible internal implementation leaked in export rhs: {rhs}"))

for severity, rule, src, dst, loc, msg in violations:
    print(f"{severity}|{rule}|{src}|{dst}|{loc}|{msg}")

print(f"SUMMARY|violations={len(violations)}")
sys.exit(1 if violations else 0)
PY
