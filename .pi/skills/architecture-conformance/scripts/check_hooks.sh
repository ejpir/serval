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

wrapper_decl_re = re.compile(r'pub\s+fn\s+[A-Za-z0-9_]+\s*\(\s*comptime\s+Inner\s*:\s*type\s*\)\s*type')

required_hooks = ["selectUpstream"]
optional_hooks = [
    "onRequest",
    "onRequestBody",
    "onUpstreamRequest",
    "onUpstreamConnect",
    "onResponse",
    "onResponseBody",
    "onError",
    "onLog",
    "onConnectionOpen",
    "onConnectionClose",
]

violations = []

for module in modules:
    module_dir = root / module
    if not module_dir.is_dir():
        violations.append(("MAJOR", "Z4", module, "-", "-", f"module path not found: {module}"))
        continue

    for path in module_dir.rglob("*.zig"):
        text = path.read_text(encoding="utf-8")
        if "Inner" not in text:
            continue
        if not (wrapper_decl_re.search(text) or "@hasDecl(Inner" in text):
            continue

        loc = str(path.relative_to(root))

        for hook in required_hooks:
            if f"pub fn {hook}(" not in text:
                violations.append(("CRITICAL", "Z4", module, "-", loc, f"wrapper missing required hook surface: {hook}"))
            elif f"self.inner.{hook}(" not in text:
                violations.append(("CRITICAL", "Z4", module, "-", loc, f"required hook does not delegate to inner: {hook}"))

        for hook in optional_hooks:
            has_surface = f"pub fn {hook}(" in text
            if not has_surface:
                violations.append(("MAJOR", "Z4", module, "-", loc, f"wrapper missing optional hook passthrough surface: {hook}"))
                continue

            has_guard = f"@hasDecl(Inner, \"{hook}\")" in text
            delegates = f"self.inner.{hook}(" in text

            if not has_guard:
                violations.append(("MINOR", "Z4", module, "-", loc, f"hook surface exists without @hasDecl guard: {hook}"))
            if not delegates and hook != "onRequest":
                violations.append(("MINOR", "Z4", module, "-", loc, f"hook surface exists but does not delegate: {hook}"))

for severity, rule, src, dst, loc, msg in violations:
    print(f"{severity}|{rule}|{src}|{dst}|{loc}|{msg}")

print(f"SUMMARY|violations={len(violations)}")
sys.exit(1 if violations else 0)
PY
