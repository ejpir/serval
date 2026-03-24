#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
POLICY="$ROOT/.pi/skills/architecture-conformance/policy/layers.json"

if [[ ! -f "$POLICY" ]]; then
  echo "CRITICAL|Z1|-|-|-|missing policy file: $POLICY"
  exit 2
fi

python3 - "$ROOT" "$POLICY" "$@" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
policy_path = Path(sys.argv[2])
requested = sys.argv[3:]

with policy_path.open("r", encoding="utf-8") as f:
    policy = json.load(f)

layers = policy.get("layers", {})
allowed_sideways = {tuple(x) for x in policy.get("allowed_sideways", [])}

module_to_layer = {}
for layer_str, modules in layers.items():
    layer = int(layer_str)
    for m in modules:
        module_to_layer[m] = layer

if requested:
    modules = requested
else:
    modules = sorted([p.name for p in root.iterdir() if p.is_dir() and p.name.startswith("serval") and "zig-" not in p.name])

import_re = re.compile(r'@import\("([^"]+)"\)')

violations = []

for module in modules:
    module_dir = root / module
    if not module_dir.is_dir():
        violations.append(("MAJOR", "Z1", module, "-", "-", f"module path not found: {module}"))
        continue
    if module not in module_to_layer:
        violations.append(("MAJOR", "Z1", module, "-", "-", "module missing from policy/layers.json"))
        continue

    from_layer = module_to_layer[module]
    for path in module_dir.rglob("*.zig"):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception as exc:
            violations.append(("MAJOR", "Z1", module, "-", str(path.relative_to(root)), f"failed to read file: {exc}"))
            continue

        for line_no, line in enumerate(lines, start=1):
            for dep in import_re.findall(line):
                if dep not in module_to_layer:
                    continue
                if dep == module:
                    continue

                to_layer = module_to_layer[dep]
                location = f"{path.relative_to(root)}:{line_no}"

                if to_layer > from_layer:
                    violations.append((
                        "CRITICAL", "Z1", module, dep, location,
                        f"upward dependency not allowed (layer {from_layer} -> {to_layer})"
                    ))
                elif to_layer == from_layer and (module, dep) not in allowed_sideways:
                    violations.append((
                        "MAJOR", "Z1", module, dep, location,
                        f"same-layer dependency not allowed by policy (layer {from_layer})"
                    ))

for severity, rule, src, dst, loc, msg in violations:
    print(f"{severity}|{rule}|{src}|{dst}|{loc}|{msg}")

print(f"SUMMARY|violations={len(violations)}")
sys.exit(1 if violations else 0)
PY
