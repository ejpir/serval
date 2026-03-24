#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
POLICY="$ROOT/.pi/skills/architecture-conformance/policy/reuse_rules.json"

if [[ ! -f "$POLICY" ]]; then
  echo "CRITICAL|Z2|-|-|-|missing policy file: $POLICY"
  exit 2
fi

python3 - "$ROOT" "$POLICY" "$@" <<'PY'
import fnmatch
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
policy_path = Path(sys.argv[2])
raw_args = sys.argv[3:]

strict_mode = False
requested = []
for arg in raw_args:
    if arg == "--strict":
        strict_mode = True
    else:
        requested.append(arg)

with policy_path.open("r", encoding="utf-8") as f:
    policy = json.load(f)

if "rules" in policy:
    print("CRITICAL|Z2|-|-|-|legacy policy key 'rules' is not supported; use 'forbid', 'prefer', and 'duplicate_api'", file=sys.stderr)
    sys.exit(2)

forbid_rules = policy.get("forbid", [])
prefer_rules = policy.get("prefer", [])
duplicate_rules = policy.get("duplicate_api", [])

compiled_text_rules = []
for policy_type, rules in (("forbid", forbid_rules), ("prefer", prefer_rules)):
    for rule in rules:
        mode = rule.get("mode", "default")
        if mode == "strict" and not strict_mode:
            continue
        compiled_text_rules.append({
            "policy_type": policy_type,
            "id": rule["id"],
            "rule": rule.get("rule", "Z2"),
            "severity": rule.get("severity", "MAJOR"),
            "regex": re.compile(rule["regex"]),
            "message": rule.get("message", f"{policy_type} policy violation"),
            "recommendation": rule.get("recommendation", ""),
            "allow_paths": rule.get("allow_paths", []),
        })

compiled_duplicate_rules = []
for rule in duplicate_rules:
    mode = rule.get("mode", "default")
    if mode == "strict" and not strict_mode:
        continue
    names = rule.get("names", [])
    if not names:
        continue
    compiled_duplicate_rules.append({
        "policy_type": "duplicate_api",
        "id": rule["id"],
        "rule": rule.get("rule", "Z2"),
        "severity": rule.get("severity", "MAJOR"),
        "names": set(names),
        "message": rule.get("message", "duplicate API helper"),
        "recommendation": rule.get("recommendation", ""),
        "allow_paths": rule.get("allow_paths", []),
    })

if requested:
    modules = requested
else:
    modules = sorted([
        p.name
        for p in root.iterdir()
        if p.is_dir() and p.name.startswith("serval") and "zig-" not in p.name
    ])

fn_decl_re = re.compile(r'^\s*(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(')
violations = []

def is_allowed(rel_path: str, globs):
    for g in globs:
        if fnmatch.fnmatch(rel_path, g):
            return True
    return False

for module in modules:
    module_dir = root / module
    if not module_dir.is_dir():
        violations.append(("MAJOR", "Z2", module, "-", "-", f"module path not found: {module}"))
        continue

    for path in module_dir.rglob("*.zig"):
        rel = str(path.relative_to(root))
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception as exc:
            violations.append(("MAJOR", "Z2", module, "-", rel, f"failed to read file: {exc}"))
            continue

        # Text pattern rules: forbid/prefer
        for rule in compiled_text_rules:
            if is_allowed(rel, rule["allow_paths"]):
                continue
            rx = rule["regex"]
            for i, line in enumerate(lines, start=1):
                if rx.search(line):
                    detail = f"{rule['id']}[{rule['policy_type']}]: {rule['message']}"
                    if rule["recommendation"]:
                        detail += f" Recommendation: {rule['recommendation']}"
                    violations.append((
                        rule["severity"],
                        rule["rule"],
                        module,
                        "-",
                        f"{rel}:{i}",
                        detail,
                    ))

        # Duplicate helper declaration rules
        for rule in compiled_duplicate_rules:
            if is_allowed(rel, rule["allow_paths"]):
                continue
            for i, line in enumerate(lines, start=1):
                m = fn_decl_re.match(line)
                if not m:
                    continue
                fn_name = m.group(1)
                if fn_name not in rule["names"]:
                    continue

                detail = f"{rule['id']}[{rule['policy_type']}]: {rule['message']} (found `{fn_name}`)"
                if rule["recommendation"]:
                    detail += f" Recommendation: {rule['recommendation']}"
                violations.append((
                    rule["severity"],
                    rule["rule"],
                    module,
                    "-",
                    f"{rel}:{i}",
                    detail,
                ))

for severity, rule, src, dst, loc, msg in violations:
    print(f"{severity}|{rule}|{src}|{dst}|{loc}|{msg}")

print(f"SUMMARY|violations={len(violations)}|strict={1 if strict_mode else 0}")
sys.exit(1 if violations else 0)
PY
