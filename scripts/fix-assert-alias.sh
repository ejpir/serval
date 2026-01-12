#!/bin/bash
# Fix std.debug.assert to use assert alias consistently across codebase
#
# Usage: ./scripts/fix-assert-alias.sh [--check]
#   --check  Only report files that need fixing, don't modify

set -e

CHECK_ONLY=false
if [[ "$1" == "--check" ]]; then
    CHECK_ONLY=true
fi

# Find all Zig files using std.debug.assert without the alias
needs_fix=()
while IFS= read -r file; do
    # Skip if alias already exists
    if grep -q "const assert = std.debug.assert" "$file" 2>/dev/null; then
        continue
    fi
    # Check if file uses std.debug.assert
    if grep -q "std\.debug\.assert" "$file" 2>/dev/null; then
        needs_fix+=("$file")
    fi
done < <(find . -name "*.zig" -type f ! -path "./.zig-cache/*")

if [[ ${#needs_fix[@]} -eq 0 ]]; then
    echo "All files use assert alias consistently."
    exit 0
fi

echo "Files needing fix: ${#needs_fix[@]}"
for file in "${needs_fix[@]}"; do
    echo "  $file"
done

if $CHECK_ONLY; then
    exit 1
fi

echo ""
echo "Fixing..."

for file in "${needs_fix[@]}"; do
    # Check if file has std import
    if ! grep -q "^const std = @import" "$file"; then
        echo "  SKIP: $file (no std import)"
        continue
    fi

    echo "  FIX: $file"

    # Step 1: Add alias after std import (use temp marker to avoid self-replacement)
    sed -i 's/^const std = @import("std");$/const std = @import("std");\nconst assert = __ASSERT_PLACEHOLDER__;/' "$file"

    # Step 2: Replace all std.debug.assert with assert
    sed -i 's/std\.debug\.assert/assert/g' "$file"

    # Step 3: Replace placeholder with actual value
    sed -i 's/__ASSERT_PLACEHOLDER__/std.debug.assert/' "$file"
done

echo ""
echo "Done. Run 'zig build test' to verify."
