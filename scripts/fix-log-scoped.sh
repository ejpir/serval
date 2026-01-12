#!/bin/bash
# Migrate std.log calls to scoped logging from serval-core
#
# Usage: ./scripts/fix-log-scoped.sh [--check]
#   --check  Only report files that need fixing, don't modify

set -e

CHECK_ONLY=false
if [[ "$1" == "--check" ]]; then
    CHECK_ONLY=true
fi

# Derive scope name from file path
get_scope() {
    local file="$1"

    # serval-router/foo.zig -> router
    if [[ "$file" =~ ^\./serval-([^/]+)/ ]]; then
        echo "${BASH_REMATCH[1]}"
    # examples/gateway/main.zig -> gateway
    elif [[ "$file" == "./examples/gateway/main.zig" ]]; then
        echo "gateway"
    # examples/gateway/controller/foo.zig -> gateway_controller
    elif [[ "$file" =~ ^\./examples/gateway/([^/]+)/ ]]; then
        echo "gateway_${BASH_REMATCH[1]}"
    # examples/router/foo.zig -> router_example
    elif [[ "$file" =~ ^\./examples/router/ ]]; then
        echo "router_example"
    # examples/foo.zig -> foo (filename without extension)
    elif [[ "$file" =~ ^\./examples/([^/]+)\.zig$ ]]; then
        echo "${BASH_REMATCH[1]}"
    # experiments/* -> experiment
    elif [[ "$file" =~ ^\./experiments/ ]]; then
        echo "tls_experiment"
    else
        echo "serval"
    fi
}

# Find files that use std.log but don't have scoped logging
needs_fix=()
while IFS= read -r file; do
    # Skip serval-core/log.zig itself
    if [[ "$file" == "./serval-core/log.zig" ]]; then
        continue
    fi
    # Check if already using scoped logging
    if grep -q "\.log\.scoped\|= log\.scoped" "$file" 2>/dev/null; then
        continue
    fi
    # Check if uses std.log
    if grep -q "std\.log\.\(debug\|info\|warn\|err\)" "$file" 2>/dev/null; then
        needs_fix+=("$file")
    fi
done < <(find . -name "*.zig" -type f ! -path "./.zig-cache/*")

if [[ ${#needs_fix[@]} -eq 0 ]]; then
    echo "All files use scoped logging consistently."
    exit 0
fi

echo "Files needing migration: ${#needs_fix[@]}"
for file in "${needs_fix[@]}"; do
    scope=$(get_scope "$file")
    echo "  $file -> .$scope"
done

if $CHECK_ONLY; then
    exit 1
fi

echo ""
echo "Migrating..."

for file in "${needs_fix[@]}"; do
    scope=$(get_scope "$file")
    echo "  FIX: $file (.$scope)"

    # Determine how to add the log import based on existing imports
    if grep -q 'const core = @import("serval-core")' "$file"; then
        # Add after: const core = @import("serval-core");
        sed -i "s|^const core = @import(\"serval-core\");|const core = @import(\"serval-core\");\nconst log = core.log.scoped(.$scope);|" "$file"
    elif grep -q 'const serval_core = @import("serval-core")' "$file"; then
        # Add after: const serval_core = @import("serval-core");
        sed -i "s|^const serval_core = @import(\"serval-core\");|const serval_core = @import(\"serval-core\");\nconst log = serval_core.log.scoped(.$scope);|" "$file"
    elif grep -q '@import("serval-core")' "$file"; then
        # Has some serval-core import, add log import after std
        sed -i "s|^const std = @import(\"std\");|const std = @import(\"std\");\nconst log = @import(\"serval-core\").log.scoped(.$scope);|" "$file"
    else
        # No serval-core import, add after std import
        sed -i "s|^const std = @import(\"std\");|const std = @import(\"std\");\nconst log = @import(\"serval-core\").log.scoped(.$scope);|" "$file"
    fi

    # Replace std.log calls with log calls
    sed -i 's/std\.log\.debug/log.debug/g' "$file"
    sed -i 's/std\.log\.info/log.info/g' "$file"
    sed -i 's/std\.log\.warn/log.warn/g' "$file"
    sed -i 's/std\.log\.err/log.err/g' "$file"
done

echo ""
echo "Done. Run 'zig build test' to verify."
