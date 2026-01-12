#!/bin/bash
# Script to fix std.time usages across the codebase
# Uses serval-core.time helpers instead
# Run from repo root: ./scripts/fix_std_time.sh

set -e

echo "=== Fixing std.time usages ==="

# -----------------------------------------------------------------------------
# Part 1: serval-* modules (import serval-core)
# -----------------------------------------------------------------------------

# serval-core/config.zig - special case, import time relatively
echo "Fixing serval-core/config.zig..."
sed -i 's/= 60 \* std\.time\.ns_per_s;/= time.secondsToNanos(60);/g' serval-core/config.zig
sed -i 's/= 5 \* std\.time\.ns_per_s;/= time.secondsToNanos(5);/g' serval-core/config.zig
sed -i 's/= 30 \* std\.time\.ns_per_s;/= time.secondsToNanos(30);/g' serval-core/config.zig
sed -i 's/= 10 \* std\.time\.ns_per_s,/= time.secondsToNanos(10),/g' serval-core/config.zig

# serval-pool/pool.zig
echo "Fixing serval-pool/pool.zig..."
sed -i 's/std\.time\.ns_per_s/time.ns_per_s/g' serval-pool/pool.zig

# serval-server/h1/server.zig - replace @divFloor pattern
echo "Fixing serval-server/h1/server.zig..."
sed -i 's/@intCast(@divFloor(ctx\.start_time_ns, std\.time\.ns_per_s))/time.nanosToSecondsI128(ctx.start_time_ns)/g' serval-server/h1/server.zig

# serval-tls/stream.zig
echo "Fixing serval-tls/stream.zig..."
sed -i 's/std\.time\.ns_per_s/time.ns_per_s/g' serval-tls/stream.zig

# serval-metrics/stats.zig
echo "Fixing serval-metrics/stats.zig..."
sed -i 's/std\.time\.ns_per_s/time.ns_per_s/g' serval-metrics/stats.zig
sed -i 's/std\.time\.ns_per_ms/time.ns_per_ms/g' serval-metrics/stats.zig

# serval-metrics/metrics.zig
echo "Fixing serval-metrics/metrics.zig..."
sed -i 's/std\.time\.ns_per_ms/time.ns_per_ms/g' serval-metrics/metrics.zig

# serval-otel/processor.zig
echo "Fixing serval-otel/processor.zig..."
sed -i 's/std\.time\.ns_per_ms/time.ns_per_ms/g' serval-otel/processor.zig
# Fix nanosleep to use time.sleep
sed -i 's/std\.posix\.nanosleep(0, 150 \* time\.ns_per_ms);/time.sleep(time.millisToNanos(150));/g' serval-otel/processor.zig

# serval-net/dns.zig
echo "Fixing serval-net/dns.zig..."
sed -i 's/std\.time\.ns_per_s/time.ns_per_s/g' serval-net/dns.zig

# -----------------------------------------------------------------------------
# Part 2: examples/ - need @import("serval-core") or @import("serval")
# -----------------------------------------------------------------------------

echo "Fixing examples/dns_test.zig..."
sed -i 's/std\.time\.ns_per_s/time.ns_per_s/g' examples/dns_test.zig

echo "Fixing examples/llm_streaming.zig..."
sed -i 's/std\.time\.ns_per_ms/time.ns_per_ms/g' examples/llm_streaming.zig

echo "Fixing examples/router/config_storage.zig..."
sed -i 's/std\.time\.ns_per_ms/time.ns_per_ms/g' examples/router/config_storage.zig
sed -i 's/std\.time\.ns_per_s/time.ns_per_s/g' examples/router/config_storage.zig

echo "Fixing examples/gateway/main.zig..."
sed -i 's/std\.time\.ns_per_s/time.ns_per_s/g' examples/gateway/main.zig

echo "Fixing examples/gateway/controller/routerclient/client.zig..."
sed -i 's/std\.time\.ns_per_ms/time.ns_per_ms/g' examples/gateway/controller/routerclient/client.zig
sed -i 's/std\.time\.ns_per_s/time.ns_per_s/g' examples/gateway/controller/routerclient/client.zig

echo "Fixing examples/gateway/controller/status/manager.zig..."
sed -i 's/std\.time\.ns_per_s/time.ns_per_s/g' examples/gateway/controller/status/manager.zig

echo ""
echo "=== Done! Now verify with: zig build ==="
echo ""
echo "NOTE: Some files may need 'const time = ...' import added manually."
echo "Check the following files for missing imports:"
rg -l 'time\.(ns_per_s|ns_per_ms|secondsToNanos|millisToNanos)' --glob '*.zig' | while read f; do
    if ! grep -q 'const time = ' "$f" && ! grep -q '@import.*time' "$f"; then
        echo "  NEEDS IMPORT: $f"
    fi
done
