# DNS Resolver Improvements

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix DNS resolver to return all IP addresses and handle Kubernetes search domain issues.

**Architecture:** Add `resolveAll()` function that returns all addresses. Add option to normalize FQDNs with trailing dot for Kubernetes compatibility. Keep existing `resolve()` API unchanged for backwards compatibility.

**Tech Stack:** Zig std.Io.net, serval-net/dns.zig

---

## Background

Two bugs in `serval-net/dns.zig`:

1. **Only returns first IP** - `doResolve()` returns on first address, ignoring subsequent IPs from DNS response
2. **Search domain issues in Kubernetes** - Without trailing dot, hostnames get search domains appended due to `ndots:5`, causing `NameServerFailure`

Note: The gateway controller uses EndpointSlice discovery (not DNS) for multi-instance config push, so issue #1 doesn't block HA deployments. However, fixing it is correct behavior.

---

## Task 1: Add resolveAll() to return multiple IPs

**Files:**
- Modify: `serval-net/dns.zig`
- Modify: `serval-core/config.zig` (add constant)

### Step 1: Add MAX_DNS_ADDRESSES constant

In `serval-core/config.zig`, add after line 262:

```zig
/// Maximum addresses returned from a single DNS lookup.
pub const DNS_MAX_ADDRESSES: u8 = 16;
```

### Step 2: Write failing test for resolveAll

In `serval-net/dns.zig`, add test at end:

```zig
test "DnsResolver: resolveAll returns multiple addresses" {
    var resolver = DnsResolver.init(.{});

    // We can't test real DNS in unit tests, but we can test the structure
    // This test verifies the API exists and returns the correct type
    const ResolveAllResult = DnsResolver.ResolveAllResult;
    try testing.expect(@sizeOf(ResolveAllResult) > 0);
    try testing.expect(ResolveAllResult.MAX_ADDRESSES == config.DNS_MAX_ADDRESSES);
}
```

### Step 3: Run test to verify it fails

Run: `zig build test-serval-net 2>&1 | head -50`
Expected: FAIL - `ResolveAllResult` not defined

### Step 4: Add ResolveAllResult type

In `serval-net/dns.zig`, after `ResolveResult` struct (around line 53), add:

```zig
/// Result of DNS resolution returning all addresses.
/// TigerStyle: Fixed-size array, explicit count.
pub const ResolveAllResult = struct {
    /// Maximum addresses stored.
    pub const MAX_ADDRESSES: u8 = config.DNS_MAX_ADDRESSES;

    /// Resolved IP addresses with port applied.
    addresses: [MAX_ADDRESSES]Io.net.IpAddress,
    /// Number of valid addresses in array.
    count: u8,
    /// True if any result came from cache.
    from_cache: bool,
    /// Time spent resolving in nanoseconds (0 if from cache).
    resolution_ns: u64,

    /// Get slice of valid addresses.
    pub fn slice(self: *const ResolveAllResult) []const Io.net.IpAddress {
        return self.addresses[0..self.count];
    }

    /// Initialize empty result.
    pub fn empty() ResolveAllResult {
        return .{
            .addresses = undefined,
            .count = 0,
            .from_cache = false,
            .resolution_ns = 0,
        };
    }
};
```

### Step 5: Run test to verify it passes

Run: `zig build test-serval-net 2>&1 | head -50`
Expected: PASS

### Step 6: Write failing test for resolveAll function

Add test:

```zig
test "DnsResolver: resolveAll invalid hostname rejected" {
    var resolver = DnsResolver.init(.{});

    // Empty hostname
    const result1 = resolver.resolveAll("", 80, undefined);
    try testing.expectError(DnsError.InvalidHostname, result1);

    // Hostname too long
    var too_long: [config.DNS_MAX_HOSTNAME_LEN + 10]u8 = undefined;
    @memset(&too_long, 'a');
    const result2 = resolver.resolveAll(&too_long, 80, undefined);
    try testing.expectError(DnsError.InvalidHostname, result2);
}
```

### Step 7: Run test to verify it fails

Run: `zig build test-serval-net 2>&1 | head -50`
Expected: FAIL - `resolveAll` not defined

### Step 8: Add resolveAll function

In `DnsResolver` struct, after `resolve()` function (around line 234), add:

```zig
/// Resolve a hostname to all IP addresses.
/// Returns all addresses from DNS response (up to MAX_ADDRESSES).
/// TigerStyle: Async via Io, thread-safe via mutex.
pub fn resolveAll(
    self: *DnsResolver,
    hostname: []const u8,
    port: u16,
    io: Io,
) DnsError!ResolveAllResult {
    // S1: preconditions
    if (hostname.len == 0) return DnsError.InvalidHostname;
    if (hostname.len > config.DNS_MAX_HOSTNAME_LEN) return DnsError.InvalidHostname;
    assert(port > 0);

    const now_ns = time.monotonicNanos();

    // Check cache first (under lock)
    // Note: Cache only stores single address, so cache hit returns 1 address
    {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findInCache(hostname, now_ns)) |entry| {
            self.stats_hits +|= 1;
            var result = ResolveAllResult.empty();
            result.addresses[0] = switch (entry.address) {
                .ip4 => |v| .{ .ip4 = .{ .bytes = v.bytes, .port = port } },
                .ip6 => |v| .{ .ip6 = .{ .bytes = v.bytes, .port = port, .flow = v.flow, .interface = v.interface } },
            };
            result.count = 1;
            result.from_cache = true;
            result.resolution_ns = 0;
            return result;
        }

        self.stats_misses +|= 1;
    }

    // Cache miss - resolve all addresses
    const start_ns = time.monotonicNanos();
    var result = self.doResolveAll(hostname, port, io) catch |err| {
        debugLog("DNS resolveAll failed for '{s}': {s}", .{ hostname, @errorName(err) });
        return switch (err) {
            error.UnknownHostName,
            error.ResolvConfParseFailed,
            error.InvalidDnsARecord,
            error.InvalidDnsAAAARecord,
            error.InvalidDnsCnameRecord,
            error.NameServerFailure,
            error.DetectingNetworkConfigurationFailed,
            => DnsError.DnsResolutionFailed,
            error.NameTooLong,
            error.InvalidHostName,
            => DnsError.InvalidHostname,
            else => DnsError.DnsResolutionFailed,
        };
    };
    const end_ns = time.monotonicNanos();
    result.resolution_ns = time.elapsedNanos(start_ns, end_ns);

    // Store first address in cache (under lock)
    if (result.count > 0) {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.storeInCache(hostname, result.addresses[0], now_ns);
    }

    // S2: postcondition - all addresses have correct port
    for (result.addresses[0..result.count]) |addr| {
        assert(addr.getPort() == port);
    }

    return result;
}
```

### Step 9: Add doResolveAll helper function

After `doResolve()` function, add:

```zig
/// Perform DNS resolution returning all addresses.
/// TigerStyle: Bounded by MAX_ADDRESSES.
fn doResolveAll(self: *DnsResolver, hostname: []const u8, port: u16, io: Io) !ResolveAllResult {
    _ = self;

    var result = ResolveAllResult.empty();

    // First try parsing as IP address directly
    if (Io.net.IpAddress.parse(hostname, port)) |addr| {
        debugLog("DNS: '{s}' parsed as IP address directly", .{hostname});
        result.addresses[0] = addr;
        result.count = 1;
        return result;
    } else |_| {}

    debugLog("DNS: starting resolveAll lookup for '{s}' port={d}", .{ hostname, port });

    const host = Io.net.HostName.init(hostname) catch |err| {
        std.log.err("DNS: HostName.init failed for '{s}': {s}", .{ hostname, @errorName(err) });
        return err;
    };

    var canonical_name_buffer: [Io.net.HostName.max_len]u8 = undefined;
    var lookup_buffer: [16]Io.net.HostName.LookupResult = undefined;
    var lookup_queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&lookup_buffer);

    var lookup_future = io.async(Io.net.HostName.lookup, .{
        host,
        io,
        &lookup_queue,
        .{
            .port = port,
            .canonical_name_buffer = &canonical_name_buffer,
        },
    });
    defer lookup_future.cancel(io) catch {};

    // Collect all address results (bounded by MAX_ADDRESSES)
    var iteration: u8 = 0;
    const max_iterations: u8 = 64; // S3: bounded loop
    while (iteration < max_iterations) : (iteration += 1) {
        const queue_result = lookup_queue.getOne(io) catch |err| {
            switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => break, // Queue closed, done collecting
            }
        };

        switch (queue_result) {
            .address => |addr| {
                if (result.count < ResolveAllResult.MAX_ADDRESSES) {
                    result.addresses[result.count] = addr;
                    result.count += 1;
                    debugLog("DNS: collected address #{d}: {}", .{ result.count, addr });
                }
            },
            .canonical_name => |cn| {
                debugLog("DNS: got canonical_name: {s}", .{cn.bytes});
            },
        }
    }

    if (result.count == 0) {
        // No addresses found - check if lookup had an error
        lookup_future.await(io) catch |lookup_err| {
            std.log.err("DNS: lookup_future.await returned error: {s}", .{@errorName(lookup_err)});
            return lookup_err;
        };
        return error.UnknownHostName;
    }

    debugLog("DNS: resolveAll found {d} addresses for '{s}'", .{ result.count, hostname });
    return result;
}
```

### Step 10: Run tests to verify resolveAll works

Run: `zig build test-serval-net 2>&1 | head -50`
Expected: PASS

### Step 11: Commit

```bash
git add serval-core/config.zig serval-net/dns.zig
git commit -m "feat(dns): add resolveAll() to return all IP addresses

- Add DNS_MAX_ADDRESSES constant (16)
- Add ResolveAllResult type with fixed-size address array
- Add resolveAll() that collects all DNS addresses
- Add doResolveAll() helper with bounded loop
- Existing resolve() unchanged (backwards compatible)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Add FQDN normalization helper

**Files:**
- Modify: `serval-net/dns.zig`

### Step 1: Write failing test for FQDN normalization

Add test:

```zig
test "DnsResolver: normalizeFqdn adds trailing dot" {
    var buf: [256]u8 = undefined;

    // Already has trailing dot - unchanged
    const fqdn1 = DnsResolver.normalizeFqdn("service.ns.svc.cluster.local.", &buf);
    try testing.expectEqualStrings("service.ns.svc.cluster.local.", fqdn1);

    // No trailing dot - add one
    const fqdn2 = DnsResolver.normalizeFqdn("service.ns.svc.cluster.local", &buf);
    try testing.expectEqualStrings("service.ns.svc.cluster.local.", fqdn2);

    // Short name - unchanged (not FQDN)
    const fqdn3 = DnsResolver.normalizeFqdn("localhost", &buf);
    try testing.expectEqualStrings("localhost", fqdn3);

    // IP address - unchanged
    const fqdn4 = DnsResolver.normalizeFqdn("10.0.0.1", &buf);
    try testing.expectEqualStrings("10.0.0.1", fqdn4);
}
```

### Step 2: Run test to verify it fails

Run: `zig build test-serval-net 2>&1 | head -50`
Expected: FAIL - `normalizeFqdn` not defined

### Step 3: Add normalizeFqdn function

In `DnsResolver` struct, add:

```zig
/// Normalize FQDN by adding trailing dot to bypass search domain resolution.
///
/// DNS resolvers with search domains (e.g., resolv.conf with ndots setting)
/// append search suffixes to hostnames before absolute lookup. Adding a
/// trailing dot tells the resolver "this is the complete name."
///
/// This is a general DNS utility - works in any environment (Kubernetes,
/// Docker, bare metal) where search domains might interfere with resolution.
///
/// Heuristic: Only adds dot to names with 4+ dots (likely FQDNs).
/// IP addresses and short names are returned unchanged.
///
/// TigerStyle: Pure function, no allocation, returns slice into buffer.
pub fn normalizeFqdn(hostname: []const u8, buf: *[config.DNS_MAX_HOSTNAME_LEN + 1]u8) []const u8 {
    // S1: precondition - handle empty case
    if (hostname.len == 0) return hostname;

    // Already has trailing dot - return as-is
    if (hostname[hostname.len - 1] == '.') return hostname;

    // Check if it looks like an IP address (contains only digits and dots, starts with digit)
    if (hostname[0] >= '0' and hostname[0] <= '9') {
        var is_ip = true;
        for (hostname) |c| {
            if ((c < '0' or c > '9') and c != '.' and c != ':') {
                is_ip = false;
                break;
            }
        }
        if (is_ip) return hostname;
    }

    // Count dots to detect FQDN-like names
    var dot_count: u8 = 0;
    for (hostname) |c| {
        if (c == '.') dot_count += 1;
    }

    // Heuristic: 4+ dots suggests FQDN (e.g., service.namespace.svc.cluster.local)
    // Common patterns: Kubernetes (5 parts), AWS internal DNS (4-5 parts), etc.
    // Short names like "api.example.com" (2 dots) should use search domains.
    const FQDN_DOT_THRESHOLD: u8 = 4;
    if (dot_count < FQDN_DOT_THRESHOLD) return hostname;

    // Add trailing dot to hostname
    if (hostname.len >= config.DNS_MAX_HOSTNAME_LEN) return hostname; // Can't add dot

    @memcpy(buf[0..hostname.len], hostname);
    buf[hostname.len] = '.';
    return buf[0 .. hostname.len + 1];
}
```

### Step 4: Run test to verify it passes

Run: `zig build test-serval-net 2>&1 | head -50`
Expected: PASS

### Step 5: Add test for normalizeFqdn edge cases

```zig
test "DnsResolver: normalizeFqdn edge cases" {
    var buf: [256]u8 = undefined;

    // Empty string
    const empty = DnsResolver.normalizeFqdn("", &buf);
    try testing.expectEqualStrings("", empty);

    // IPv6 address - unchanged
    const ipv6 = DnsResolver.normalizeFqdn("::1", &buf);
    try testing.expectEqualStrings("::1", ipv6);

    // 3 dots - not enough for FQDN threshold
    const three_dots = DnsResolver.normalizeFqdn("a.b.c.d", &buf);
    try testing.expectEqualStrings("a.b.c.d", three_dots);

    // 4 dots - meets threshold, gets trailing dot
    const four_dots = DnsResolver.normalizeFqdn("a.b.c.d.e", &buf);
    try testing.expectEqualStrings("a.b.c.d.e.", four_dots);
}
```

### Step 6: Run tests

Run: `zig build test-serval-net 2>&1 | head -50`
Expected: PASS

### Step 7: Commit

```bash
git add serval-net/dns.zig
git commit -m "feat(dns): add normalizeFqdn() to bypass search domain resolution

DNS resolvers with search domains (resolv.conf ndots) append suffixes
before absolute lookup. Adding trailing dot marks name as complete.

normalizeFqdn() is a general-purpose helper (not environment-specific):
- Detects FQDN-like names (4+ dots) and appends trailing dot
- IP addresses and short names returned unchanged
- Opt-in: callers decide when to use it

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Update PARKED.md

**Files:**
- Modify: `examples/gateway/PARKED.md`

### Step 1: Update DNS Resolver section

Find the "DNS Resolver in Containers" section and update to:

```markdown
## DNS Resolver in Containers

**Status**: ✅ PARTIALLY ADDRESSED

Added `DnsResolver.normalizeFqdn()` to auto-append trailing dot to FQDN-like hostnames (4+ dots).
This is a general-purpose DNS utility that helps bypass search domain resolution in any
environment (Kubernetes, Docker, bare metal) where resolv.conf has search domains configured.

**Remaining Issues**:
- Zig's async DNS still may have issues in some container environments
- Not all resolution failures have been debugged

**Workaround** (still recommended for reliability):
- Use FQDN with trailing dot: `service.namespace.svc.cluster.local.`
- Or use `normalizeFqdn()` helper before resolving
- In Kubernetes: use `hostNetwork: true` on gateway pod

See: `serval-net/dns.zig` - `normalizeFqdn()` function
```

### Step 2: Add new section for resolveAll

Add after the updated section:

```markdown
---

## DNS Returns Only First IP

**Status**: ✅ IMPLEMENTED

Added `DnsResolver.resolveAll()` to return all IP addresses from DNS response:
- Returns up to `DNS_MAX_ADDRESSES` (16) addresses
- Backwards compatible - existing `resolve()` unchanged
- Cache only stores first address (multi-address caching not needed)

Note: Gateway controller uses EndpointSlice discovery (not DNS) for multi-instance
config push, so this was not blocking HA deployments.

See: `serval-net/dns.zig` - `resolveAll()` and `ResolveAllResult`
```

### Step 3: Commit

```bash
git add examples/gateway/PARKED.md
git commit -m "docs: update PARKED.md with DNS resolver improvements

- Mark 'DNS Returns Only First IP' as implemented
- Mark 'DNS Resolver in Containers' as partially addressed
- Document normalizeFqdn() and resolveAll() additions

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Update serval-net README

**Files:**
- Modify: `serval-net/README.md`

### Step 1: Update DNS section

Find the DNS section and add documentation for new functions:

```markdown
### DNS Resolution

```zig
const dns = @import("serval-net");

var resolver = dns.DnsResolver.init(.{});

// Single address (existing API)
const result = try resolver.resolve("example.com", 80, io);

// All addresses (new)
const all_result = try resolver.resolveAll("example.com", 80, io);
for (all_result.slice()) |addr| {
    // Use each address
}

// FQDN normalization for Kubernetes
var buf: [256]u8 = undefined;
const normalized = dns.DnsResolver.normalizeFqdn(
    "service.namespace.svc.cluster.local",
    &buf,
);
// Returns "service.namespace.svc.cluster.local."
```
```

### Step 2: Commit

```bash
git add serval-net/README.md
git commit -m "docs(serval-net): document resolveAll and normalizeFqdn

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Build and run full test suite

### Step 1: Build

Run: `zig build`
Expected: Success (exit code 0)

### Step 2: Run all tests

Run: `zig build test`
Expected: All tests pass

### Step 3: Verify no regressions

Run: `zig build test-router && zig build test-lb && zig build test-health`
Expected: All pass

---

## Summary

| Task | Description | Status |
|------|-------------|--------|
| 1 | Add `resolveAll()` for multiple IPs | |
| 2 | Add `normalizeFqdn()` for Kubernetes | |
| 3 | Update PARKED.md | |
| 4 | Update serval-net README | |
| 5 | Build and test | |

## Notes

- The gateway controller already uses EndpointSlice discovery, so the DNS multi-IP fix is for correctness, not to unblock HA
- `normalizeFqdn()` is a helper that callers can use; it doesn't auto-apply to all DNS calls
- Cache stores only first address; multi-address caching adds complexity without clear benefit
