// serval-net/dns.zig
//! DNS Resolution with TTL Caching
//!
//! Async hostname resolution with fixed-size cache.
//! TigerStyle: Zero allocation after init, bounded cache, explicit timing.
//!
//! Design:
//! - Fixed-size cache array (no runtime allocation)
//! - TTL-based expiration using monotonic time
//! - Thread-safe via mutex
//! - Eviction: invalid first, then oldest expired, then oldest valid
//! - IPv4 and IPv6 support via Zig std.Io.net

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const config = @import("serval-core").config;
const time = @import("serval-core").time;

// =============================================================================
// Errors
// =============================================================================

/// DNS resolution errors.
/// TigerStyle: Explicit error set, no catch {}.
pub const DnsError = error{
    /// Hostname resolution failed (DNS lookup error, no records found).
    DnsResolutionFailed,
    /// Resolution timed out before completing.
    DnsTimeout,
    /// Hostname is empty or exceeds maximum length.
    InvalidHostname,
    /// Cache is full and no entries can be evicted (should not occur with LRU).
    CacheFull,
};

// =============================================================================
// Result Types
// =============================================================================

/// Result of DNS resolution.
/// TigerStyle: Explicit struct, includes timing and cache status.
pub const ResolveResult = struct {
    /// Resolved IP address with port applied.
    address: Io.net.IpAddress,
    /// True if result came from cache, false if resolved.
    from_cache: bool,
    /// Time spent resolving in nanoseconds (0 if from cache).
    resolution_ns: u64,
};

// =============================================================================
// Configuration
// =============================================================================

/// DNS resolver configuration.
/// TigerStyle: Explicit defaults, units in names.
pub const DnsConfig = struct {
    /// TTL for cached entries in nanoseconds.
    ttl_ns: u64 = config.DNS_DEFAULT_TTL_NS,
    /// Resolution timeout in nanoseconds (not yet implemented - placeholder).
    timeout_ns: u64 = config.DNS_TIMEOUT_NS,
};

// =============================================================================
// Cache Entry
// =============================================================================

/// Single cache entry for a hostname -> address mapping.
/// TigerStyle: Fixed-size, no pointers to external memory.
const CacheEntry = struct {
    /// Hostname stored inline (fixed buffer).
    hostname: [config.DNS_MAX_HOSTNAME_LEN]u8,
    /// Actual length of hostname (0 if empty).
    hostname_len: u8,
    /// Resolved IP address.
    address: Io.net.IpAddress,
    /// Monotonic time when this entry expires.
    expires_ns: u64,
    /// True if entry contains valid data.
    valid: bool,

    /// Check if entry has expired.
    /// TigerStyle: Pure function, explicit comparison.
    pub fn isExpired(self: *const CacheEntry, now_ns: u64) bool {
        // S1: precondition - entry must be valid
        assert(self.valid);
        return now_ns >= self.expires_ns;
    }

    /// Check if entry matches the given hostname.
    /// TigerStyle: Returns false for invalid entries.
    pub fn matches(self: *const CacheEntry, hostname: []const u8) bool {
        if (!self.valid) return false;
        if (self.hostname_len != hostname.len) return false;
        return std.mem.eql(u8, self.hostname[0..self.hostname_len], hostname);
    }

    /// Initialize an empty (invalid) entry.
    /// TigerStyle: Explicit initialization, no undefined.
    pub fn empty() CacheEntry {
        return .{
            .hostname = std.mem.zeroes([config.DNS_MAX_HOSTNAME_LEN]u8),
            .hostname_len = 0,
            .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
            .expires_ns = 0,
            .valid = false,
        };
    }
};

// =============================================================================
// DNS Resolver
// =============================================================================

/// Thread-safe DNS resolver with TTL caching.
/// TigerStyle: Fixed-size cache, no runtime allocation.
pub const DnsResolver = struct {
    /// Fixed-size cache array.
    cache: [config.DNS_MAX_CACHE_ENTRIES]CacheEntry,
    /// Resolver configuration.
    cfg: DnsConfig,
    /// Mutex for thread safety.
    mutex: std.Thread.Mutex,
    /// Statistics: cache hits.
    stats_hits: u64,
    /// Statistics: cache misses.
    stats_misses: u64,

    /// Initialize a new DNS resolver.
    /// TigerStyle: Returns initialized struct, no allocation.
    pub fn init(dns_config: DnsConfig) DnsResolver {
        // S1: precondition - TTL must be positive
        assert(dns_config.ttl_ns > 0);
        // S1: precondition - timeout must be positive
        assert(dns_config.timeout_ns > 0);

        var resolver: DnsResolver = .{
            .cache = undefined,
            .cfg = dns_config,
            .mutex = .{},
            .stats_hits = 0,
            .stats_misses = 0,
        };

        // Initialize all cache entries as empty
        for (&resolver.cache) |*entry| {
            entry.* = CacheEntry.empty();
        }

        return resolver;
    }

    /// Resolve a hostname to an IP address.
    /// Returns cached result if available and not expired.
    /// TigerStyle: Async via Io, thread-safe via mutex.
    pub fn resolve(
        self: *DnsResolver,
        hostname: []const u8,
        port: u16,
        io: Io,
    ) DnsError!ResolveResult {
        // S1: preconditions
        if (hostname.len == 0) return DnsError.InvalidHostname;
        if (hostname.len > config.DNS_MAX_HOSTNAME_LEN) return DnsError.InvalidHostname;
        assert(port > 0);

        const now_ns = time.monotonicNanos();

        // Check cache first (under lock)
        {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.findInCache(hostname, now_ns)) |entry| {
                self.stats_hits +|= 1; // S4: saturating add to prevent overflow
                // Copy address and update port based on variant
                const result_addr: Io.net.IpAddress = switch (entry.address) {
                    .ip4 => |v| .{ .ip4 = .{ .bytes = v.bytes, .port = port } },
                    .ip6 => |v| .{ .ip6 = .{ .bytes = v.bytes, .port = port, .flow = v.flow, .interface = v.interface } },
                };
                return .{
                    .address = result_addr,
                    .from_cache = true,
                    .resolution_ns = 0,
                };
            }

            self.stats_misses +|= 1; // S4: saturating add
        }

        // Cache miss - resolve (outside lock to avoid blocking other threads)
        const start_ns = time.monotonicNanos();
        const address = self.doResolve(hostname, port, io) catch |err| {
            // Map HostName errors to DnsError
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
        const elapsed_ns = time.elapsedNanos(start_ns, end_ns);

        // Store in cache (under lock)
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.storeInCache(hostname, address, now_ns);
        }

        // S2: postcondition - returned address has correct port
        assert(address.getPort() == port);

        return .{
            .address = address,
            .from_cache = false,
            .resolution_ns = elapsed_ns,
        };
    }

    /// Invalidate a cached entry for a hostname.
    /// TigerStyle: Thread-safe, no error if not found.
    pub fn invalidate(self: *DnsResolver, hostname: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (&self.cache) |*entry| {
            if (entry.matches(hostname)) {
                entry.valid = false;
                return;
            }
        }
    }

    /// Invalidate all cached entries.
    /// TigerStyle: Thread-safe, clears entire cache.
    pub fn invalidateAll(self: *DnsResolver) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (&self.cache) |*entry| {
            entry.valid = false;
        }
    }

    /// Get cache statistics.
    /// TigerStyle: Read-only, returns copies.
    pub fn getStats(self: *DnsResolver) struct { hits: u64, misses: u64 } {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{ .hits = self.stats_hits, .misses = self.stats_misses };
    }

    /// Find a valid, non-expired entry in cache.
    /// Caller must hold mutex.
    /// TigerStyle: Returns pointer to avoid copy, const for safety.
    fn findInCache(self: *DnsResolver, hostname: []const u8, now_ns: u64) ?*const CacheEntry {
        for (&self.cache) |*entry| {
            if (entry.matches(hostname)) {
                if (!entry.isExpired(now_ns)) {
                    return entry;
                }
                // Entry exists but expired - will be replaced
                return null;
            }
        }
        return null;
    }

    /// Store a resolved address in cache.
    /// Eviction strategy: first invalid, then oldest expired, then oldest valid.
    /// Caller must hold mutex.
    /// TigerStyle: Bounded operation, always finds a slot.
    fn storeInCache(self: *DnsResolver, hostname: []const u8, address: Io.net.IpAddress, now_ns: u64) void {
        // S1: precondition - hostname fits in buffer
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);

        // Find slot: first invalid, then oldest (lowest expires_ns)
        var best_slot: ?*CacheEntry = null;
        var oldest_expires: u64 = std.math.maxInt(u64);

        for (&self.cache) |*entry| {
            // Prefer invalid slots
            if (!entry.valid) {
                best_slot = entry;
                break;
            }
            // Track oldest for eviction
            if (entry.expires_ns < oldest_expires) {
                oldest_expires = entry.expires_ns;
                best_slot = entry;
            }
        }

        // S2: postcondition - always find a slot (bounded array)
        const slot = best_slot orelse unreachable;

        // Store entry
        slot.valid = true;
        slot.hostname_len = @intCast(hostname.len);
        @memcpy(slot.hostname[0..hostname.len], hostname);
        // Zero remaining bytes for consistency
        @memset(slot.hostname[hostname.len..], 0);
        slot.address = address;
        slot.expires_ns = now_ns +| self.cfg.ttl_ns; // Saturating add for safety
    }

    /// Perform actual DNS resolution using Zig's async HostName API.
    /// TigerStyle: Wraps std library, handles errors explicitly.
    fn doResolve(self: *DnsResolver, hostname: []const u8, port: u16, io: Io) !Io.net.IpAddress {
        _ = self; // cfg.timeout_ns not yet used (future: pass to lookup)

        // First try parsing as IP address directly (common case for upstreams)
        if (Io.net.IpAddress.parse(hostname, port)) |addr| {
            return addr;
        } else |_| {
            // Not a numeric IP, proceed with DNS lookup
        }

        // Create HostName for DNS lookup
        const host = try Io.net.HostName.init(hostname);

        // Use lookup to get addresses
        var canonical_name_buffer: [Io.net.HostName.max_len]u8 = undefined;
        var lookup_buffer: [16]Io.net.HostName.LookupResult = undefined;
        var lookup_queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&lookup_buffer);

        // Start async lookup
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

        // Get first address result
        while (lookup_queue.getOne(io)) |result| {
            switch (result) {
                .address => |addr| return addr,
                .canonical_name => continue,
            }
        } else |err| {
            switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => {
                    // No addresses found - check if lookup had an error
                    lookup_future.await(io) catch |lookup_err| return lookup_err;
                    return error.UnknownHostName;
                },
            }
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "DnsResolver: init with default config" {
    const resolver = DnsResolver.init(.{});
    try testing.expectEqual(@as(u64, config.DNS_DEFAULT_TTL_NS), resolver.cfg.ttl_ns);
    try testing.expectEqual(@as(u64, config.DNS_TIMEOUT_NS), resolver.cfg.timeout_ns);
    try testing.expectEqual(@as(u64, 0), resolver.stats_hits);
    try testing.expectEqual(@as(u64, 0), resolver.stats_misses);
}

test "DnsResolver: init with custom config" {
    const custom_ttl: u64 = 30 * std.time.ns_per_s;
    const custom_timeout: u64 = 2 * std.time.ns_per_s;
    const resolver = DnsResolver.init(.{
        .ttl_ns = custom_ttl,
        .timeout_ns = custom_timeout,
    });
    try testing.expectEqual(custom_ttl, resolver.cfg.ttl_ns);
    try testing.expectEqual(custom_timeout, resolver.cfg.timeout_ns);
}

test "DnsResolver: cache starts empty" {
    const resolver = DnsResolver.init(.{});
    for (resolver.cache) |entry| {
        try testing.expect(!entry.valid);
    }
}

test "CacheEntry: empty initialization" {
    const entry = CacheEntry.empty();
    try testing.expect(!entry.valid);
    try testing.expectEqual(@as(u8, 0), entry.hostname_len);
    try testing.expectEqual(@as(u64, 0), entry.expires_ns);
}

test "CacheEntry: matches returns false for invalid entry" {
    const entry = CacheEntry.empty();
    try testing.expect(!entry.matches("example.com"));
}

test "CacheEntry: matches hostname correctly" {
    var entry = CacheEntry.empty();
    entry.valid = true;
    const hostname = "example.com";
    entry.hostname_len = @intCast(hostname.len);
    @memcpy(entry.hostname[0..hostname.len], hostname);

    try testing.expect(entry.matches("example.com"));
    try testing.expect(!entry.matches("example.org"));
    try testing.expect(!entry.matches("example.co"));
    try testing.expect(!entry.matches("example.com."));
}

test "CacheEntry: isExpired checks correctly" {
    var entry = CacheEntry.empty();
    entry.valid = true;
    entry.expires_ns = 1000;

    try testing.expect(!entry.isExpired(999));
    try testing.expect(entry.isExpired(1000));
    try testing.expect(entry.isExpired(1001));
}

test "DnsResolver: invalidate hostname" {
    var resolver = DnsResolver.init(.{});

    // Manually add an entry
    resolver.cache[0].valid = true;
    resolver.cache[0].hostname_len = 11;
    @memcpy(resolver.cache[0].hostname[0..11], "example.com");

    try testing.expect(resolver.cache[0].valid);

    // Invalidate it
    resolver.invalidate("example.com");
    try testing.expect(!resolver.cache[0].valid);
}

test "DnsResolver: invalidate non-existent hostname does not crash" {
    var resolver = DnsResolver.init(.{});
    resolver.invalidate("nonexistent.com");
    // Should not crash
}

test "DnsResolver: invalidateAll clears cache" {
    var resolver = DnsResolver.init(.{});

    // Add some entries
    resolver.cache[0].valid = true;
    resolver.cache[1].valid = true;
    resolver.cache[2].valid = true;

    resolver.invalidateAll();

    for (resolver.cache) |entry| {
        try testing.expect(!entry.valid);
    }
}

test "DnsResolver: getStats returns correct values" {
    var resolver = DnsResolver.init(.{});
    resolver.stats_hits = 42;
    resolver.stats_misses = 17;

    const stats = resolver.getStats();
    try testing.expectEqual(@as(u64, 42), stats.hits);
    try testing.expectEqual(@as(u64, 17), stats.misses);
}

test "DnsResolver: invalid hostname rejected" {
    var resolver = DnsResolver.init(.{});

    // Empty hostname
    const result1 = resolver.resolve("", 80, undefined);
    try testing.expectError(DnsError.InvalidHostname, result1);

    // Hostname too long (create a string longer than max)
    var too_long: [config.DNS_MAX_HOSTNAME_LEN + 10]u8 = undefined;
    @memset(&too_long, 'a');
    const result2 = resolver.resolve(&too_long, 80, undefined);
    try testing.expectError(DnsError.InvalidHostname, result2);
}

test "DnsResolver: storeInCache evicts oldest" {
    var resolver = DnsResolver.init(.{});
    const now_ns: u64 = 1000000;

    // Fill cache with entries, each with increasing expires_ns
    for (&resolver.cache, 0..) |*entry, i| {
        entry.valid = true;
        entry.expires_ns = now_ns + @as(u64, @intCast(i)) * 1000;
        const hostname = "host";
        entry.hostname_len = @intCast(hostname.len);
        @memcpy(entry.hostname[0..hostname.len], hostname);
    }

    // Mark first entry with specific data so we can identify it
    resolver.cache[0].hostname_len = 5;
    @memcpy(resolver.cache[0].hostname[0..5], "first");
    resolver.cache[0].expires_ns = now_ns; // Oldest

    // Store new entry - should evict the oldest (entry 0)
    const new_addr = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 8080 } };
    resolver.storeInCache("newhost", new_addr, now_ns + 100000);

    // Entry 0 should now have the new hostname
    try testing.expect(resolver.cache[0].matches("newhost"));
}

test "DnsResolver: storeInCache prefers invalid slots" {
    var resolver = DnsResolver.init(.{});
    const now_ns: u64 = 1000000;

    // Fill some entries but leave slot 5 invalid
    for (&resolver.cache, 0..) |*entry, i| {
        if (i == 5) continue; // Leave slot 5 invalid
        entry.valid = true;
        entry.expires_ns = now_ns + 10000;
        const hostname = "host";
        entry.hostname_len = @intCast(hostname.len);
        @memcpy(entry.hostname[0..hostname.len], hostname);
    }

    // Store new entry - should use invalid slot 5
    const new_addr = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 8080 } };
    resolver.storeInCache("newhost", new_addr, now_ns);

    try testing.expect(resolver.cache[5].matches("newhost"));
}

test "ResolveResult: struct layout" {
    // TigerStyle: Verify struct size is reasonable
    const size = @sizeOf(ResolveResult);
    try testing.expect(size < 64); // Should be small for stack allocation
}

test "DnsConfig: default values" {
    const cfg = DnsConfig{};
    try testing.expectEqual(config.DNS_DEFAULT_TTL_NS, cfg.ttl_ns);
    try testing.expectEqual(config.DNS_TIMEOUT_NS, cfg.timeout_ns);
}
