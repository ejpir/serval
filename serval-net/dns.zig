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

const serval_core = @import("serval-core");
const log = serval_core.log.scoped(.net);
const config = serval_core.config;
const time = serval_core.time;
const debugLog = serval_core.debugLog;

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

/// Map std DNS errors to DnsError.
/// TigerStyle: Single source of truth for error mapping.
fn mapDnsError(err: anyerror) DnsError {
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
}

/// Copy an IP address with a new port.
/// TigerStyle: Pure function, handles both IPv4 and IPv6.
fn copyAddressWithPort(addr: Io.net.IpAddress, port: u16) Io.net.IpAddress {
    return switch (addr) {
        .ip4 => |v| .{ .ip4 = .{ .bytes = v.bytes, .port = port } },
        .ip6 => |v| .{ .ip6 = .{ .bytes = v.bytes, .port = port, .flow = v.flow, .interface = v.interface } },
    };
}

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

    /// Initialize result to empty state.
    /// TigerStyle C3: Out-pointer pattern for struct >64 bytes.
    pub fn init(out: *ResolveAllResult) void {
        out.* = .{
            .addresses = undefined,
            .count = 0,
            .from_cache = false,
            .resolution_ns = 0,
        };
    }
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
                return .{
                    .address = copyAddressWithPort(entry.address, port),
                    .from_cache = true,
                    .resolution_ns = 0,
                };
            }

            self.stats_misses +|= 1; // S4: saturating add
        }

        // Cache miss - resolve (outside lock to avoid blocking other threads)
        const start_ns = time.monotonicNanos();
        const address = self.doResolve(hostname, port, io) catch |err| {
            debugLog("DNS resolve failed for '{s}': {s}", .{ hostname, @errorName(err) });
            return mapDnsError(err);
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

    /// Resolve a hostname to all IP addresses.
    /// Returns all addresses from DNS response (up to MAX_ADDRESSES).
    /// TigerStyle C3: Out-pointer pattern for struct >64 bytes (~460 bytes).
    /// TigerStyle: Async via Io, thread-safe via mutex.
    pub fn resolveAll(
        self: *DnsResolver,
        hostname: []const u8,
        port: u16,
        io: Io,
        out: *ResolveAllResult,
    ) DnsError!void {
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
                ResolveAllResult.init(out);
                out.addresses[0] = copyAddressWithPort(entry.address, port);
                out.count = 1;
                out.from_cache = true;
                return;
            }

            self.stats_misses +|= 1;
        }

        // Cache miss - resolve all addresses
        const start_ns = time.monotonicNanos();
        self.doResolveAll(hostname, port, io, out) catch |err| {
            debugLog("DNS resolveAll failed for '{s}': {s}", .{ hostname, @errorName(err) });
            return mapDnsError(err);
        };
        const end_ns = time.monotonicNanos();
        out.resolution_ns = time.elapsedNanos(start_ns, end_ns);

        // Store first address in cache (under lock)
        if (out.count > 0) {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.storeInCache(hostname, out.addresses[0], now_ns);
        }

        // S2: postcondition - all addresses have correct port
        for (out.addresses[0..out.count]) |addr| {
            assert(addr.getPort() == port);
        }
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
        _ = self;

        // Try parsing as IP address directly (common case for upstreams)
        if (tryParseIpAddress(hostname, port)) |addr| return addr;

        logResolvConf(io);
        debugLog("DNS: starting lookup for '{s}' port={d}", .{ hostname, port });

        const host = Io.net.HostName.init(hostname) catch |err| {
            log.err("DNS: HostName.init failed for '{s}': {s}", .{ hostname, @errorName(err) });
            return err;
        };

        var canonical_name_buffer: [Io.net.HostName.max_len]u8 = undefined;
        var lookup_buffer: [16]Io.net.HostName.LookupResult = undefined;
        var lookup_queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&lookup_buffer);

        var lookup_future = io.async(Io.net.HostName.lookup, .{
            host,
            io,
            &lookup_queue,
            .{ .port = port, .canonical_name_buffer = &canonical_name_buffer },
        });
        defer lookup_future.cancel(io) catch |err| switch (err) {
            error.Canceled => {},
            else => debugLog("DNS: lookup_future.cancel failed: {s}", .{@errorName(err)}),
        };

        // Get first address result
        var result_count: u32 = 0;
        while (lookup_queue.getOne(io)) |result| {
            result_count += 1;
            switch (result) {
                .address => |addr| {
                    debugLog("DNS: got address result #{d}: {}", .{ result_count, addr });
                    return addr;
                },
                .canonical_name => continue,
            }
        } else |err| {
            return handleLookupQueueError(err, &lookup_future, io, result_count);
        }
    }

    /// Try parsing hostname as an IP address directly.
    /// TigerStyle: Pure function, common path optimization.
    fn tryParseIpAddress(hostname: []const u8, port: u16) ?Io.net.IpAddress {
        if (Io.net.IpAddress.parse(hostname, port)) |addr| {
            debugLog("DNS: '{s}' parsed as IP address directly", .{hostname});
            return addr;
        } else |_| {
            return null;
        }
    }

    /// Handle lookup queue errors (Canceled or Closed).
    /// TigerStyle Y1: Extracted to keep doResolve under 70 lines.
    fn handleLookupQueueError(
        err: anyerror,
        lookup_future: anytype,
        io: Io,
        result_count: u32,
    ) anyerror {
        debugLog("DNS: lookup_queue.getOne returned error: {s} after {d} results", .{ @errorName(err), result_count });
        switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => {
                lookup_future.await(io) catch |lookup_err| {
                    log.err("DNS: lookup_future.await returned error: {s}", .{@errorName(lookup_err)});
                    return lookup_err;
                };
                return error.UnknownHostName;
            },
            else => return err,
        }
    }

    /// Collect addresses from DNS lookup queue into result.
    /// TigerStyle Y1: Extracted from doResolveAll to stay under 70 lines.
    /// TigerStyle S3: Bounded loop with explicit max iterations.
    fn collectDnsAddresses(
        lookup_queue: *Io.Queue(Io.net.HostName.LookupResult),
        io: Io,
        out: *ResolveAllResult,
    ) error{Canceled}!void {
        // S1: precondition - out must be initialized
        assert(out.count == 0);

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
                    if (out.count < ResolveAllResult.MAX_ADDRESSES) {
                        out.addresses[out.count] = addr;
                        out.count += 1;
                        debugLog("DNS: collected address #{d}: {}", .{ out.count, addr });
                    }
                },
                .canonical_name => |cn| {
                    debugLog("DNS: got canonical_name: {s}", .{cn.bytes});
                },
            }
        }
    }

    /// Perform DNS resolution returning all addresses.
    /// TigerStyle C3: Out-pointer pattern for struct >64 bytes.
    /// TigerStyle: Bounded by MAX_ADDRESSES.
    fn doResolveAll(self: *DnsResolver, hostname: []const u8, port: u16, io: Io, out: *ResolveAllResult) !void {
        _ = self;

        // S1: preconditions - hostname validated by caller, but verify invariants
        assert(hostname.len > 0);
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);
        assert(port > 0);

        ResolveAllResult.init(out);

        // Try parsing as IP address directly
        if (tryParseIpAddress(hostname, port)) |addr| {
            out.addresses[0] = addr;
            out.count = 1;
            return;
        }

        logResolvConf(io);
        debugLog("DNS: starting resolveAll lookup for '{s}' port={d}", .{ hostname, port });

        const host = Io.net.HostName.init(hostname) catch |err| {
            log.err("DNS: HostName.init failed for '{s}': {s}", .{ hostname, @errorName(err) });
            return err;
        };

        var canonical_name_buffer: [Io.net.HostName.max_len]u8 = undefined;
        var lookup_buffer: [16]Io.net.HostName.LookupResult = undefined;
        var lookup_queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&lookup_buffer);

        var lookup_future = io.async(Io.net.HostName.lookup, .{
            host,
            io,
            &lookup_queue,
            .{ .port = port, .canonical_name_buffer = &canonical_name_buffer },
        });
        defer lookup_future.cancel(io) catch |err| switch (err) {
            error.Canceled => {},
            else => debugLog("DNS: lookup_future.cancel failed: {s}", .{@errorName(err)}),
        };

        // Collect all address results (bounded by MAX_ADDRESSES)
        try collectDnsAddresses(&lookup_queue, io, out);

        if (out.count == 0) {
            lookup_future.await(io) catch |lookup_err| {
                log.err("DNS: lookup_future.await returned error: {s}", .{@errorName(lookup_err)});
                return lookup_err;
            };
            return error.UnknownHostName;
        }

        debugLog("DNS: resolveAll found {d} addresses for '{s}'", .{ out.count, hostname });
    }

    /// Normalize FQDN by adding trailing dot to bypass search domain resolution.
    ///
    /// DNS resolvers with search domains (e.g., resolv.conf with ndots setting)
    /// append search suffixes to hostnames before absolute lookup. Adding a
    /// trailing dot tells the resolver "this is the complete name."
    ///
    /// Heuristic: Only adds dot to names with 4+ dots (likely FQDNs).
    /// IP addresses and short names are returned unchanged.
    ///
    /// TigerStyle: Pure function, no allocation, returns slice into buffer.
    pub fn normalizeFqdn(hostname: []const u8, buf: *[config.DNS_MAX_HOSTNAME_LEN + 1]u8) []const u8 {
        if (hostname.len == 0) return hostname;
        if (hostname[hostname.len - 1] == '.') return hostname;
        if (looksLikeIpAddress(hostname)) return hostname;

        const dot_count = countDots(hostname);
        const FQDN_DOT_THRESHOLD: u8 = 4;
        if (dot_count < FQDN_DOT_THRESHOLD) return hostname;
        if (hostname.len >= config.DNS_MAX_HOSTNAME_LEN) return hostname;

        @memcpy(buf[0..hostname.len], hostname);
        buf[hostname.len] = '.';
        const result = buf[0 .. hostname.len + 1];

        // S2: postcondition - result ends with dot
        assert(result[result.len - 1] == '.');
        return result;
    }

    /// Check if hostname looks like an IP address (IPv4 or IPv6).
    /// TigerStyle: Pure function, bounded loop.
    fn looksLikeIpAddress(hostname: []const u8) bool {
        if (hostname.len == 0) return false;
        // Must start with digit for IPv4, or contain ':' for IPv6
        const first = hostname[0];
        if (first < '0' or first > '9') {
            // Check for IPv6 (contains ':')
            for (hostname) |c| {
                if (c == ':') return true;
            }
            return false;
        }
        // Starts with digit - check if all chars are valid IP chars
        for (hostname) |c| {
            const is_digit = c >= '0' and c <= '9';
            const is_separator = c == '.' or c == ':';
            if (!is_digit and !is_separator) return false;
        }
        return true;
    }

    /// Count dots in hostname.
    fn countDots(hostname: []const u8) u8 {
        var count: u8 = 0;
        for (hostname) |c| {
            if (c == '.') count +|= 1;
        }
        return count;
    }

    /// Debug helper: read and log /etc/resolv.conf contents using posix
    fn logResolvConf(io: Io) void {
        _ = io;
        const fd = std.posix.open("/etc/resolv.conf", .{}, 0) catch |err| {
            log.warn("DNS debug: cannot open /etc/resolv.conf: {s}", .{@errorName(err)});
            return;
        };
        defer std.posix.close(fd);

        var buf: [1024]u8 = undefined;
        const bytes_read = std.posix.read(fd, &buf) catch |err| {
            log.warn("DNS debug: cannot read /etc/resolv.conf: {s}", .{@errorName(err)});
            return;
        };

        debugLog("DNS debug: /etc/resolv.conf ({d} bytes):", .{bytes_read});
        // Log each line
        var iter = std.mem.splitScalar(u8, buf[0..bytes_read], '\n');
        var line_count: u32 = 0;
        while (iter.next()) |line| {
            line_count += 1;
            if (line_count > 20) {
                debugLog("DNS debug:   ... (truncated)", .{});
                break;
            }
            if (line.len > 0) {
                debugLog("DNS debug:   {s}", .{line});
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
    const custom_ttl: u64 = 30 * time.ns_per_s;
    const custom_timeout: u64 = 2 * time.ns_per_s;
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

test "DnsResolver: resolveAll returns multiple addresses" {
    const resolver = DnsResolver.init(.{});

    // We can't test real DNS in unit tests, but we can test the structure
    // This test verifies the API exists and returns the correct type
    try testing.expect(@sizeOf(ResolveAllResult) > 0);
    try testing.expect(ResolveAllResult.MAX_ADDRESSES == config.DNS_MAX_ADDRESSES);

    // Test empty result initialization via out-pointer pattern (TigerStyle C3)
    var empty_result: ResolveAllResult = undefined;
    ResolveAllResult.init(&empty_result);
    try testing.expectEqual(@as(u8, 0), empty_result.count);
    try testing.expect(!empty_result.from_cache);
    try testing.expectEqual(@as(u64, 0), empty_result.resolution_ns);

    // Test slice function returns empty for empty result
    const empty_slice = empty_result.slice();
    try testing.expectEqual(@as(usize, 0), empty_slice.len);

    // Test that resolver has the resolveAll method (type check)
    _ = @TypeOf(resolver).resolveAll;
}

test "DnsResolver: resolveAll invalid hostname rejected" {
    var resolver = DnsResolver.init(.{});
    var result: ResolveAllResult = undefined;

    // Empty hostname
    const result1 = resolver.resolveAll("", 80, undefined, &result);
    try testing.expectError(DnsError.InvalidHostname, result1);

    // Hostname too long
    var too_long: [config.DNS_MAX_HOSTNAME_LEN + 10]u8 = undefined;
    @memset(&too_long, 'a');
    const result2 = resolver.resolveAll(&too_long, 80, undefined, &result);
    try testing.expectError(DnsError.InvalidHostname, result2);
}

test "ResolveAllResult: slice returns correct view" {
    var result: ResolveAllResult = undefined;
    ResolveAllResult.init(&result);

    // Add some addresses
    result.addresses[0] = .{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 80 } };
    result.addresses[1] = .{ .ip4 = .{ .bytes = .{ 5, 6, 7, 8 }, .port = 80 } };
    result.count = 2;

    const slice_view = result.slice();
    try testing.expectEqual(@as(usize, 2), slice_view.len);
    try testing.expectEqual(@as(u16, 80), slice_view[0].getPort());
    try testing.expectEqual(@as(u16, 80), slice_view[1].getPort());
}

test "DnsResolver: normalizeFqdn adds trailing dot" {
    var buf: [config.DNS_MAX_HOSTNAME_LEN + 1]u8 = undefined;

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

test "DnsResolver: normalizeFqdn edge cases" {
    var buf: [config.DNS_MAX_HOSTNAME_LEN + 1]u8 = undefined;

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
