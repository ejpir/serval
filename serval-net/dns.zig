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
    /// DNS returned more addresses than MAX_ADDRESSES buffer can hold.
    /// TigerStyle S7: Make overflow explicit rather than silently dropping.
    AddressOverflow,
};

/// Map std DNS errors to DnsError.
/// TigerStyle: Single source of truth for error mapping.
fn map_dns_error(err: anyerror) DnsError {
    assert(@errorName(err).len > 0);
    return switch (err) {
        error.UnknownHostName,
        error.ResolvConfParseFailed,
        error.InvalidDnsARecord,
        error.InvalidDnsAAAARecord,
        error.InvalidDnsCnameRecord,
        error.NameServerFailure,
        error.DetectingNetworkConfigurationFailed,
        error.IterationLimitExceeded,
        => DnsError.DnsResolutionFailed,
        error.NameTooLong,
        error.InvalidHostName,
        => DnsError.InvalidHostname,
        error.AddressOverflow,
        => DnsError.AddressOverflow,
        else => DnsError.DnsResolutionFailed,
    };
}

/// Copy an IP address with a new port.
/// TigerStyle S5: Takes pointer since IpAddress is 32 bytes (>16 bytes).
/// TigerStyle: Pure function, handles both IPv4 and IPv6.
fn copy_address_with_port(addr: *const Io.net.IpAddress, port: u16) Io.net.IpAddress {
    assert(port > 0);
    return switch (addr.*) {
        .ip4 => |v| .{ .ip4 = .{ .bytes = v.bytes, .port = port } },
        .ip6 => |v| .{
            .ip6 = .{ .bytes = v.bytes, .port = port, .flow = v.flow, .interface = v.interface },
        },
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
        assert(self.count <= ResolveAllResult.MAX_ADDRESSES);
        return self.addresses[0..self.count];
    }

    /// Initialize result to empty state.
    /// TigerStyle C3: Out-pointer pattern for struct >64 bytes.
    pub fn init(out: *ResolveAllResult) void {
        assert(@intFromPtr(out) != 0);
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
};

// =============================================================================
// Cache Entry
// =============================================================================

/// Single cache entry for a hostname -> addresses mapping.
/// TigerStyle: Fixed-size, no pointers to external memory.
const CacheEntry = struct {
    /// Hostname stored inline (fixed buffer).
    hostname: [config.DNS_MAX_HOSTNAME_LEN]u8,
    /// Actual length of hostname (0 if empty).
    hostname_len: u8,
    /// Multiple addresses for failover. TigerStyle: Fixed-size array.
    addresses: [config.DNS_MAX_ADDRESSES]Io.net.IpAddress,
    /// Number of valid addresses (0 to DNS_MAX_ADDRESSES).
    address_count: u8,
    /// Rotating cursor for round-robin distribution in resolve().
    next_address_idx: u8,
    /// Monotonic time when this entry expires.
    expires_ns: u64,
    /// True if entry contains valid data.
    valid: bool,

    /// Check if entry has expired.
    /// TigerStyle: Pure function, explicit comparison.
    pub fn is_expired(self: *const CacheEntry, now_ns: u64) bool {
        // S1: precondition - entry must be valid
        assert(self.valid);
        return now_ns >= self.expires_ns;
    }

    /// Check if entry matches the given hostname.
    /// TigerStyle: Returns false for invalid entries.
    pub fn matches(self: *const CacheEntry, hostname: []const u8) bool {
        // S1: precondition - hostname within bounds
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);

        if (!self.valid) return false;
        if (self.hostname_len != hostname.len) return false;
        return std.mem.eql(u8, self.hostname[0..self.hostname_len], hostname);
    }

    /// Get next address using rotating cursor (round-robin).
    /// TigerStyle: Mutates cursor, returns const pointer to avoid copy.
    pub fn getNextAddress(self: *CacheEntry) ?*const Io.net.IpAddress {
        // S1: precondition - entry must be valid with addresses
        if (self.address_count == 0) return null;
        assert(self.next_address_idx < self.address_count);

        const idx = self.next_address_idx;
        self.next_address_idx = (self.next_address_idx + 1) % self.address_count;

        // S2: postcondition - cursor still valid
        assert(self.next_address_idx < self.address_count);
        return &self.addresses[idx];
    }

    /// Initialize an empty (invalid) entry via out-pointer.
    /// TigerStyle C3: Out-pointer pattern for struct >64 bytes.
    /// TigerStyle: Explicit initialization, no undefined.
    pub fn init_empty(out: *CacheEntry) void {
        // S1: precondition - out pointer valid
        assert(@intFromPtr(out) != 0);

        out.* = .{
            .hostname = std.mem.zeroes([config.DNS_MAX_HOSTNAME_LEN]u8),
            .hostname_len = 0,
            .addresses = undefined,
            .address_count = 0,
            .next_address_idx = 0,
            .expires_ns = 0,
            .valid = false,
        };

        // S1: postcondition - entry is invalid
        assert(!out.valid);
        assert(out.hostname_len == 0);
        assert(out.address_count == 0);
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
    resolver_config: DnsConfig,
    /// Mutex for thread safety.
    mutex: std.Io.Mutex,
    /// Statistics: cache hits.
    stats_hits: u64,
    /// Statistics: cache misses.
    stats_misses: u64,

    /// Initialize a new DNS resolver.
    /// TigerStyle C3: Out-pointer pattern for large struct.
    pub fn init(out: *DnsResolver, dns_config: DnsConfig) void {
        // S1: precondition - out must be valid
        assert(@intFromPtr(out) != 0);
        // S1: precondition - TTL must be positive
        assert(dns_config.ttl_ns > 0);

        out.* = .{
            .cache = undefined,
            .resolver_config = dns_config,
            .mutex = .init,
            .stats_hits = 0,
            .stats_misses = 0,
        };

        // Initialize all cache entries as empty
        // TigerStyle C3: Use out-pointer init for large struct
        for (&out.cache) |*entry| {
            CacheEntry.init_empty(entry);
        }
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
        assert(hostname.len > 0);
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);
        assert(port > 0);

        const now_ns = time.monotonicNanos();

        // Check cache first (under lock)
        {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);

            if (self.find_in_cache(hostname, now_ns)) |entry| {
                self.stats_hits +|= 1; // S4: saturating add to prevent overflow
                // Use rotating cursor for round-robin distribution across addresses
                const addr = entry.getNextAddress() orelse unreachable; // Valid entry has addresses
                return .{
                    .address = copy_address_with_port(addr, port),
                    .from_cache = true,
                    .resolution_ns = 0,
                };
            }

            self.stats_misses +|= 1; // S4: saturating add
        }

        // Cache miss - resolve (outside lock to avoid blocking other threads)
        const start_ns = time.monotonicNanos();
        const address = self.do_resolve(hostname, port, io) catch |err| {
            debugLog("DNS resolve failed for '{s}': {s}", .{ hostname, @errorName(err) });
            return map_dns_error(err);
        };
        const end_ns = time.monotonicNanos();
        const elapsed_ns = time.elapsedNanos(start_ns, end_ns);

        // Store in cache (under lock) - single address as slice
        {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);
            const addr_slice: []const Io.net.IpAddress = &[_]Io.net.IpAddress{address};
            self.store_in_cache(hostname, addr_slice, now_ns);
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
    pub fn resolve_all(
        self: *DnsResolver,
        hostname: []const u8,
        port: u16,
        io: Io,
        out: *ResolveAllResult,
    ) DnsError!void {
        // S1: preconditions
        if (hostname.len == 0) return DnsError.InvalidHostname;
        if (hostname.len > config.DNS_MAX_HOSTNAME_LEN) return DnsError.InvalidHostname;
        assert(hostname.len > 0);
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);
        assert(port > 0);
        assert(@intFromPtr(out) != 0);

        const now_ns = time.monotonicNanos();

        // Check cache first (under lock)
        // Cache stores multiple addresses for failover
        {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);

            if (self.find_in_cache(hostname, now_ns)) |entry| {
                self.stats_hits +|= 1;
                ResolveAllResult.init(out);
                // Copy all cached addresses with port applied
                for (0..entry.address_count) |i| {
                    out.addresses[i] = copy_address_with_port(&entry.addresses[i], port);
                }
                out.count = entry.address_count;
                out.from_cache = true;
                return;
            }

            self.stats_misses +|= 1;
        }

        // Cache miss - resolve all addresses
        const start_ns = time.monotonicNanos();
        self.do_resolve_all(hostname, port, io, out) catch |err| {
            debugLog("DNS resolve_all failed for '{s}': {s}", .{ hostname, @errorName(err) });
            return map_dns_error(err);
        };
        const end_ns = time.monotonicNanos();
        out.resolution_ns = time.elapsedNanos(start_ns, end_ns);

        // Store all addresses in cache (under lock)
        if (out.count > 0) {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);
            self.store_in_cache(hostname, out.addresses[0..out.count], now_ns);
        }

        // S2: postcondition - all addresses have correct port
        for (out.addresses[0..out.count]) |addr| {
            assert(addr.getPort() == port);
        }
    }

    /// Invalidate a cached entry for a hostname.
    /// TigerStyle: Thread-safe, no error if not found.
    pub fn invalidate(self: *DnsResolver, hostname: []const u8) void {
        assert(hostname.len > 0);
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        for (&self.cache) |*entry| {
            if (entry.matches(hostname)) {
                entry.valid = false;
                return;
            }
        }
    }

    /// Invalidate all cached entries.
    /// TigerStyle: Thread-safe, clears entire cache.
    pub fn invalidate_all(self: *DnsResolver) void {
        assert(config.DNS_MAX_CACHE_ENTRIES > 0);
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        for (&self.cache) |*entry| {
            entry.valid = false;
        }
    }

    /// Get cache statistics.
    /// TigerStyle: Read-only, returns copies.
    pub fn get_stats(self: *DnsResolver) struct { hits: u64, misses: u64 } {
        assert(@intFromPtr(self) != 0);
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        return .{ .hits = self.stats_hits, .misses = self.stats_misses };
    }

    /// Find a valid, non-expired entry in cache.
    /// Caller must hold mutex.
    /// TigerStyle: Returns mutable pointer to allow cursor update in getNextAddress().
    fn find_in_cache(self: *DnsResolver, hostname: []const u8, now_ns: u64) ?*CacheEntry {
        assert(hostname.len > 0);
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);
        assert(self.cache.len == config.DNS_MAX_CACHE_ENTRIES);
        for (&self.cache) |*entry| {
            if (entry.matches(hostname)) {
                if (!entry.is_expired(now_ns)) {
                    return entry;
                }
                // Entry exists but expired - will be replaced
                return null;
            }
        }
        return null;
    }

    /// Store resolved addresses in cache.
    /// Eviction strategy: first invalid, then oldest expired, then oldest valid.
    /// Caller must hold mutex.
    /// TigerStyle: Bounded operation, always finds a slot.
    fn store_in_cache(
        self: *DnsResolver,
        hostname: []const u8,
        addresses: []const Io.net.IpAddress,
        now_ns: u64,
    ) void {
        // S1: preconditions
        assert(hostname.len > 0);
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);
        assert(addresses.len > 0);
        assert(addresses.len <= config.DNS_MAX_ADDRESSES);

        var best_slot: ?*CacheEntry = null;
        var oldest_expires: u64 = std.math.maxInt(u64);

        // First pass: check if hostname already exists (overwrite in-place to prevent duplicates)
        for (&self.cache) |*entry| {
            if (entry.matches(hostname)) {
                best_slot = entry;
                break;
            }
        }

        // Second pass: find invalid or oldest slot if hostname not found
        if (best_slot == null) {
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
        }

        // S2: postcondition - always find a slot (bounded array)
        const slot = best_slot orelse unreachable;

        // Store entry
        slot.valid = true;
        slot.hostname_len = @intCast(hostname.len);
        @memcpy(slot.hostname[0..hostname.len], hostname);
        // Zero remaining bytes for consistency
        @memset(slot.hostname[hostname.len..], 0);

        // Store multiple addresses (capped at DNS_MAX_ADDRESSES)
        const count: u8 = @intCast(@min(addresses.len, config.DNS_MAX_ADDRESSES));
        for (0..count) |i| {
            slot.addresses[i] = addresses[i];
        }
        slot.address_count = count;
        slot.next_address_idx = 0; // Reset cursor on cache update

        // TigerStyle: Fail-safe on overflow - expire immediately rather than cache forever
        const ttl_result = @addWithOverflow(now_ns, self.resolver_config.ttl_ns);
        slot.expires_ns = if (ttl_result[1] != 0) now_ns else ttl_result[0];

        // S2: postcondition - slot is valid with addresses
        assert(slot.valid);
        assert(slot.address_count > 0);
        assert(slot.next_address_idx < slot.address_count);
    }

    /// Perform actual DNS resolution using Zig's async HostName API.
    /// TigerStyle: Wraps std library, handles errors explicitly.
    fn do_resolve(self: *DnsResolver, hostname: []const u8, port: u16, io: Io) !Io.net.IpAddress {
        assert(hostname.len > 0);
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);
        assert(port > 0);
        _ = self;

        // Try parsing as IP address directly (common case for upstreams)
        if (try_parse_ip_address(hostname, port)) |addr| return addr;

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
        const max_lookup_results: u32 = 256; // S3: bound lookup results
        var result_count: u32 = 0;
        while (result_count < max_lookup_results) : (result_count += 1) {
            const result = lookup_queue.getOne(io) catch |err| {
                return handle_lookup_queue_error(err, &lookup_future, io, result_count);
            };

            switch (result) {
                .address => |addr| {
                    debugLog("DNS: got address result #{d}: {}", .{ result_count + 1, addr });
                    return addr;
                },
                .canonical_name => continue,
            }
        }

        if (result_count >= max_lookup_results) return error.IterationLimitExceeded;
        return error.UnknownHostName;
    }

    /// Try parsing hostname as an IP address directly.
    /// TigerStyle S4: Log parse errors explicitly instead of swallowing.
    /// TigerStyle: Pure function, common path optimization.
    fn try_parse_ip_address(hostname: []const u8, port: u16) ?Io.net.IpAddress {
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);
        assert(port > 0);
        if (Io.net.IpAddress.parse(hostname, port)) |addr| {
            debugLog("DNS: '{s}' parsed as IP address directly", .{hostname});
            return addr;
        } else |err| {
            // S4: Log the error explicitly - this is expected for hostnames, debug level
            debugLog("DNS: IpAddress.parse failed for '{s}': {s}", .{ hostname, @errorName(err) });
            return null;
        }
    }

    /// Handle lookup queue errors (Canceled or Closed).
    /// TigerStyle Y1: Extracted to keep do_resolve under 70 lines.
    fn handle_lookup_queue_error(
        err: anyerror,
        lookup_future: anytype,
        io: Io,
        result_count: u32,
    ) anyerror {
        assert(@errorName(err).len > 0);
        debugLog(
            "DNS: lookup_queue.getOne error: {s} after {d} results",
            .{ @errorName(err), result_count },
        );
        switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => {
                lookup_future.await(io) catch |lookup_err| {
                    log.err("DNS: await error: {s}", .{@errorName(lookup_err)});
                    return lookup_err;
                };
                return error.UnknownHostName;
            },
            else => return err,
        }
    }

    /// Collect addresses from DNS lookup queue into result.
    /// TigerStyle Y1: Extracted from do_resolve_all to stay under 70 lines.
    /// TigerStyle S3: Bounded loop with explicit max iterations.
    /// TigerStyle S7: Returns AddressOverflow if DNS returns more addresses than buffer can hold.
    fn collect_dns_addresses(
        lookup_queue: *Io.Queue(Io.net.HostName.LookupResult),
        io: Io,
        out: *ResolveAllResult,
    ) error{ Canceled, IterationLimitExceeded, AddressOverflow }!void {
        // S1: precondition - out must be initialized
        assert(@intFromPtr(lookup_queue) != 0);
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
                    // S7: Fail explicitly if buffer is full rather than silently dropping addresses
                    if (out.count >= ResolveAllResult.MAX_ADDRESSES) {
                        debugLog(
                            "DNS: AddressOverflow - max {d} addresses",
                            .{ResolveAllResult.MAX_ADDRESSES},
                        );
                        return error.AddressOverflow;
                    }
                    out.addresses[out.count] = addr;
                    out.count += 1;
                    debugLog("DNS: collected address #{d}: {}", .{ out.count, addr });
                },
                .canonical_name => |cn| {
                    debugLog("DNS: got canonical_name: {s}", .{cn.bytes});
                },
            }
        }

        if (iteration >= max_iterations) return error.IterationLimitExceeded;
    }

    /// Perform DNS resolution returning all addresses.
    /// TigerStyle C3: Out-pointer pattern for struct >64 bytes.
    /// TigerStyle: Bounded by MAX_ADDRESSES.
    fn do_resolve_all(
        self: *DnsResolver,
        hostname: []const u8,
        port: u16,
        io: Io,
        out: *ResolveAllResult,
    ) !void {
        _ = self;

        // S1: preconditions - hostname validated by caller, but verify invariants
        assert(hostname.len > 0);
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);
        assert(port > 0);

        ResolveAllResult.init(out);

        // Try parsing as IP address directly
        if (try_parse_ip_address(hostname, port)) |addr| {
            out.addresses[0] = addr;
            out.count = 1;
            return;
        }

        debugLog("DNS: starting resolve_all lookup for '{s}' port={d}", .{ hostname, port });

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
        try collect_dns_addresses(&lookup_queue, io, out);

        if (out.count == 0) {
            lookup_future.await(io) catch |lookup_err| {
                log.err("DNS: lookup_future.await returned error: {s}", .{@errorName(lookup_err)});
                return lookup_err;
            };
            return error.UnknownHostName;
        }

        debugLog("DNS: resolve_all found {d} addresses for '{s}'", .{ out.count, hostname });
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
    /// Returns error.IterationLimitExceeded if bounded loop exceeded (fail-fast).
    pub fn normalize_fqdn(
        hostname: []const u8,
        buf: *[config.DNS_MAX_HOSTNAME_LEN + 1]u8,
    ) error{IterationLimitExceeded}![]const u8 {
        assert(@intFromPtr(buf) != 0);

        if (hostname.len == 0) return hostname;
        if (hostname.len >= config.DNS_MAX_HOSTNAME_LEN) return hostname;
        if (hostname[hostname.len - 1] == '.') return hostname;
        if (try looks_like_ip_address(hostname)) return hostname;

        const dot_count = try count_dots(hostname);
        const fqdn_dot_threshold: u8 = 4;
        if (dot_count < fqdn_dot_threshold) return hostname;

        @memcpy(buf[0..hostname.len], hostname);
        buf[hostname.len] = '.';
        const result = buf[0 .. hostname.len + 1];

        // S2: postcondition - result ends with dot
        assert(result[result.len - 1] == '.');
        return result;
    }

    /// Check if hostname is a valid IP address (IPv4 or IPv6).
    /// TigerStyle: Use actual parsing instead of heuristics to avoid false positives.
    fn looks_like_ip_address(hostname: []const u8) error{IterationLimitExceeded}!bool {
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);

        if (hostname.len == 0) return false;

        // Use actual IP parsing - port value doesn't matter for validity check
        if (Io.net.IpAddress.parse(hostname, 1)) |_| {
            return true;
        } else |_| {
            return false;
        }
    }

    /// Count dots in hostname.
    /// TigerStyle S4: Bounded loop with explicit max iterations.
    fn count_dots(hostname: []const u8) error{IterationLimitExceeded}!u8 {
        assert(hostname.len <= config.DNS_MAX_HOSTNAME_LEN);
        assert(hostname.len <= std.math.maxInt(u16));

        const host_len: u16 = @intCast(hostname.len);
        const max_iterations: u16 = host_len;
        var count: u8 = 0;
        var index: u16 = 0;
        var iterations: u16 = 0;
        while (index < host_len) : (index += 1) {
            iterations += 1;
            if (iterations > max_iterations) return error.IterationLimitExceeded;
            const ch = hostname[@intCast(index)];
            if (ch == '.') count +|= 1;
        }
        return count;
    }

    /// Debug helper: read and log /etc/resolv.conf contents using posix
    fn log_resolv_conf(io: Io) void {
        assert(config.DNS_MAX_HOSTNAME_LEN > 0);
        _ = io;

        const fd = std.posix.open("/etc/resolv.conf", .{ .ACCMODE = .RDONLY }, 0) catch |err| {
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
        // Log each line - TigerStyle S4: bounded loop with explicit max iterations
        const max_iterations_count: u32 = 20;
        var iter = std.mem.splitScalar(u8, buf[0..bytes_read], '\n');
        var iterations: u32 = 0;
        while (iter.next()) |line| {
            iterations += 1;
            if (iterations > max_iterations_count) {
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
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});
    try testing.expectEqual(@as(u64, config.DNS_DEFAULT_TTL_NS), resolver.resolver_config.ttl_ns);
    try testing.expectEqual(@as(u64, 0), resolver.stats_hits);
    try testing.expectEqual(@as(u64, 0), resolver.stats_misses);
}

test "DnsResolver: init with custom config" {
    const custom_ttl: u64 = 30 * time.ns_per_s;
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{
        .ttl_ns = custom_ttl,
    });
    try testing.expectEqual(custom_ttl, resolver.resolver_config.ttl_ns);
}

test "DnsResolver: cache starts empty" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});
    for (resolver.cache) |entry| {
        try testing.expect(!entry.valid);
    }
}

test "CacheEntry: init_empty initialization" {
    // TigerStyle C3: Out-pointer pattern for large struct
    var entry: CacheEntry = undefined;
    CacheEntry.init_empty(&entry);
    try testing.expect(!entry.valid);
    try testing.expectEqual(@as(u8, 0), entry.hostname_len);
    try testing.expectEqual(@as(u8, 0), entry.address_count);
    try testing.expectEqual(@as(u8, 0), entry.next_address_idx);
    try testing.expectEqual(@as(u64, 0), entry.expires_ns);
}

test "CacheEntry: matches returns false for invalid entry" {
    var entry: CacheEntry = undefined;
    CacheEntry.init_empty(&entry);
    try testing.expect(!entry.matches("example.com"));
}

test "CacheEntry: matches hostname correctly" {
    var entry: CacheEntry = undefined;
    CacheEntry.init_empty(&entry);
    entry.valid = true;
    const hostname = "example.com";
    entry.hostname_len = @intCast(hostname.len);
    @memcpy(entry.hostname[0..hostname.len], hostname);

    try testing.expect(entry.matches("example.com"));
    try testing.expect(!entry.matches("example.org"));
    try testing.expect(!entry.matches("example.co"));
    try testing.expect(!entry.matches("example.com."));
}

test "CacheEntry: is_expired checks correctly" {
    var entry: CacheEntry = undefined;
    CacheEntry.init_empty(&entry);
    entry.valid = true;
    entry.expires_ns = 1000;

    try testing.expect(!entry.is_expired(999));
    try testing.expect(entry.is_expired(1000));
    try testing.expect(entry.is_expired(1001));
}

test "DnsResolver: invalidate hostname" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

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
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});
    resolver.invalidate("nonexistent.com");
    // Should not crash
}

test "DnsResolver: invalidate_all clears cache" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

    // Add some entries
    resolver.cache[0].valid = true;
    resolver.cache[1].valid = true;
    resolver.cache[2].valid = true;

    resolver.invalidate_all();

    for (resolver.cache) |entry| {
        try testing.expect(!entry.valid);
    }
}

test "DnsResolver: get_stats returns correct values" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});
    resolver.stats_hits = 42;
    resolver.stats_misses = 17;

    const stats = resolver.get_stats();
    try testing.expectEqual(@as(u64, 42), stats.hits);
    try testing.expectEqual(@as(u64, 17), stats.misses);
}

test "DnsResolver: invalid hostname rejected" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

    // Empty hostname
    const result1 = resolver.resolve("", 80, undefined);
    try testing.expectError(DnsError.InvalidHostname, result1);

    // Hostname too long (create a string longer than max)
    var too_long: [config.DNS_MAX_HOSTNAME_LEN + 10]u8 = undefined;
    @memset(&too_long, 'a');
    const result2 = resolver.resolve(&too_long, 80, undefined);
    try testing.expectError(DnsError.InvalidHostname, result2);
}

test "DnsResolver: store_in_cache evicts oldest" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});
    const now_ns: u64 = 1000000;

    // Fill cache with entries, each with increasing expires_ns
    for (&resolver.cache, 0..) |*entry, i| {
        entry.valid = true;
        entry.expires_ns = now_ns + @as(u64, @intCast(i)) * 1000;
        const hostname = "host";
        entry.hostname_len = @intCast(hostname.len);
        @memcpy(entry.hostname[0..hostname.len], hostname);
        entry.addresses[0] = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
        entry.address_count = 1;
        entry.next_address_idx = 0;
    }

    // Mark first entry with specific data so we can identify it
    resolver.cache[0].hostname_len = 5;
    @memcpy(resolver.cache[0].hostname[0..5], "first");
    resolver.cache[0].expires_ns = now_ns; // Oldest

    // Store new entry - should evict the oldest (entry 0)
    const new_addr = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 8080 } };
    const addr_slice: []const Io.net.IpAddress = &[_]Io.net.IpAddress{new_addr};
    resolver.store_in_cache("newhost", addr_slice, now_ns + 100000);

    // Entry 0 should now have the new hostname
    try testing.expect(resolver.cache[0].matches("newhost"));
}

test "DnsResolver: store_in_cache prefers invalid slots" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});
    const now_ns: u64 = 1000000;

    // Fill some entries but leave slot 5 invalid
    for (&resolver.cache, 0..) |*entry, i| {
        if (i == 5) continue; // Leave slot 5 invalid
        entry.valid = true;
        entry.expires_ns = now_ns + 10000;
        const hostname = "host";
        entry.hostname_len = @intCast(hostname.len);
        @memcpy(entry.hostname[0..hostname.len], hostname);
        entry.addresses[0] = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
        entry.address_count = 1;
        entry.next_address_idx = 0;
    }

    // Store new entry - should use invalid slot 5
    const new_addr = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 8080 } };
    const addr_slice: []const Io.net.IpAddress = &[_]Io.net.IpAddress{new_addr};
    resolver.store_in_cache("newhost", addr_slice, now_ns);

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
}

test "DnsResolver: resolve_all returns multiple addresses" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

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

    // Test that resolver has the resolve_all method (type check)
    _ = @TypeOf(resolver).resolve_all;
}

test "DnsResolver: resolve_all invalid hostname rejected" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});
    var result: ResolveAllResult = undefined;

    // Empty hostname
    const result1 = resolver.resolve_all("", 80, undefined, &result);
    try testing.expectError(DnsError.InvalidHostname, result1);

    // Hostname too long
    var too_long: [config.DNS_MAX_HOSTNAME_LEN + 10]u8 = undefined;
    @memset(&too_long, 'a');
    const result2 = resolver.resolve_all(&too_long, 80, undefined, &result);
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

test "DnsResolver: normalize_fqdn adds trailing dot" {
    var buf: [config.DNS_MAX_HOSTNAME_LEN + 1]u8 = undefined;

    // Already has trailing dot - unchanged
    const fqdn1 = try DnsResolver.normalize_fqdn("service.ns.svc.cluster.local.", &buf);
    try testing.expectEqualStrings("service.ns.svc.cluster.local.", fqdn1);

    // No trailing dot - add one
    const fqdn2 = try DnsResolver.normalize_fqdn("service.ns.svc.cluster.local", &buf);
    try testing.expectEqualStrings("service.ns.svc.cluster.local.", fqdn2);

    // Short name - unchanged (not FQDN)
    const fqdn3 = try DnsResolver.normalize_fqdn("localhost", &buf);
    try testing.expectEqualStrings("localhost", fqdn3);

    // IP address - unchanged
    const fqdn4 = try DnsResolver.normalize_fqdn("10.0.0.1", &buf);
    try testing.expectEqualStrings("10.0.0.1", fqdn4);
}

test "DnsResolver: normalize_fqdn edge cases" {
    var buf: [config.DNS_MAX_HOSTNAME_LEN + 1]u8 = undefined;

    // Empty string
    const empty = try DnsResolver.normalize_fqdn("", &buf);
    try testing.expectEqualStrings("", empty);

    // IPv6 address - unchanged
    const ipv6 = try DnsResolver.normalize_fqdn("::1", &buf);
    try testing.expectEqualStrings("::1", ipv6);

    // 3 dots - not enough for FQDN threshold
    const three_dots = try DnsResolver.normalize_fqdn("a.b.c.d", &buf);
    try testing.expectEqualStrings("a.b.c.d", three_dots);

    // 4 dots - meets threshold, gets trailing dot
    const four_dots = try DnsResolver.normalize_fqdn("a.b.c.d.e", &buf);
    try testing.expectEqualStrings("a.b.c.d.e.", four_dots);
}

test "DnsResolver: normalize_fqdn boundary lengths" {
    var buf: [config.DNS_MAX_HOSTNAME_LEN + 1]u8 = undefined;

    // Build hostname at DNS_MAX_HOSTNAME_LEN - 1 with 4+ dots (FQDN threshold)
    // Pattern: "a.b.c.d." repeated + padding to reach len - 1
    // We need 4 dots minimum, so "a.b.c.d.e" base (9 chars, 4 dots)
    var hostname_max_minus_one: [config.DNS_MAX_HOSTNAME_LEN - 1]u8 = undefined;
    @memset(&hostname_max_minus_one, 'x');
    // Add dots to meet threshold: positions 1, 3, 5, 7 for "x.x.x.x.xxx..."
    hostname_max_minus_one[1] = '.';
    hostname_max_minus_one[3] = '.';
    hostname_max_minus_one[5] = '.';
    hostname_max_minus_one[7] = '.';

    const result_minus_one = try DnsResolver.normalize_fqdn(&hostname_max_minus_one, &buf);
    // Should append dot, resulting in DNS_MAX_HOSTNAME_LEN length
    try testing.expectEqual(config.DNS_MAX_HOSTNAME_LEN, result_minus_one.len);
    try testing.expectEqual(@as(u8, '.'), result_minus_one[result_minus_one.len - 1]);

    // Build hostname at exactly DNS_MAX_HOSTNAME_LEN with 4+ dots
    var hostname_max: [config.DNS_MAX_HOSTNAME_LEN]u8 = undefined;
    @memset(&hostname_max, 'x');
    hostname_max[1] = '.';
    hostname_max[3] = '.';
    hostname_max[5] = '.';
    hostname_max[7] = '.';

    const result_max = try DnsResolver.normalize_fqdn(&hostname_max, &buf);
    // Should NOT append (no room), return unchanged
    try testing.expectEqual(config.DNS_MAX_HOSTNAME_LEN, result_max.len);
    // Verify it's the original (last char is 'x', not '.')
    try testing.expectEqual(@as(u8, 'x'), result_max[result_max.len - 1]);
}

test "map_dns_error: maps IterationLimitExceeded to DnsResolutionFailed" {
    const mapped = map_dns_error(error.IterationLimitExceeded);
    try testing.expectEqual(DnsError.DnsResolutionFailed, mapped);
}

test "DnsError: AddressOverflow is in error set" {
    // TigerStyle S7: Verify AddressOverflow error exists
    const err: DnsError = DnsError.AddressOverflow;
    try testing.expectEqual(DnsError.AddressOverflow, err);
}

test "map_dns_error: maps known errors correctly" {
    // DNS resolution failures
    try testing.expectEqual(DnsError.DnsResolutionFailed, map_dns_error(error.UnknownHostName));
    try testing.expectEqual(DnsError.DnsResolutionFailed, map_dns_error(error.NameServerFailure));

    // Invalid hostname errors
    try testing.expectEqual(DnsError.InvalidHostname, map_dns_error(error.NameTooLong));
    try testing.expectEqual(DnsError.InvalidHostname, map_dns_error(error.InvalidHostName));

    // Address overflow error
    try testing.expectEqual(DnsError.AddressOverflow, map_dns_error(error.AddressOverflow));

    // Unknown errors fall through to DnsResolutionFailed
    try testing.expectEqual(DnsError.DnsResolutionFailed, map_dns_error(error.OutOfMemory));
}

test "DnsResolver: resolve cache hit returns cached result" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

    // Pre-populate cache with valid entry (multi-address)
    const hostname = "cached.example.com";
    const cached_addr = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 10, 20, 30, 40 }, .port = 0 } };
    const future_expires_ns: u64 = time.monotonicNanos() + 60 * time.ns_per_s;

    resolver.cache[0].valid = true;
    resolver.cache[0].hostname_len = @intCast(hostname.len);
    @memcpy(resolver.cache[0].hostname[0..hostname.len], hostname);
    resolver.cache[0].addresses[0] = cached_addr;
    resolver.cache[0].address_count = 1;
    resolver.cache[0].next_address_idx = 0;
    resolver.cache[0].expires_ns = future_expires_ns;

    // Record initial stats
    const initial_hits = resolver.stats_hits;
    const initial_misses = resolver.stats_misses;

    // Resolve with io = undefined (cache hit won't use io)
    const result = try resolver.resolve(hostname, 8080, undefined);

    // Strict assertions
    try testing.expect(result.from_cache);
    try testing.expectEqual(@as(u64, 0), result.resolution_ns);
    try testing.expectEqual(initial_hits + 1, resolver.stats_hits);
    try testing.expectEqual(initial_misses, resolver.stats_misses);

    // Port should be rewritten
    try testing.expectEqual(@as(u16, 8080), result.address.getPort());

    // IP should match cached value
    const ip4 = result.address.ip4;
    try testing.expectEqual(@as(u8, 10), ip4.bytes[0]);
    try testing.expectEqual(@as(u8, 20), ip4.bytes[1]);
    try testing.expectEqual(@as(u8, 30), ip4.bytes[2]);
    try testing.expectEqual(@as(u8, 40), ip4.bytes[3]);
}

test "DnsResolver: resolve_all cache hit returns cached result" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

    // Pre-populate cache with valid entry (multi-address)
    const hostname = "cached-all.example.com";
    const cached_addr = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 100 }, .port = 0 } };
    const future_expires_ns: u64 = time.monotonicNanos() + 60 * time.ns_per_s;

    resolver.cache[0].valid = true;
    resolver.cache[0].hostname_len = @intCast(hostname.len);
    @memcpy(resolver.cache[0].hostname[0..hostname.len], hostname);
    resolver.cache[0].addresses[0] = cached_addr;
    resolver.cache[0].address_count = 1;
    resolver.cache[0].next_address_idx = 0;
    resolver.cache[0].expires_ns = future_expires_ns;

    // Record initial stats
    const initial_hits = resolver.stats_hits;
    const initial_misses = resolver.stats_misses;

    // Resolve all with io = undefined (cache hit won't use io)
    var result: ResolveAllResult = undefined;
    try resolver.resolve_all(hostname, 9090, undefined, &result);

    // Strict assertions
    try testing.expect(result.from_cache);
    try testing.expectEqual(@as(u64, 0), result.resolution_ns);
    try testing.expectEqual(@as(u8, 1), result.count);
    try testing.expectEqual(initial_hits + 1, resolver.stats_hits);
    try testing.expectEqual(initial_misses, resolver.stats_misses);

    // Port should be rewritten
    try testing.expectEqual(@as(u16, 9090), result.addresses[0].getPort());

    // IP should match cached value
    const ip4 = result.addresses[0].ip4;
    try testing.expectEqual(@as(u8, 192), ip4.bytes[0]);
    try testing.expectEqual(@as(u8, 168), ip4.bytes[1]);
    try testing.expectEqual(@as(u8, 1), ip4.bytes[2]);
    try testing.expectEqual(@as(u8, 100), ip4.bytes[3]);
}

test "DnsResolver: resolve IP address fast path (no DNS)" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

    // Record initial stats
    const initial_hits = resolver.stats_hits;
    const initial_misses = resolver.stats_misses;

    // Resolve an IP address directly - should use fast path, no DNS lookup
    const result = try resolver.resolve("127.0.0.1", 3000, undefined);

    // Not from cache (parsed directly)
    try testing.expect(!result.from_cache);

    // Port should be correct
    try testing.expectEqual(@as(u16, 3000), result.address.getPort());

    // IP should be 127.0.0.1
    const ip4 = result.address.ip4;
    try testing.expectEqual(@as(u8, 127), ip4.bytes[0]);
    try testing.expectEqual(@as(u8, 0), ip4.bytes[1]);
    try testing.expectEqual(@as(u8, 0), ip4.bytes[2]);
    try testing.expectEqual(@as(u8, 1), ip4.bytes[3]);

    // Stats: cache miss because we resolved (but via fast path)
    try testing.expectEqual(initial_hits, resolver.stats_hits);
    try testing.expectEqual(initial_misses + 1, resolver.stats_misses);
}

test "DnsResolver: resolve_all IP address fast path (no DNS)" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

    // Record initial stats
    const initial_hits = resolver.stats_hits;
    const initial_misses = resolver.stats_misses;

    // Resolve an IP address directly - should use fast path, no DNS lookup
    var result: ResolveAllResult = undefined;
    try resolver.resolve_all("10.0.0.1", 8000, undefined, &result);

    // Not from cache (parsed directly)
    try testing.expect(!result.from_cache);
    try testing.expectEqual(@as(u8, 1), result.count);

    // Port should be correct
    try testing.expectEqual(@as(u16, 8000), result.addresses[0].getPort());

    // IP should be 10.0.0.1
    const ip4 = result.addresses[0].ip4;
    try testing.expectEqual(@as(u8, 10), ip4.bytes[0]);
    try testing.expectEqual(@as(u8, 0), ip4.bytes[1]);
    try testing.expectEqual(@as(u8, 0), ip4.bytes[2]);
    try testing.expectEqual(@as(u8, 1), ip4.bytes[3]);

    // Stats: cache miss because we resolved (but via fast path)
    try testing.expectEqual(initial_hits, resolver.stats_hits);
    try testing.expectEqual(initial_misses + 1, resolver.stats_misses);
}

test "DnsResolver: store_in_cache overwrites existing hostname" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});
    const now_ns: u64 = 1_000_000_000;

    // Store initial entry for "example.com"
    const addr1 = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 80 } };
    const addr1_slice: []const Io.net.IpAddress = &[_]Io.net.IpAddress{addr1};
    resolver.store_in_cache("example.com", addr1_slice, now_ns);

    // Verify it's in slot 0 (first invalid slot)
    try testing.expect(resolver.cache[0].matches("example.com"));
    try testing.expectEqual(@as(u8, 1), resolver.cache[0].addresses[0].ip4.bytes[0]);

    // Store updated entry for same hostname - should overwrite slot 0, not use slot 1
    const addr2 = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 5, 6, 7, 8 }, .port = 80 } };
    const addr2_slice: []const Io.net.IpAddress = &[_]Io.net.IpAddress{addr2};
    resolver.store_in_cache("example.com", addr2_slice, now_ns + 1000);

    // Verify slot 0 was overwritten (not slot 1)
    try testing.expect(resolver.cache[0].matches("example.com"));
    try testing.expectEqual(@as(u8, 5), resolver.cache[0].addresses[0].ip4.bytes[0]);
    // Slot 1 should still be invalid
    try testing.expect(!resolver.cache[1].valid);
}

test "DnsResolver: TTL overflow expires immediately" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

    // Use near-max time to trigger overflow
    const near_max_ns: u64 = std.math.maxInt(u64) - 1000;
    const addr = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 80 } };
    const addr_slice: []const Io.net.IpAddress = &[_]Io.net.IpAddress{addr};

    resolver.store_in_cache("overflow.test", addr_slice, near_max_ns);

    // Entry should expire immediately (or very soon) due to overflow protection
    // expires_ns should be <= near_max_ns (not maxInt which would never expire)
    try testing.expect(resolver.cache[0].expires_ns <= near_max_ns);
}

test "DnsResolver: looks_like_ip_address rejects invalid IPs" {
    // These should NOT be detected as IP addresses (were false positives before fix)
    try testing.expect(!(try DnsResolver.looks_like_ip_address("1.2.3")));
    try testing.expect(!(try DnsResolver.looks_like_ip_address("1.2.3.4.5")));
    try testing.expect(!(try DnsResolver.looks_like_ip_address("123:456")));
    try testing.expect(!(try DnsResolver.looks_like_ip_address("host:port")));

    // These SHOULD be detected as valid IP addresses
    try testing.expect(try DnsResolver.looks_like_ip_address("127.0.0.1"));
    try testing.expect(try DnsResolver.looks_like_ip_address("192.168.1.1"));
    try testing.expect(try DnsResolver.looks_like_ip_address("0.0.0.0"));
    try testing.expect(try DnsResolver.looks_like_ip_address("255.255.255.255"));

    // IPv6 addresses
    try testing.expect(try DnsResolver.looks_like_ip_address("::1"));
    try testing.expect(try DnsResolver.looks_like_ip_address("::"));
}

test "DnsResolver: multi-address cache stores all addresses" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});
    const now_ns: u64 = 1_000_000_000;

    // Store multiple addresses for same hostname
    const addr1 = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 80 } };
    const addr2 = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 10, 0, 0, 2 }, .port = 80 } };
    const addr3 = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 10, 0, 0, 3 }, .port = 80 } };
    const addrs = [_]Io.net.IpAddress{ addr1, addr2, addr3 };

    resolver.store_in_cache("multi.example.com", &addrs, now_ns);

    // Verify all addresses stored
    try testing.expect(resolver.cache[0].matches("multi.example.com"));
    try testing.expectEqual(@as(u8, 3), resolver.cache[0].address_count);
    try testing.expectEqual(@as(u8, 0), resolver.cache[0].next_address_idx);

    // Verify each address
    try testing.expectEqual(@as(u8, 1), resolver.cache[0].addresses[0].ip4.bytes[3]);
    try testing.expectEqual(@as(u8, 2), resolver.cache[0].addresses[1].ip4.bytes[3]);
    try testing.expectEqual(@as(u8, 3), resolver.cache[0].addresses[2].ip4.bytes[3]);
}

test "DnsResolver: resolve rotates through cached addresses" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

    // Pre-populate cache with 3 addresses
    const hostname = "rotate.example.com";
    const future_expires_ns: u64 = time.monotonicNanos() + 60 * time.ns_per_s;

    resolver.cache[0].valid = true;
    resolver.cache[0].hostname_len = @intCast(hostname.len);
    @memcpy(resolver.cache[0].hostname[0..hostname.len], hostname);
    resolver.cache[0].addresses[0] = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 0 } };
    resolver.cache[0].addresses[1] = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 2 }, .port = 0 } };
    resolver.cache[0].addresses[2] = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 3 }, .port = 0 } };
    resolver.cache[0].address_count = 3;
    resolver.cache[0].next_address_idx = 0;
    resolver.cache[0].expires_ns = future_expires_ns;

    // First resolve: should return address[0]
    const result1 = try resolver.resolve(hostname, 8080, undefined);
    try testing.expect(result1.from_cache);
    try testing.expectEqual(@as(u8, 1), result1.address.ip4.bytes[3]);

    // Second resolve: should return address[1]
    const result2 = try resolver.resolve(hostname, 8080, undefined);
    try testing.expect(result2.from_cache);
    try testing.expectEqual(@as(u8, 2), result2.address.ip4.bytes[3]);

    // Third resolve: should return address[2]
    const result3 = try resolver.resolve(hostname, 8080, undefined);
    try testing.expect(result3.from_cache);
    try testing.expectEqual(@as(u8, 3), result3.address.ip4.bytes[3]);

    // Fourth resolve: should wrap to address[0]
    const result4 = try resolver.resolve(hostname, 8080, undefined);
    try testing.expect(result4.from_cache);
    try testing.expectEqual(@as(u8, 1), result4.address.ip4.bytes[3]);
}

test "DnsResolver: resolve_all cache hit returns all addresses" {
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{});

    // Pre-populate cache with 3 addresses
    const hostname = "all.example.com";
    const future_expires_ns: u64 = time.monotonicNanos() + 60 * time.ns_per_s;

    resolver.cache[0].valid = true;
    resolver.cache[0].hostname_len = @intCast(hostname.len);
    @memcpy(resolver.cache[0].hostname[0..hostname.len], hostname);
    resolver.cache[0].addresses[0] = .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 0 } };
    resolver.cache[0].addresses[1] = .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 2 }, .port = 0 } };
    resolver.cache[0].addresses[2] = .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 3 }, .port = 0 } };
    resolver.cache[0].address_count = 3;
    resolver.cache[0].next_address_idx = 0;
    resolver.cache[0].expires_ns = future_expires_ns;

    // resolve_all should return all 3 addresses
    var result: ResolveAllResult = undefined;
    try resolver.resolve_all(hostname, 9000, undefined, &result);

    try testing.expect(result.from_cache);
    try testing.expectEqual(@as(u8, 3), result.count);

    // All addresses should be present with correct port
    try testing.expectEqual(@as(u16, 9000), result.addresses[0].getPort());
    try testing.expectEqual(@as(u16, 9000), result.addresses[1].getPort());
    try testing.expectEqual(@as(u16, 9000), result.addresses[2].getPort());

    // Verify IPs
    try testing.expectEqual(@as(u8, 1), result.addresses[0].ip4.bytes[3]);
    try testing.expectEqual(@as(u8, 2), result.addresses[1].ip4.bytes[3]);
    try testing.expectEqual(@as(u8, 3), result.addresses[2].ip4.bytes[3]);
}

test "CacheEntry: getNextAddress rotates correctly" {
    var entry: CacheEntry = undefined;
    CacheEntry.init_empty(&entry);

    // Set up with 3 addresses
    entry.valid = true;
    entry.addresses[0] = .{ .ip4 = .{ .bytes = .{ 1, 0, 0, 0 }, .port = 0 } };
    entry.addresses[1] = .{ .ip4 = .{ .bytes = .{ 2, 0, 0, 0 }, .port = 0 } };
    entry.addresses[2] = .{ .ip4 = .{ .bytes = .{ 3, 0, 0, 0 }, .port = 0 } };
    entry.address_count = 3;
    entry.next_address_idx = 0;

    // First call: returns index 0, cursor moves to 1
    const addr1 = entry.getNextAddress().?;
    try testing.expectEqual(@as(u8, 1), addr1.ip4.bytes[0]);
    try testing.expectEqual(@as(u8, 1), entry.next_address_idx);

    // Second call: returns index 1, cursor moves to 2
    const addr2 = entry.getNextAddress().?;
    try testing.expectEqual(@as(u8, 2), addr2.ip4.bytes[0]);
    try testing.expectEqual(@as(u8, 2), entry.next_address_idx);

    // Third call: returns index 2, cursor wraps to 0
    const addr3 = entry.getNextAddress().?;
    try testing.expectEqual(@as(u8, 3), addr3.ip4.bytes[0]);
    try testing.expectEqual(@as(u8, 0), entry.next_address_idx);

    // Fourth call: returns index 0 again (full cycle)
    const addr4 = entry.getNextAddress().?;
    try testing.expectEqual(@as(u8, 1), addr4.ip4.bytes[0]);
}

test "CacheEntry: getNextAddress returns null for empty entry" {
    var entry: CacheEntry = undefined;
    CacheEntry.init_empty(&entry);

    // No addresses
    try testing.expectEqual(@as(?*const Io.net.IpAddress, null), entry.getNextAddress());
}
