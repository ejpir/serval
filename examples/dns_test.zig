// examples/dns_test.zig
//! DNS Resolution Test
//!
//! Standalone test for debugging DNS resolution issues.
//! Usage: zig build run-dns-test -- <hostname> [port]
//!
//! Shows:
//! - /etc/resolv.conf contents (nameservers, search domains, options)
//! - DNS resolution results
//! - Timing information

const std = @import("std");
const Io = std.Io;
const posix = std.posix;

const serval_net = @import("serval-net");
const DnsResolver = serval_net.DnsResolver;
const ResolveAllResult = serval_net.dns.ResolveAllResult;

const serval_core = @import("serval-core");
const config = serval_core.config;
const time = serval_core.time;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line args
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: {s} <hostname> [port]\n", .{args[0]});
        std.debug.print("\nExamples:\n", .{});
        std.debug.print("  {s} google.com\n", .{args[0]});
        std.debug.print("  {s} jaeger.default.svc.cluster.local 4318\n", .{args[0]});
        std.debug.print("  {s} jaeger.default.svc.cluster.local. 4318  # With trailing dot\n", .{args[0]});
        return;
    }

    const hostname = args[1];
    const port: u16 = if (args.len > 2) std.fmt.parseInt(u16, args[2], 10) catch 80 else 80;

    std.debug.print("\n=== DNS Resolution Test ===\n\n", .{});
    std.debug.print("Hostname: {s}\n", .{hostname});
    std.debug.print("Port: {d}\n\n", .{port});

    // Show resolv.conf
    showResolvConf();

    // Parse and show nameservers explicitly
    showNameservers();

    // Initialize IO runtime
    var io_runtime = Io.Threaded.init(allocator, .{});
    defer io_runtime.deinit();
    const io = io_runtime.io();

    // Initialize DNS resolver
    var resolver: DnsResolver = undefined;
    DnsResolver.init(&resolver, .{
        .ttl_ns = 60 * time.ns_per_s,
        .timeout_ns = 10 * time.ns_per_s,
    });

    // Try resolving
    std.debug.print("\n=== Resolution Attempt ===\n\n", .{});

    // First, try single resolve
    std.debug.print("Trying resolve() for single address...\n", .{});
    const start1 = time.monotonicNanos();
    if (resolver.resolve(hostname, port, io)) |result| {
        const elapsed_ms = @as(f64, @floatFromInt(time.monotonicNanos() - start1)) / 1_000_000.0;
        std.debug.print("  Success!\n", .{});
        std.debug.print("  Address: {}\n", .{result.address});
        std.debug.print("  From cache: {}\n", .{result.from_cache});
        std.debug.print("  Resolution time: {d:.2}ms\n", .{elapsed_ms});
    } else |err| {
        const elapsed_ms = @as(f64, @floatFromInt(time.monotonicNanos() - start1)) / 1_000_000.0;
        std.debug.print("  Failed: {s}\n", .{@errorName(err)});
        std.debug.print("  Time: {d:.2}ms\n", .{elapsed_ms});
    }

    // Then try resolve_all
    std.debug.print("\nTrying resolve_all() for all addresses...\n", .{});
    var all_result: ResolveAllResult = undefined;
    const start2 = time.monotonicNanos();
    if (resolver.resolve_all(hostname, port, io, &all_result)) {
        const elapsed_ms = @as(f64, @floatFromInt(time.monotonicNanos() - start2)) / 1_000_000.0;
        std.debug.print("  Success! Found {d} addresses:\n", .{all_result.count});
        for (all_result.slice(), 0..) |addr, i| {
            std.debug.print("    [{d}] {}\n", .{ i, addr });
        }
        std.debug.print("  From cache: {}\n", .{all_result.from_cache});
        std.debug.print("  Resolution time: {d:.2}ms\n", .{elapsed_ms});
    } else |err| {
        const elapsed_ms = @as(f64, @floatFromInt(time.monotonicNanos() - start2)) / 1_000_000.0;
        std.debug.print("  Failed: {s}\n", .{@errorName(err)});
        std.debug.print("  Time: {d:.2}ms\n", .{elapsed_ms});
    }

    // Try with FQDN normalization
    var fqdn_buf: [config.DNS_MAX_HOSTNAME_LEN + 1]u8 = undefined;
    const normalized = DnsResolver.normalize_fqdn(hostname, &fqdn_buf) catch |err| {
        std.debug.print("FQDN normalization failed: {s}\n", .{@errorName(err)});
        return;
    };
    if (!std.mem.eql(u8, normalized, hostname)) {
        std.debug.print("\nTrying with FQDN normalization: '{s}'...\n", .{normalized});
        const start3 = time.monotonicNanos();
        if (resolver.resolve(normalized, port, io)) |result| {
            const elapsed_ms = @as(f64, @floatFromInt(time.monotonicNanos() - start3)) / 1_000_000.0;
            std.debug.print("  Success!\n", .{});
            std.debug.print("  Address: {}\n", .{result.address});
            std.debug.print("  From cache: {}\n", .{result.from_cache});
            std.debug.print("  Resolution time: {d:.2}ms\n", .{elapsed_ms});
        } else |err| {
            const elapsed_ms = @as(f64, @floatFromInt(time.monotonicNanos() - start3)) / 1_000_000.0;
            std.debug.print("  Failed: {s}\n", .{@errorName(err)});
            std.debug.print("  Time: {d:.2}ms\n", .{elapsed_ms});
        }
    }

    // Show cache stats
    const stats = resolver.get_stats();
    std.debug.print("\n=== Cache Stats ===\n", .{});
    std.debug.print("Hits: {d}\n", .{stats.hits});
    std.debug.print("Misses: {d}\n", .{stats.misses});
}

fn showResolvConf() void {
    std.debug.print("=== /etc/resolv.conf ===\n\n", .{});

    const fd = posix.open("/etc/resolv.conf", .{}, 0) catch |err| {
        std.debug.print("Cannot open /etc/resolv.conf: {s}\n", .{@errorName(err)});
        return;
    };
    defer posix.close(fd);

    var buf: [4096]u8 = undefined;
    const bytes_read = posix.read(fd, &buf) catch |err| {
        std.debug.print("Cannot read /etc/resolv.conf: {s}\n", .{@errorName(err)});
        return;
    };

    std.debug.print("{s}\n", .{buf[0..bytes_read]});
}

fn showNameservers() void {
    std.debug.print("=== Parsed Nameservers ===\n\n", .{});

    const fd = posix.open("/etc/resolv.conf", .{}, 0) catch |err| {
        std.debug.print("Cannot open: {s}\n", .{@errorName(err)});
        return;
    };
    defer posix.close(fd);

    var buf: [4096]u8 = undefined;
    const bytes_read = posix.read(fd, &buf) catch |err| {
        std.debug.print("Cannot read: {s}\n", .{@errorName(err)});
        return;
    };

    var nameserver_count: u32 = 0;
    var search_domains: ?[]const u8 = null;
    var ndots: ?[]const u8 = null;

    var lines = std.mem.splitScalar(u8, buf[0..bytes_read], '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (std.mem.startsWith(u8, trimmed, "nameserver ")) {
            const ns = std.mem.trim(u8, trimmed["nameserver ".len..], " \t");
            nameserver_count += 1;
            std.debug.print("  Nameserver #{d}: {s}\n", .{ nameserver_count, ns });
        } else if (std.mem.startsWith(u8, trimmed, "search ")) {
            search_domains = std.mem.trim(u8, trimmed["search ".len..], " \t");
        } else if (std.mem.startsWith(u8, trimmed, "options ")) {
            const options = trimmed["options ".len..];
            // Look for ndots option
            var opts = std.mem.splitScalar(u8, options, ' ');
            while (opts.next()) |opt| {
                if (std.mem.startsWith(u8, opt, "ndots:")) {
                    ndots = opt["ndots:".len..];
                }
            }
        }
    }

    if (search_domains) |sd| {
        std.debug.print("\n  Search domains: {s}\n", .{sd});
    }
    if (ndots) |n| {
        std.debug.print("  ndots: {s}\n", .{n});
    }

    if (nameserver_count == 0) {
        std.debug.print("  No nameservers found!\n", .{});
    }
}
