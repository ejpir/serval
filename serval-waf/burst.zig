//! serval-waf/burst.zig
//! Bounded per-client burst tracking with CAS-guarded table updates.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const types = @import("types.zig");

const time = core.time;

pub const OutcomeUpdate = struct {
    tracker_degraded: bool = false,
};

const SensitiveFamily = enum(u8) {
    dotfiles,
    wp_admin,
    phpmyadmin,
    admin,
    actuator,
};

const Entry = struct {
    in_use: bool = false,
    key_hash: u64 = 0,
    last_seen_ns: u64 = 0,
    window_start_ns: u64 = 0,
    request_count: u16 = 0,
    unique_path_count: u8 = 0,
    namespace_family_mask: u8 = 0,
    miss_reject_count: u16 = 0,
    path_hashes: [types.MAX_TRACKED_PATH_HASHES]u64 = [_]u64{0} ** types.MAX_TRACKED_PATH_HASHES,
};

pub const Tracker = struct {
    enabled: bool,
    window_ns: u64,
    capacity: u16,
    retry_budget: u8,
    lock: std.atomic.Value(u8),
    slots: [types.MAX_TRACKER_CAPACITY]Entry,

    pub fn init(self: *Tracker, config: *const types.Config) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(config) != 0);

        self.* = .{
            .enabled = config.burst_enabled,
            .window_ns = config.burst_window_ns,
            .capacity = if (config.burst_enabled) config.burst_tracker_capacity else 0,
            .retry_budget = if (config.burst_enabled) config.burst_tracker_retry_budget else 1,
            .lock = std.atomic.Value(u8).init(0),
            .slots = undefined,
        };
        var idx: u16 = 0;
        while (idx < types.MAX_TRACKER_CAPACITY) : (idx += 1) {
            self.slots[idx] = Entry{};
        }
    }

    pub fn snapshot(self: *Tracker, input: *const types.InspectionInput) types.BehavioralSnapshot {
        if (!self.enabled) return .{};
        const now_ns = time.monotonicNanos();
        if (!self.tryLock()) {
            return .{ .tracker_degraded = true };
        }
        defer self.unlock();

        const key_hash = hashClient(input.client_addr);
        const idx = self.findEntryIndex(key_hash) orelse return .{};
        var entry = &self.slots[idx];
        self.resetWindowIfExpired(entry, now_ns);

        return .{
            .request_count = entry.request_count,
            .unique_path_count = entry.unique_path_count,
            .namespace_family_count = @intCast(@popCount(entry.namespace_family_mask)),
            .miss_reject_count = entry.miss_reject_count,
        };
    }

    pub fn commitRequest(self: *Tracker, input: *const types.InspectionInput) OutcomeUpdate {
        if (!self.enabled) return .{};
        const now_ns = time.monotonicNanos();
        if (!self.tryLock()) {
            return .{ .tracker_degraded = true };
        }
        defer self.unlock();

        var degraded = false;
        var entry = self.getOrCreateEntry(hashClient(input.client_addr), now_ns, &degraded);
        self.resetWindowIfExpired(entry, now_ns);
        entry.last_seen_ns = now_ns;
        entry.request_count +|= 1;
        self.addPathHash(entry, hashLower(input.path));
        self.addSensitiveFamily(entry, input.path);
        return .{ .tracker_degraded = degraded };
    }

    pub fn commitOutcome(self: *Tracker, client_addr: []const u8, is_miss: bool, is_reject: bool) OutcomeUpdate {
        if (!self.enabled) return .{};
        if (!is_miss and !is_reject) return .{};

        const now_ns = time.monotonicNanos();
        if (!self.tryLock()) {
            return .{ .tracker_degraded = true };
        }
        defer self.unlock();

        var degraded = false;
        var entry = self.getOrCreateEntry(hashClient(client_addr), now_ns, &degraded);
        self.resetWindowIfExpired(entry, now_ns);
        entry.last_seen_ns = now_ns;
        entry.miss_reject_count +|= 1;
        return .{ .tracker_degraded = degraded };
    }

    fn tryLock(self: *Tracker) bool {
        assert(self.retry_budget > 0);
        var tries: u8 = 0;
        while (tries < self.retry_budget) : (tries += 1) {
            const previous = self.lock.cmpxchgWeak(0, 1, .acq_rel, .acquire);
            if (previous == null) return true;
        }
        return false;
    }

    fn unlock(self: *Tracker) void {
        self.lock.store(0, .release);
    }

    fn getOrCreateEntry(self: *Tracker, key_hash: u64, now_ns: u64, degraded: *bool) *Entry {
        assert(self.capacity > 0);
        assert(self.capacity <= types.MAX_TRACKER_CAPACITY);

        if (self.findEntryIndex(key_hash)) |existing_idx| {
            return &self.slots[existing_idx];
        }

        var first_free: ?u16 = null;
        var oldest_expired: ?u16 = null;
        var oldest_expired_seen: u64 = std.math.maxInt(u64);
        var oldest_active: ?u16 = null;
        var oldest_active_seen: u64 = std.math.maxInt(u64);

        var idx: u16 = 0;
        while (idx < self.capacity) : (idx += 1) {
            const entry = &self.slots[idx];
            if (!entry.in_use) {
                if (first_free == null) first_free = idx;
                continue;
            }

            const is_expired = now_ns -| entry.window_start_ns >= self.window_ns;
            if (is_expired) {
                if (entry.last_seen_ns < oldest_expired_seen) {
                    oldest_expired_seen = entry.last_seen_ns;
                    oldest_expired = idx;
                }
            } else if (entry.last_seen_ns < oldest_active_seen) {
                oldest_active_seen = entry.last_seen_ns;
                oldest_active = idx;
            }
        }

        const target_idx = first_free orelse oldest_expired orelse oldest_active.?;
        if (first_free == null and oldest_expired == null) {
            degraded.* = true;
        }
        self.slots[target_idx] = .{
            .in_use = true,
            .key_hash = key_hash,
            .last_seen_ns = now_ns,
            .window_start_ns = now_ns,
        };
        return &self.slots[target_idx];
    }

    fn findEntryIndex(self: *Tracker, key_hash: u64) ?u16 {
        var idx: u16 = 0;
        while (idx < self.capacity) : (idx += 1) {
            const entry = &self.slots[idx];
            if (!entry.in_use) continue;
            if (entry.key_hash != key_hash) continue;
            return idx;
        }
        return null;
    }

    fn resetWindowIfExpired(self: *Tracker, entry: *Entry, now_ns: u64) void {
        if (now_ns -| entry.window_start_ns < self.window_ns) return;
        entry.window_start_ns = now_ns;
        entry.request_count = 0;
        entry.unique_path_count = 0;
        entry.namespace_family_mask = 0;
        entry.miss_reject_count = 0;
        var idx: u8 = 0;
        while (idx < types.MAX_TRACKED_PATH_HASHES) : (idx += 1) {
            entry.path_hashes[idx] = 0;
        }
    }

    fn addPathHash(self: *Tracker, entry: *Entry, path_hash: u64) void {
        _ = self;
        var idx: u8 = 0;
        while (idx < entry.unique_path_count) : (idx += 1) {
            if (entry.path_hashes[idx] == path_hash) return;
        }
        if (entry.unique_path_count >= types.MAX_TRACKED_PATH_HASHES) return;
        entry.path_hashes[entry.unique_path_count] = path_hash;
        entry.unique_path_count +|= 1;
    }

    fn addSensitiveFamily(self: *Tracker, entry: *Entry, path: []const u8) void {
        _ = self;
        const family = classifyFamily(path) orelse return;
        const shift: std.math.Log2Int(u8) = @intCast(@intFromEnum(family));
        const bit: u8 = @as(u8, 1) << shift;
        entry.namespace_family_mask |= bit;
    }
};

fn hashClient(client_addr: []const u8) u64 {
    var hash = std.hash.Fnv1a_64.init();
    hash.update(client_addr);
    const value = hash.final();
    return if (value == 0) 1 else value;
}

fn hashLower(value: []const u8) u64 {
    var hash = std.hash.Fnv1a_64.init();
    var idx: u32 = 0;
    while (idx < value.len) : (idx += 1) {
        var byte = value[idx];
        if (byte >= 'A' and byte <= 'Z') byte += 32;
        hash.update(&[_]u8{byte});
    }
    const result = hash.final();
    return if (result == 0) 1 else result;
}

fn classifyFamily(path: []const u8) ?SensitiveFamily {
    if (startsWithAsciiCi(path, "/.git/") or equalsAsciiCi(path, "/.env")) return .dotfiles;
    if (startsWithAsciiCi(path, "/wp-")) return .wp_admin;
    if (containsAsciiCi(path, "phpmyadmin")) return .phpmyadmin;
    if (startsWithAsciiCi(path, "/admin")) return .admin;
    if (startsWithAsciiCi(path, "/actuator")) return .actuator;
    return null;
}

fn startsWithAsciiCi(value: []const u8, prefix: []const u8) bool {
    if (prefix.len > value.len) return false;
    return equalsAsciiCi(value[0..prefix.len], prefix);
}

fn equalsAsciiCi(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var idx: u32 = 0;
    while (idx < a.len) : (idx += 1) {
        if (std.ascii.toLower(a[idx]) != std.ascii.toLower(b[idx])) return false;
    }
    return true;
}

fn containsAsciiCi(value: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > value.len) return false;

    var idx: u32 = 0;
    while (idx + needle.len <= value.len) : (idx += 1) {
        if (equalsAsciiCi(value[idx .. idx + needle.len], needle)) return true;
    }
    return false;
}

test "Tracker tracks bounded request and path diversity" {
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("path", .path, .contains_ascii_ci, "/wp-admin", 60, .score),
    };
    const cfg = types.Config{
        .rules = rules[0..],
        .burst_enabled = true,
        .burst_tracker_capacity = 8,
    };
    var tracker: Tracker = undefined;
    tracker.init(&cfg);

    const input = types.InspectionInput{
        .method = .GET,
        .path = "/foo",
        .query = "",
        .host = "example.com",
        .user_agent = "curl",
        .client_addr = "127.0.0.1",
    };

    _ = tracker.commitRequest(&input);
    const snapshot = tracker.snapshot(&input);
    try std.testing.expectEqual(@as(u16, 1), snapshot.request_count);
    try std.testing.expectEqual(@as(u8, 1), snapshot.unique_path_count);
}

test "Tracker marks degraded when CAS lock budget is exhausted" {
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("path", .path, .contains_ascii_ci, "/wp-admin", 60, .score),
    };
    const cfg = types.Config{
        .rules = rules[0..],
        .burst_enabled = true,
        .burst_tracker_capacity = 8,
        .burst_tracker_retry_budget = 1,
    };
    var tracker: Tracker = undefined;
    tracker.init(&cfg);
    tracker.lock.store(1, .release);

    const input = types.InspectionInput{
        .method = .GET,
        .path = "/foo",
        .query = "",
        .host = "example.com",
        .user_agent = "curl",
        .client_addr = "127.0.0.1",
    };

    const update = tracker.commitRequest(&input);
    try std.testing.expect(update.tracker_degraded);
}

test "Tracker replaces stale active entry and marks degraded on saturation" {
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("path", .path, .contains_ascii_ci, "/wp-admin", 60, .score),
    };
    const cfg = types.Config{
        .rules = rules[0..],
        .burst_enabled = true,
        .burst_tracker_capacity = 1,
    };
    var tracker: Tracker = undefined;
    tracker.init(&cfg);

    var input_a = types.InspectionInput{
        .method = .GET,
        .path = "/a",
        .query = "",
        .host = "example.com",
        .user_agent = "curl",
        .client_addr = "10.0.0.1",
    };
    var input_b = input_a;
    input_b.client_addr = "10.0.0.2";

    _ = tracker.commitRequest(&input_a);
    const update = tracker.commitRequest(&input_b);
    try std.testing.expect(update.tracker_degraded);
}

test "Tracker caps distinct path hashes" {
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("path", .path, .contains_ascii_ci, "/wp-admin", 60, .score),
    };
    const cfg = types.Config{
        .rules = rules[0..],
        .burst_enabled = true,
        .burst_tracker_capacity = 4,
    };
    var tracker: Tracker = undefined;
    tracker.init(&cfg);

    var input = types.InspectionInput{
        .method = .GET,
        .path = "/x",
        .query = "",
        .host = "example.com",
        .user_agent = "curl",
        .client_addr = "10.0.0.1",
    };

    var idx: u8 = 0;
    var path_buf: [32]u8 = undefined;
    while (idx < 24) : (idx += 1) {
        const path = try std.fmt.bufPrint(path_buf[0..], "/path-{d}", .{idx});
        input.path = path;
        _ = tracker.commitRequest(&input);
    }

    const snapshot = tracker.snapshot(&input);
    try std.testing.expectEqual(types.MAX_TRACKED_PATH_HASHES, snapshot.unique_path_count);
}
