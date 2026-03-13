//! HTTP-01 challenge token store.
//!
//! TigerStyle: Fixed-capacity table, explicit expiration, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;

const max_entries: usize = config.ACME_MAX_ACTIVE_CHALLENGES;
const max_host_len: usize = config.ACME_MAX_DOMAIN_NAME_LEN;
const max_token_len: usize = config.ACME_MAX_HTTP01_TOKEN_BYTES;
const max_key_authorization_len: usize = config.ACME_MAX_HTTP01_KEY_AUTHORIZATION_BYTES;

pub const Error = error{
    InvalidHost,
    InvalidToken,
    InvalidKeyAuthorization,
    InvalidExpiration,
    StoreFull,
};

const Slot = struct {
    used: bool = false,
    host_len: u16 = 0,
    host_bytes: [max_host_len]u8 = [_]u8{0} ** max_host_len,
    token_len: u8 = 0,
    token_bytes: [max_token_len]u8 = [_]u8{0} ** max_token_len,
    key_authorization_len: u16 = 0,
    key_authorization_bytes: [max_key_authorization_len]u8 = [_]u8{0} ** max_key_authorization_len,
    expires_at_ns: u64 = 0,
};

pub const ChallengeView = struct {
    host: []const u8,
    token: []const u8,
    key_authorization: []const u8,
    expires_at_ns: u64,
};

pub const Http01Store = struct {
    slots: [max_entries]Slot = [_]Slot{.{}} ** max_entries,
    count: u8 = 0,

    pub fn init() Http01Store {
        return .{};
    }

    pub fn upsert(
        self: *Http01Store,
        host: []const u8,
        token: []const u8,
        key_authorization: []const u8,
        expires_at_ns: u64,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.count <= max_entries);

        try validateHost(host);
        try validateToken(token);
        try validateKeyAuthorization(key_authorization);
        if (expires_at_ns == 0) return error.InvalidExpiration;

        if (self.findExistingIndex(host, token)) |existing_index| {
            storeSlot(&self.slots[existing_index], host, token, key_authorization, expires_at_ns);
            return;
        }

        const free_index = self.findFreeIndex() orelse return error.StoreFull;
        storeSlot(&self.slots[free_index], host, token, key_authorization, expires_at_ns);

        self.count += 1;
        assert(self.count <= max_entries);
    }

    pub fn lookup(
        self: *Http01Store,
        host: []const u8,
        token: []const u8,
        now_ns: u64,
    ) ?ChallengeView {
        assert(@intFromPtr(self) != 0);
        assert(self.count <= max_entries);

        if (host.len == 0 or token.len == 0) return null;

        if (self.findExistingIndex(host, token)) |index| {
            const slot: *Slot = &self.slots[index];
            assert(slot.used);

            if (now_ns >= slot.expires_at_ns) {
                clearSlot(slot);
                assert(self.count > 0);
                self.count -= 1;
                return null;
            }

            return .{
                .host = slotHost(slot),
                .token = slotToken(slot),
                .key_authorization = slotKeyAuthorization(slot),
                .expires_at_ns = slot.expires_at_ns,
            };
        }

        return null;
    }

    pub fn remove(self: *Http01Store, host: []const u8, token: []const u8) bool {
        assert(@intFromPtr(self) != 0);
        assert(self.count <= max_entries);

        if (self.findExistingIndex(host, token)) |index| {
            clearSlot(&self.slots[index]);
            assert(self.count > 0);
            self.count -= 1;
            return true;
        }

        return false;
    }

    pub fn expire(self: *Http01Store, now_ns: u64) u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.count <= max_entries);

        var removed: u8 = 0;
        var index: usize = 0;
        while (index < self.slots.len) : (index += 1) {
            const slot: *Slot = &self.slots[index];
            if (!slot.used) continue;
            if (now_ns < slot.expires_at_ns) continue;

            clearSlot(slot);
            assert(self.count > 0);
            self.count -= 1;
            removed += 1;
        }

        return removed;
    }

    pub fn activeCount(self: *const Http01Store) u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.count <= max_entries);
        return self.count;
    }

    fn findExistingIndex(self: *const Http01Store, host: []const u8, token: []const u8) ?usize {
        assert(@intFromPtr(self) != 0);

        var index: usize = 0;
        while (index < self.slots.len) : (index += 1) {
            const slot: *const Slot = &self.slots[index];
            if (!slot.used) continue;
            if (!std.mem.eql(u8, slotHost(slot), host)) continue;
            if (!std.mem.eql(u8, slotToken(slot), token)) continue;
            return index;
        }

        return null;
    }

    fn findFreeIndex(self: *const Http01Store) ?usize {
        assert(@intFromPtr(self) != 0);

        var index: usize = 0;
        while (index < self.slots.len) : (index += 1) {
            if (!self.slots[index].used) return index;
        }
        return null;
    }
};

fn validateHost(host: []const u8) Error!void {
    if (host.len == 0 or host.len > max_host_len) return error.InvalidHost;
    if (std.mem.indexOfScalar(u8, host, '/')) |_| return error.InvalidHost;
}

fn validateToken(token: []const u8) Error!void {
    if (token.len == 0 or token.len > max_token_len) return error.InvalidToken;
}

fn validateKeyAuthorization(key_authorization: []const u8) Error!void {
    if (key_authorization.len == 0 or key_authorization.len > max_key_authorization_len) {
        return error.InvalidKeyAuthorization;
    }
}

fn storeSlot(
    slot: *Slot,
    host: []const u8,
    token: []const u8,
    key_authorization: []const u8,
    expires_at_ns: u64,
) void {
    assert(@intFromPtr(slot) != 0);
    assert(host.len > 0 and host.len <= max_host_len);
    assert(token.len > 0 and token.len <= max_token_len);
    assert(key_authorization.len > 0 and key_authorization.len <= max_key_authorization_len);
    assert(expires_at_ns > 0);

    @memset(slot.host_bytes[0..], 0);
    @memset(slot.token_bytes[0..], 0);
    @memset(slot.key_authorization_bytes[0..], 0);

    @memcpy(slot.host_bytes[0..host.len], host);
    @memcpy(slot.token_bytes[0..token.len], token);
    @memcpy(slot.key_authorization_bytes[0..key_authorization.len], key_authorization);

    slot.used = true;
    slot.host_len = @intCast(host.len);
    slot.token_len = @intCast(token.len);
    slot.key_authorization_len = @intCast(key_authorization.len);
    slot.expires_at_ns = expires_at_ns;
}

fn clearSlot(slot: *Slot) void {
    assert(@intFromPtr(slot) != 0);

    slot.* = .{};
}

fn slotHost(slot: *const Slot) []const u8 {
    assert(@intFromPtr(slot) != 0);
    assert(slot.host_len <= max_host_len);

    return slot.host_bytes[0..slot.host_len];
}

fn slotToken(slot: *const Slot) []const u8 {
    assert(@intFromPtr(slot) != 0);
    assert(slot.token_len <= max_token_len);

    return slot.token_bytes[0..slot.token_len];
}

fn slotKeyAuthorization(slot: *const Slot) []const u8 {
    assert(@intFromPtr(slot) != 0);
    assert(slot.key_authorization_len <= max_key_authorization_len);

    return slot.key_authorization_bytes[0..slot.key_authorization_len];
}

test "Http01Store stores and reads active challenge" {
    var store = Http01Store.init();
    try store.upsert("example.com", "token-a", "token-a.thumbprint", 50);

    const view = store.lookup("example.com", "token-a", 10) orelse return error.MissingChallenge;
    try std.testing.expect(std.mem.eql(u8, "token-a.thumbprint", view.key_authorization));
    try std.testing.expectEqual(@as(u8, 1), store.activeCount());
}

test "Http01Store upsert replaces existing challenge" {
    var store = Http01Store.init();
    try store.upsert("example.com", "token-a", "old-thumbprint", 50);
    try store.upsert("example.com", "token-a", "new-thumbprint", 60);

    const view = store.lookup("example.com", "token-a", 10) orelse return error.MissingChallenge;
    try std.testing.expect(std.mem.eql(u8, "new-thumbprint", view.key_authorization));
    try std.testing.expectEqual(@as(u8, 1), store.activeCount());
}

test "Http01Store lookup removes expired challenges" {
    var store = Http01Store.init();
    try store.upsert("example.com", "token-a", "thumbprint", 100);

    try std.testing.expect(store.lookup("example.com", "token-a", 100) == null);
    try std.testing.expectEqual(@as(u8, 0), store.activeCount());
}

test "Http01Store fill returns StoreFull" {
    var store = Http01Store.init();

    var index: usize = 0;
    while (index < max_entries) : (index += 1) {
        var token_buf: [32]u8 = undefined;
        const token = try std.fmt.bufPrint(&token_buf, "token-{d}", .{index});
        try store.upsert("example.com", token, "thumbprint", @intCast(index + 100));
    }

    try std.testing.expectEqual(@as(u8, @intCast(max_entries)), store.activeCount());
    try std.testing.expectError(
        error.StoreFull,
        store.upsert("example.com", "token-overflow", "thumbprint", 999),
    );
}

test "Http01Store expire removes expired subset" {
    var store = Http01Store.init();
    try store.upsert("example.com", "token-a", "thumbprint-a", 100);
    try store.upsert("example.com", "token-b", "thumbprint-b", 200);

    const expired = store.expire(150);
    try std.testing.expectEqual(@as(u8, 1), expired);
    try std.testing.expectEqual(@as(u8, 1), store.activeCount());
    try std.testing.expect(store.lookup("example.com", "token-a", 151) == null);
    try std.testing.expect(store.lookup("example.com", "token-b", 151) != null);
}
