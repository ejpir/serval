//! Reloadable server TLS context manager.
//!
//! Tracks active SSL_CTX generation with bounded retired slots and explicit
//! acquire/release for in-flight handshakes.
//! TigerStyle: Fixed-capacity slots, explicit state, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const ssl = @import("ssl.zig");
const config = @import("serval-core").config;

const slot_capacity: usize = config.TLS_RELOADABLE_CTX_SLOT_COUNT;
const mutex_lock_max_attempts: u32 = 1_000_000;

pub const Error = error{
    NoActiveContext,
    RefCountOverflow,
    NoFreeSlot,
};

const Slot = struct {
    used: bool = false,
    active: bool = false,
    generation: u32 = 0,
    ref_count: u32 = 0,
    ctx: ?*ssl.SSL_CTX = null,
};

pub const Lease = struct {
    ctx: *ssl.SSL_CTX,
    generation: u32,
    slot_index: u8,
};

pub const ReloadableServerCtx = struct {
    mutex: std.atomic.Mutex = .unlocked,
    slots: [slot_capacity]Slot = [_]Slot{.{}} ** slot_capacity,
    active_slot_index: u8 = 0,
    next_generation: u32 = 2,

    comptime {
        if (slot_capacity < 2) {
            @compileError("ReloadableServerCtx requires at least 2 slots");
        }
        if (slot_capacity > std.math.maxInt(u8) + 1) {
            @compileError("ReloadableServerCtx slot capacity exceeds u8 index range");
        }
    }

    pub fn init(initial_ctx: *ssl.SSL_CTX) ReloadableServerCtx {
        assert(@intFromPtr(initial_ctx) != 0);

        var manager = ReloadableServerCtx{};
        manager.slots[0] = .{
            .used = true,
            .active = true,
            .generation = 1,
            .ref_count = 0,
            .ctx = initial_ctx,
        };
        manager.active_slot_index = 0;
        manager.next_generation = 2;
        return manager;
    }

    pub fn deinit(self: *ReloadableServerCtx) void {
        assert(@intFromPtr(self) != 0);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();

        var index: usize = 0;
        while (index < self.slots.len) : (index += 1) {
            const slot = self.slots[index];
            if (!slot.used) continue;

            assert(slot.ref_count == 0);
            if (slot.ctx) |ctx| ssl.SSL_CTX_free(ctx);
            self.slots[index] = .{};
        }
    }

    pub fn acquire(self: *ReloadableServerCtx) Error!Lease {
        assert(@intFromPtr(self) != 0);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();

        const slot_index = self.active_slot_index;
        assert(slot_index < slot_capacity);
        const slot = &self.slots[slot_index];

        if (!slot.used or !slot.active or slot.ctx == null) {
            return error.NoActiveContext;
        }
        if (slot.ref_count == std.math.maxInt(u32)) {
            return error.RefCountOverflow;
        }

        slot.ref_count += 1;
        return .{
            .ctx = slot.ctx.?,
            .generation = slot.generation,
            .slot_index = slot_index,
        };
    }

    pub fn release(self: *ReloadableServerCtx, lease: Lease) void {
        assert(@intFromPtr(self) != 0);
        assert(lease.slot_index < slot_capacity);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();

        var slot = &self.slots[lease.slot_index];
        assert(slot.used);
        assert(slot.generation == lease.generation);
        assert(slot.ctx == lease.ctx);
        assert(slot.ref_count > 0);

        slot.ref_count -= 1;
        if (slot.active) return;
        if (slot.ref_count > 0) return;

        freeSlotLocked(slot);
    }

    pub fn activate(self: *ReloadableServerCtx, new_ctx: *ssl.SSL_CTX) Error!u32 {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(new_ctx) != 0);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();

        const free_index = findFreeSlotLocked(self) orelse return error.NoFreeSlot;
        const old_index = self.active_slot_index;
        const old_slot = &self.slots[old_index];
        assert(old_slot.used);
        assert(old_slot.active);

        old_slot.active = false;

        const generation = self.next_generation;
        self.next_generation +%= 1;
        if (self.next_generation == 0) self.next_generation = 1;

        self.slots[free_index] = .{
            .used = true,
            .active = true,
            .generation = generation,
            .ref_count = 0,
            .ctx = new_ctx,
        };
        self.active_slot_index = @intCast(free_index);

        if (old_slot.ref_count == 0) {
            freeSlotLocked(old_slot);
        }

        return generation;
    }

    /// Build a new server SSL context from PEM files and atomically activate it.
    /// Existing handshakes keep using leased generations until release.
    pub fn activateFromPemFiles(
        self: *ReloadableServerCtx,
        cert_path: []const u8,
        key_path: []const u8,
    ) (Error || ssl.CreateServerCtxFromPemFilesError)!u32 {
        assert(@intFromPtr(self) != 0);

        if (cert_path.len == 0) return error.InvalidCertPath;
        if (key_path.len == 0) return error.InvalidKeyPath;
        assert(cert_path.len > 0);
        assert(key_path.len > 0);

        const new_ctx = try ssl.createServerCtxFromPemFiles(cert_path, key_path);
        errdefer ssl.SSL_CTX_free(new_ctx);

        const generation = try self.activate(new_ctx);
        assert(generation > 0);
        return generation;
    }

    pub fn activeGeneration(self: *ReloadableServerCtx) u32 {
        assert(@intFromPtr(self) != 0);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();

        const slot = self.slots[self.active_slot_index];
        assert(slot.used and slot.active);
        return slot.generation;
    }

    fn findFreeSlotLocked(self: *ReloadableServerCtx) ?usize {
        assert(@intFromPtr(self) != 0);

        var index: usize = 0;
        while (index < self.slots.len) : (index += 1) {
            if (!self.slots[index].used) return index;
        }
        return null;
    }

    fn freeSlotLocked(slot: *Slot) void {
        assert(@intFromPtr(slot) != 0);
        assert(slot.used);
        assert(!slot.active);
        assert(slot.ref_count == 0);

        if (slot.ctx) |ctx| ssl.SSL_CTX_free(ctx);
        slot.* = .{};
    }
};

fn lockMutex(mutex: *std.atomic.Mutex) void {
    assert(@intFromPtr(mutex) != 0);

    var attempts: u32 = 0;
    while (attempts < mutex_lock_max_attempts) : (attempts += 1) {
        if (mutex.tryLock()) return;
        std.atomic.spinLoopHint();
    }

    @panic("ReloadableServerCtx mutex lock timeout");
}

fn createServerCtxForTest() !*ssl.SSL_CTX {
    ssl.init();
    return ssl.createServerCtx();
}

test "ReloadableServerCtx acquires and releases active generation" {
    const ctx = try createServerCtxForTest();
    var manager = ReloadableServerCtx.init(ctx);
    defer manager.deinit();

    const lease = try manager.acquire();
    try std.testing.expectEqual(@as(u32, 1), lease.generation);
    manager.release(lease);

    try std.testing.expectEqual(@as(u32, 1), manager.activeGeneration());
}

test "ReloadableServerCtx activation swaps active generation" {
    const ctx_one = try createServerCtxForTest();
    var manager = ReloadableServerCtx.init(ctx_one);
    defer manager.deinit();

    const old_lease = try manager.acquire();

    const ctx_two = try createServerCtxForTest();
    const generation_two = try manager.activate(ctx_two);
    try std.testing.expectEqual(@as(u32, 2), generation_two);

    const new_lease = try manager.acquire();
    try std.testing.expect(new_lease.ctx == ctx_two);
    try std.testing.expectEqual(generation_two, new_lease.generation);

    manager.release(new_lease);
    manager.release(old_lease);

    try std.testing.expectEqual(generation_two, manager.activeGeneration());
}

test "ReloadableServerCtx activation fails when slots are exhausted" {
    const first_ctx = try createServerCtxForTest();
    var manager = ReloadableServerCtx.init(first_ctx);
    defer manager.deinit();

    var held_leases: [slot_capacity]?Lease = [_]?Lease{null} ** slot_capacity;
    held_leases[0] = try manager.acquire();

    var index: usize = 1;
    while (index < slot_capacity) : (index += 1) {
        const next_ctx = try createServerCtxForTest();
        _ = try manager.activate(next_ctx);
        held_leases[index] = try manager.acquire();
    }

    const overflow_ctx = try createServerCtxForTest();
    try std.testing.expectError(error.NoFreeSlot, manager.activate(overflow_ctx));
    ssl.SSL_CTX_free(overflow_ctx);

    var release_index: usize = 0;
    while (release_index < held_leases.len) : (release_index += 1) {
        if (held_leases[release_index]) |lease| {
            manager.release(lease);
        }
    }
}

test "ReloadableServerCtx activateFromPemFiles preserves generation on validation error" {
    const first_ctx = try createServerCtxForTest();
    var manager = ReloadableServerCtx.init(first_ctx);
    defer manager.deinit();

    try std.testing.expectError(
        error.InvalidCertPath,
        manager.activateFromPemFiles("", "/tmp/non-empty-key.pem"),
    );
    try std.testing.expectEqual(@as(u32, 1), manager.activeGeneration());
}
