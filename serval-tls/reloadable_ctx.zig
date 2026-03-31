//! Reloadable server TLS context manager.
//!
//! Tracks active SSL_CTX generation with bounded retired slots and explicit
//! acquire/release for in-flight handshakes.
//! TigerStyle: Fixed-capacity slots, explicit state, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const ssl = @import("ssl.zig");

const slot_capacity: usize = 5;
const mutex_lock_max_attempts: u32 = 1_000_000;

/// Errors returned by `ReloadableServerCtx` lease/reload operations.
/// `error.NoActiveContext` is returned by `acquire` when no valid active slot/context is available.
/// `error.RefCountOverflow` is returned by `acquire` when the active slot lease counter cannot be incremented.
/// `error.NoFreeSlot` is returned by `activate` when every fixed-capacity slot is already in use.
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

/// Snapshot of an acquired TLS context slot, returned by `ReloadableServerCtx.acquire`.
/// `ctx` points to the leased `SSL_CTX`; `generation` and `slot_index` identify the exact slot/version.
/// Treat this as an opaque handle: pass the same value back to `ReloadableServerCtx.release` unchanged.
/// Lifetime is tied to the lease; releasing decrements the slot refcount and may allow retired contexts to be freed.
pub const Lease = struct {
    ctx: *ssl.SSL_CTX,
    generation: u32,
    slot_index: u8,
};

/// Thread-safe manager for a reloadable server `SSL_CTX` using fixed slots and generation tracking.
/// `init` requires a non-null initial context pointer; slot capacity is compile-time constrained to `[2, maxInt(u8)+1]`.
/// `acquire` returns a `Lease` for the current active context and increments that slot's refcount under `mutex`.
/// `acquire` fails with `error.NoActiveContext` if no valid active slot exists, or `error.RefCountOverflow` on saturation.
/// `deinit` frees all used slot contexts and asserts all slot refcounts are zero (no outstanding leases).
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

    /// Initializes a `ReloadableServerCtx` with `initial_ctx` as the active TLS context.
    /// Preconditions: `initial_ctx` must be non-null (`assert(@intFromPtr(initial_ctx) != 0)`).
    /// The returned manager starts with slot `0` marked used/active, generation `1`, and ref count `0`.
    /// `next_generation` is set to `2`; the context pointer is stored as-is (caller must keep it valid).
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

    /// Deinitializes all occupied TLS context slots in this reloadable server context.
    /// Preconditions: `self` must be a valid non-null pointer, and every `used` slot must have `ref_count == 0` (enforced by `assert`).
    /// Takes `self.mutex` for the full operation, frees each slot's `SSL_CTX` when present, then resets the slot to empty.
    /// This function returns no errors; violated preconditions trigger assertion failure.
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

    /// Acquires a `Lease` for the currently active TLS context slot.
    /// Requires `self` to be a valid pointer; the active slot index must remain within `slot_capacity` (asserted).
    /// Under `self.mutex`, this validates that the active slot is `used`, `active`, and has a non-null `ctx`, then increments `ref_count`.
    /// Returns `error.NoActiveContext` if no usable active context exists, or `error.RefCountOverflow` if `ref_count` is already `maxInt(u32)`.
    /// The returned lease carries `ctx`, `generation`, and `slot_index`, and represents one counted reference to that slot.
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

    /// Releases one held `Lease` reference back to this reloadable server context.
    /// Preconditions: `lease` must originate from this instance and still match the slot (`slot_index`, `generation`, and `ctx`); violations trip assertions.
    /// Decrements the slot `ref_count` under the mutex and returns immediately if the slot is still active or still referenced.
    /// When the slot is inactive and this was the last reference, the slot is freed (`freeSlotLocked`); this function does not return an error.
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

    /// Atomically switches the active TLS server context to `new_ctx` under the internal mutex and returns the assigned generation.
    /// `self` and `new_ctx` must be valid non-null pointers (enforced by assertions).
    /// Fails with `error.NoFreeSlot` when no inactive slot is available; on failure, the active slot is unchanged.
    /// Marks the previous active slot inactive and frees it immediately only if its `ref_count` is zero.
    /// Generation increments with wraparound and never returns `0` (that value is skipped).
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

    /// Returns the generation number of the currently active TLS context slot.
    /// Requires `self` to be a valid non-null `*ReloadableServerCtx`.
    /// Acquires `self.mutex` for the read and releases it before returning; the value is a snapshot taken under lock.
    /// Asserts that the selected slot is both `used` and `active`; assertion failures indicate broken internal invariants.
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
