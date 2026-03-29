//! Public filter SDK types.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");

/// Maximum allowed header tag key size in bytes.
/// SDK helpers enforce this limit before forwarding tag keys to the host.
/// Keys must also be non-empty when used through the public API.
pub const MAX_TAG_KEY_BYTES: u32 = 64;
/// Maximum allowed header tag value size in bytes.
/// SDK helpers enforce this limit before forwarding tag values to the host.
/// Values longer than this limit are rejected by assertions in the public API.
pub const MAX_TAG_VALUE_BYTES: u32 = 256;

/// Re-export of `core.RejectResponse` for filter SDK consumers.
/// Use this alias when constructing a `Decision.reject` response.
/// Ownership and semantics are defined by `serval-core`.
pub const RejectResponse = core.RejectResponse;

/// Borrowed header fields exposed through the SDK read and write views.
/// Both `name` and `value` reference existing storage and are not owned by this type.
/// Do not retain these slices longer than the backing header storage remains valid.
pub const HeaderView = struct {
    name: []const u8,
    value: []const u8,
};

/// Read-only view over a contiguous slice of `core.Header` values.
/// Header names and values are borrowed; the view does not own the underlying storage.
/// Use `len` and `get` to inspect the slice without mutating it.
pub const HeaderSliceView = struct {
    headers: []const core.Header,

    /// Returns the number of headers currently visible through this read-only view.
    /// The result is the length of the backing header slice.
    /// This method does not allocate and cannot fail.
    pub fn len(self: HeaderSliceView) usize {
        return self.headers.len;
    }

    /// Returns the header at `idx`, or `null` when the index is out of bounds.
    /// The returned view borrows the underlying header name and value slices.
    /// This method does not allocate and never mutates the source slice.
    pub fn get(self: HeaderSliceView, idx: usize) ?HeaderView {
        if (idx >= self.headers.len) return null;
        const h = self.headers[idx];
        return .{ .name = h.name, .value = h.value };
    }
};

/// Error returned when a write view has no remaining header capacity.
/// This occurs only when inserting a new header into a full storage buffer.
/// Updating an existing header does not use this error.
pub const HeaderWriteError = error{
    TooManyHeaders,
};

/// Mutable header buffer view backed by caller-owned storage.
/// This type provides in-place read, update, insert, and removal operations over a prefix of `storage`.
/// The `count` pointer tracks the populated header prefix and must remain valid for the lifetime of the view.
pub const HeaderWriteView = struct {
    storage: []core.Header,
    count: *u32,

    /// Initialize a header write view over existing storage and a live count pointer.
    /// `count` must point to valid storage and its current value must not exceed `storage.len`.
    /// The view borrows both arguments and does not allocate or copy headers.
    pub fn init(storage: []core.Header, count: *u32) HeaderWriteView {
        assert(@intFromPtr(count) != 0);
        assert(count.* <= storage.len);
        return .{ .storage = storage, .count = count };
    }

    /// Return the number of populated headers in the view.
    /// This is the logical length tracked by `count`, not the total storage capacity.
    /// The result is always less than or equal to the backing storage length.
    pub fn len(self: HeaderWriteView) usize {
        return self.count.*;
    }

    /// Return the header at `idx` when it is within the populated range.
    /// Returns `null` when `idx` is out of bounds.
    /// The returned header values are copied out as a lightweight view of the stored name and value slices.
    pub fn get(self: HeaderWriteView, idx: usize) ?HeaderView {
        if (idx >= self.count.*) return null;
        const h = self.storage[idx];
        return .{ .name = h.name, .value = h.value };
    }

    /// Produce a read-only slice view over the populated portion of this header buffer.
    /// The returned view borrows the same backing storage and remains valid only while the storage and count stay valid.
    /// No copying is performed.
    pub fn asReadOnly(self: HeaderWriteView) HeaderSliceView {
        return .{ .headers = self.storage[0..self.count.*] };
    }

    /// Insert a new header or update the first case-insensitive match in place.
    /// When a matching header exists, only its value is replaced and the header count is unchanged.
    /// Returns `error.TooManyHeaders` if the backing storage is full; `name` must be non-empty.
    pub fn upsert(self: *HeaderWriteView, name: []const u8, value: []const u8) HeaderWriteError!void {
        assert(@intFromPtr(self) != 0);
        assert(name.len > 0);

        var index: usize = 0;
        while (index < self.count.*) : (index += 1) {
            if (std.ascii.eqlIgnoreCase(self.storage[index].name, name)) {
                self.storage[index].value = value;
                return;
            }
        }

        if (self.count.* >= self.storage.len) return error.TooManyHeaders;
        const write_index: usize = @intCast(self.count.*);
        self.storage[write_index] = .{ .name = name, .value = value };
        self.count.* += 1;
    }

    /// Remove the first header whose name matches `name` case-insensitively.
    /// Returns `true` when a header was removed and the remaining entries were compacted in place.
    /// Returns `false` when no matching header exists; `name` must be non-empty.
    pub fn remove(self: *HeaderWriteView, name: []const u8) bool {
        assert(@intFromPtr(self) != 0);
        assert(name.len > 0);

        var index: usize = 0;
        while (index < self.count.*) : (index += 1) {
            if (!std.ascii.eqlIgnoreCase(self.storage[index].name, name)) continue;

            var shift: usize = index;
            while (shift + 1 < self.count.*) : (shift += 1) {
                self.storage[shift] = self.storage[shift + 1];
            }
            self.count.* -= 1;
            return true;
        }

        return false;
    }
};

/// A view over one chunk of emitted bytes.
/// `bytes` references the chunk payload and is borrowed from the producer.
/// `is_last` marks the final chunk in a sequence so consumers can detect stream completion.
pub const ChunkView = struct {
    bytes: []const u8,
    is_last: bool,
};

/// Decision returned by a filter after processing a request or stream chunk.
/// `continue_filtering` allows the chain to proceed, `reject` returns a rejection response, and `bypass_plugin` skips the current plugin.
/// The `reject` payload carries the response details used to terminate the request.
pub const Decision = union(enum) {
    continue_filtering,
    reject: RejectResponse,
    bypass_plugin,
};

/// Errors returned by `EmitWriter.emit`.
/// `OutputLimitExceeded` means the next write would exceed the configured byte budget.
/// `WriteFailed` represents a failure reported by the underlying writer callback.
pub const EmitError = error{
    OutputLimitExceeded,
    WriteFailed,
};

/// Writer state for bounded emission into an opaque sink.
/// `ctx` is passed back to `write_fn` on every emit call; the writer does not own that memory.
/// `max_bytes` limits the total bytes that may be successfully emitted through this instance.
pub const EmitWriter = struct {
    ctx: *anyopaque,
    write_fn: *const fn (ctx: *anyopaque, bytes: []const u8) EmitError!void,
    max_bytes: u64,
    emitted_bytes: u64,

    /// Initialize an `EmitWriter` with a context pointer, write callback, and maximum byte budget.
    /// `ctx` must be valid and non-null, and `max_bytes` must be greater than zero.
    /// The returned writer starts with zero emitted bytes.
    pub fn init(
        ctx: *anyopaque,
        write_fn: *const fn (ctx: *anyopaque, bytes: []const u8) EmitError!void,
        max_bytes: u64,
    ) EmitWriter {
        assert(@intFromPtr(ctx) != 0);
        assert(max_bytes > 0);

        return .{
            .ctx = ctx,
            .write_fn = write_fn,
            .max_bytes = max_bytes,
            .emitted_bytes = 0,
        };
    }

    /// Emit a byte slice through the configured writer while enforcing the byte budget.
    /// An empty slice is a no-op.
    /// Returns `error.OutputLimitExceeded` if the write would exceed `max_bytes`, and propagates writer failures.
    pub fn emit(self: *EmitWriter, bytes: []const u8) EmitError!void {
        assert(@intFromPtr(self) != 0);
        if (bytes.len == 0) return;

        const next_total = self.emitted_bytes + bytes.len;
        if (next_total > self.max_bytes) return error.OutputLimitExceeded;

        try self.write_fn(self.ctx, bytes);
        self.emitted_bytes = next_total;
        assert(self.emitted_bytes <= self.max_bytes);
    }
};

/// Request-scoped observation context passed to filter instrumentation hooks.
/// The string fields are borrowed slices; the caller retains ownership of the backing storage.
/// Hook pointers are optional and are invoked only when both the function and `observe_ctx` are present.
pub const FilterContext = struct {
    route_id: []const u8,
    chain_id: []const u8,
    plugin_id: []const u8,
    request_id: u64,
    stream_id: u64,
    set_tag_fn: ?*const fn (ctx: *anyopaque, key: []const u8, value: []const u8) void = null,
    incr_counter_fn: ?*const fn (ctx: *anyopaque, key: []const u8, delta: u64) void = null,
    observe_ctx: ?*anyopaque = null,

    /// Set or replace an observation tag for the current filter context.
    /// Does nothing when no tag hook or observation context is installed.
    /// `key` must be non-empty and at most `MAX_TAG_KEY_BYTES`; `value` must be at most `MAX_TAG_VALUE_BYTES`.
    pub fn setTag(self: *FilterContext, key: []const u8, value: []const u8) void {
        assert(@intFromPtr(self) != 0);
        assert(key.len > 0 and key.len <= MAX_TAG_KEY_BYTES);
        assert(value.len <= MAX_TAG_VALUE_BYTES);

        const f = self.set_tag_fn orelse return;
        const ctx = self.observe_ctx orelse return;
        f(ctx, key, value);
    }

    /// Increment an observation counter for the current filter context.
    /// Does nothing when no counter hook or observation context is installed.
    /// `key` must be non-empty and at most `MAX_TAG_KEY_BYTES`; `delta` must be greater than zero.
    pub fn incrementCounter(self: *FilterContext, key: []const u8, delta: u64) void {
        assert(@intFromPtr(self) != 0);
        assert(key.len > 0 and key.len <= MAX_TAG_KEY_BYTES);
        assert(delta > 0);

        const f = self.incr_counter_fn orelse return;
        const ctx = self.observe_ctx orelse return;
        f(ctx, key, delta);
    }
};

test "EmitWriter enforces output bounds" {
    const Sink = struct {
        total: u64 = 0,
        fn write(ctx: *anyopaque, bytes: []const u8) EmitError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.total += bytes.len;
        }
    };

    var sink = Sink{};
    var writer = EmitWriter.init(&sink, Sink.write, 4);
    try writer.emit("ab");
    try writer.emit("cd");
    try std.testing.expectEqual(@as(u64, 4), sink.total);
    try std.testing.expectError(error.OutputLimitExceeded, writer.emit("x"));
}
