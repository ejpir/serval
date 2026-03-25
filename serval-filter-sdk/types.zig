//! Public filter SDK types.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");

pub const MAX_TAG_KEY_BYTES: u32 = 64;
pub const MAX_TAG_VALUE_BYTES: u32 = 256;

pub const RejectResponse = core.RejectResponse;

pub const HeaderView = struct {
    name: []const u8,
    value: []const u8,
};

pub const HeaderSliceView = struct {
    headers: []const core.Header,

    pub fn len(self: HeaderSliceView) usize {
        return self.headers.len;
    }

    pub fn get(self: HeaderSliceView, idx: usize) ?HeaderView {
        if (idx >= self.headers.len) return null;
        const h = self.headers[idx];
        return .{ .name = h.name, .value = h.value };
    }
};

pub const ChunkView = struct {
    bytes: []const u8,
    is_last: bool,
};

pub const Decision = union(enum) {
    continue_filtering,
    reject: RejectResponse,
    bypass_plugin,
};

pub const EmitError = error{
    OutputLimitExceeded,
    WriteFailed,
};

pub const EmitWriter = struct {
    ctx: *anyopaque,
    write_fn: *const fn (ctx: *anyopaque, bytes: []const u8) EmitError!void,
    max_bytes: u64,
    emitted_bytes: u64,

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

pub const FilterContext = struct {
    route_id: []const u8,
    chain_id: []const u8,
    plugin_id: []const u8,
    request_id: u64,
    stream_id: u64,
    set_tag_fn: ?*const fn (ctx: *anyopaque, key: []const u8, value: []const u8) void = null,
    incr_counter_fn: ?*const fn (ctx: *anyopaque, key: []const u8, delta: u64) void = null,
    observe_ctx: ?*anyopaque = null,

    pub fn setTag(self: *FilterContext, key: []const u8, value: []const u8) void {
        assert(@intFromPtr(self) != 0);
        assert(key.len > 0 and key.len <= MAX_TAG_KEY_BYTES);
        assert(value.len <= MAX_TAG_VALUE_BYTES);

        const f = self.set_tag_fn orelse return;
        const ctx = self.observe_ctx orelse return;
        f(ctx, key, value);
    }

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
