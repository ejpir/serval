//! HTTP/2 Stream Binding Table
//!
//! Fixed-capacity downstream↔upstream stream bindings for future stream-aware
//! proxying.
//! TigerStyle: Explicit mapping, bounded table, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;

const capacity: usize = config.H2_MAX_CONCURRENT_STREAMS;

pub const Error = error{
    DuplicateDownstreamStream,
    DuplicateUpstreamStream,
    BindingTableFull,
    BindingNotFound,
};

pub const Binding = struct {
    downstream_stream_id: u32,
    upstream_stream_id: u32,
    upstream_index: config.UpstreamIndex,
    upstream_session_generation: u32,
};

const Slot = struct {
    used: bool = false,
    binding: Binding = .{
        .downstream_stream_id = 0,
        .upstream_stream_id = 0,
        .upstream_index = 0,
        .upstream_session_generation = 0,
    },
};

pub const BindingTable = struct {
    slots: [capacity]Slot = [_]Slot{.{}} ** capacity,
    count: u16 = 0,

    pub fn init() BindingTable {
        return .{};
    }

    pub fn put(self: *BindingTable, binding: Binding) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(binding.downstream_stream_id > 0);
        assert(binding.upstream_stream_id > 0);
        assert(binding.upstream_session_generation > 0);

        if (self.getByDownstream(binding.downstream_stream_id) != null) {
            return error.DuplicateDownstreamStream;
        }
        if (self.getByUpstreamForSession(binding.upstream_index, binding.upstream_session_generation, binding.upstream_stream_id) != null) {
            return error.DuplicateUpstreamStream;
        }

        const index = self.allocSlot() orelse return error.BindingTableFull;
        self.slots[index] = .{ .used = true, .binding = binding };
        self.count += 1;
    }

    pub fn getByDownstream(self: *const BindingTable, stream_id: u32) ?Binding {
        assert(@intFromPtr(self) != 0);
        assert(self.count <= config.H2_MAX_CONCURRENT_STREAMS);

        for (self.slots) |slot| {
            if (!slot.used) continue;
            if (slot.binding.downstream_stream_id == stream_id) return slot.binding;
        }
        return null;
    }

    pub fn getByUpstream(self: *const BindingTable, stream_id: u32) ?Binding {
        assert(@intFromPtr(self) != 0);
        assert(self.count <= config.H2_MAX_CONCURRENT_STREAMS);

        for (self.slots) |slot| {
            if (!slot.used) continue;
            if (slot.binding.upstream_stream_id == stream_id) return slot.binding;
        }
        return null;
    }

    pub fn getByUpstreamForIndex(
        self: *const BindingTable,
        upstream_index: config.UpstreamIndex,
        stream_id: u32,
    ) ?Binding {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        assert(self.count <= config.H2_MAX_CONCURRENT_STREAMS);

        for (self.slots) |slot| {
            if (!slot.used) continue;
            if (slot.binding.upstream_index != upstream_index) continue;
            if (slot.binding.upstream_stream_id == stream_id) return slot.binding;
        }
        return null;
    }

    pub fn getByUpstreamForSession(
        self: *const BindingTable,
        upstream_index: config.UpstreamIndex,
        upstream_session_generation: u32,
        stream_id: u32,
    ) ?Binding {
        assert(@intFromPtr(self) != 0);
        assert(upstream_session_generation > 0);
        assert(stream_id > 0);
        assert(self.count <= config.H2_MAX_CONCURRENT_STREAMS);

        for (self.slots) |slot| {
            if (!slot.used) continue;
            if (slot.binding.upstream_index != upstream_index) continue;
            if (slot.binding.upstream_session_generation != upstream_session_generation) continue;
            if (slot.binding.upstream_stream_id == stream_id) return slot.binding;
        }
        return null;
    }

    pub fn removeByDownstream(self: *BindingTable, stream_id: u32) Error!Binding {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        for (self.slots, 0..) |slot, index| {
            if (!slot.used) continue;
            if (slot.binding.downstream_stream_id != stream_id) continue;

            const binding = slot.binding;
            self.slots[index] = .{};
            assert(self.count > 0);
            self.count -= 1;
            return binding;
        }

        return error.BindingNotFound;
    }

    pub fn removeByUpstream(self: *BindingTable, stream_id: u32) Error!Binding {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const binding = self.getByUpstream(stream_id) orelse return error.BindingNotFound;
        return self.removeByDownstream(binding.downstream_stream_id);
    }

    pub fn removeAllForUpstream(self: *BindingTable, upstream_index: config.UpstreamIndex) u16 {
        assert(@intFromPtr(self) != 0);

        var removed_count: u16 = 0;
        for (self.slots, 0..) |slot, index| {
            if (!slot.used) continue;
            if (slot.binding.upstream_index != upstream_index) continue;

            self.slots[index] = .{};
            assert(self.count > 0);
            self.count -= 1;
            removed_count += 1;
        }

        return removed_count;
    }

    pub fn removeAllForUpstreamSession(
        self: *BindingTable,
        upstream_index: config.UpstreamIndex,
        upstream_session_generation: u32,
    ) u16 {
        assert(@intFromPtr(self) != 0);
        assert(upstream_session_generation > 0);

        var removed_count: u16 = 0;
        for (self.slots, 0..) |slot, index| {
            if (!slot.used) continue;
            if (slot.binding.upstream_index != upstream_index) continue;
            if (slot.binding.upstream_session_generation != upstream_session_generation) continue;

            self.slots[index] = .{};
            assert(self.count > 0);
            self.count -= 1;
            removed_count += 1;
        }

        return removed_count;
    }

    pub fn removeAllForUpstreamSessionAboveLastStreamId(
        self: *BindingTable,
        upstream_index: config.UpstreamIndex,
        upstream_session_generation: u32,
        last_stream_id: u32,
    ) u16 {
        assert(@intFromPtr(self) != 0);
        assert(upstream_session_generation > 0);

        var removed_count: u16 = 0;
        for (self.slots, 0..) |slot, index| {
            if (!slot.used) continue;
            if (slot.binding.upstream_index != upstream_index) continue;
            if (slot.binding.upstream_session_generation != upstream_session_generation) continue;
            if (slot.binding.upstream_stream_id <= last_stream_id) continue;

            self.slots[index] = .{};
            assert(self.count > 0);
            self.count -= 1;
            removed_count += 1;
        }

        return removed_count;
    }

    fn allocSlot(self: *const BindingTable) ?usize {
        if (self.count >= config.H2_MAX_CONCURRENT_STREAMS) return null;

        for (self.slots, 0..) |slot, index| {
            if (!slot.used) return index;
        }
        return null;
    }
};

test "BindingTable stores and retrieves bindings" {
    var table = BindingTable.init();
    const binding = Binding{ .downstream_stream_id = 1, .upstream_stream_id = 11, .upstream_index = 3, .upstream_session_generation = 1 };

    try table.put(binding);
    try std.testing.expectEqualDeep(binding, table.getByDownstream(1).?);
    try std.testing.expectEqualDeep(binding, table.getByUpstream(11).?);
    try std.testing.expectEqualDeep(binding, table.getByUpstreamForIndex(3, 11).?);
}

test "BindingTable getByUpstreamForIndex disambiguates equal stream ids" {
    var table = BindingTable.init();
    try table.put(.{ .downstream_stream_id = 1, .upstream_stream_id = 7, .upstream_index = 0, .upstream_session_generation = 1 });
    try table.put(.{ .downstream_stream_id = 3, .upstream_stream_id = 7, .upstream_index = 1, .upstream_session_generation = 1 });

    const first = table.getByUpstreamForIndex(0, 7) orelse return error.MissingBinding;
    const second = table.getByUpstreamForIndex(1, 7) orelse return error.MissingBinding;

    try std.testing.expectEqual(@as(u32, 1), first.downstream_stream_id);
    try std.testing.expectEqual(@as(u32, 3), second.downstream_stream_id);
}

test "BindingTable rejects duplicate downstream stream" {
    var table = BindingTable.init();
    try table.put(.{ .downstream_stream_id = 1, .upstream_stream_id = 11, .upstream_index = 0, .upstream_session_generation = 1 });
    try std.testing.expectError(
        error.DuplicateDownstreamStream,
        table.put(.{ .downstream_stream_id = 1, .upstream_stream_id = 13, .upstream_index = 0, .upstream_session_generation = 1 }),
    );
}

test "BindingTable rejects duplicate upstream stream" {
    var table = BindingTable.init();
    try table.put(.{ .downstream_stream_id = 1, .upstream_stream_id = 11, .upstream_index = 0, .upstream_session_generation = 1 });
    try std.testing.expectError(
        error.DuplicateUpstreamStream,
        table.put(.{ .downstream_stream_id = 3, .upstream_stream_id = 11, .upstream_index = 0, .upstream_session_generation = 1 }),
    );
}

test "BindingTable allows equal upstream stream ids across session generations" {
    var table = BindingTable.init();
    try table.put(.{ .downstream_stream_id = 1, .upstream_stream_id = 11, .upstream_index = 0, .upstream_session_generation = 1 });
    try table.put(.{ .downstream_stream_id = 3, .upstream_stream_id = 11, .upstream_index = 0, .upstream_session_generation = 2 });

    const first = table.getByUpstreamForSession(0, 1, 11) orelse return error.MissingBinding;
    const second = table.getByUpstreamForSession(0, 2, 11) orelse return error.MissingBinding;
    try std.testing.expectEqual(@as(u32, 1), first.downstream_stream_id);
    try std.testing.expectEqual(@as(u32, 3), second.downstream_stream_id);
}

test "BindingTable removes bindings" {
    var table = BindingTable.init();
    const binding = Binding{ .downstream_stream_id = 1, .upstream_stream_id = 11, .upstream_index = 0, .upstream_session_generation = 1 };
    try table.put(binding);

    const removed = try table.removeByDownstream(1);
    try std.testing.expectEqualDeep(binding, removed);
    try std.testing.expect(table.getByDownstream(1) == null);
}

test "BindingTable removes by upstream stream id" {
    var table = BindingTable.init();
    const binding = Binding{ .downstream_stream_id = 3, .upstream_stream_id = 13, .upstream_index = 1, .upstream_session_generation = 1 };
    try table.put(binding);

    const removed = try table.removeByUpstream(13);
    try std.testing.expectEqualDeep(binding, removed);
    try std.testing.expect(table.getByUpstream(13) == null);
    try std.testing.expectEqual(@as(u16, 0), table.count);
}

test "BindingTable removes all bindings for one upstream index" {
    var table = BindingTable.init();
    try table.put(.{ .downstream_stream_id = 1, .upstream_stream_id = 11, .upstream_index = 0, .upstream_session_generation = 1 });
    try table.put(.{ .downstream_stream_id = 3, .upstream_stream_id = 13, .upstream_index = 1, .upstream_session_generation = 1 });
    try table.put(.{ .downstream_stream_id = 5, .upstream_stream_id = 15, .upstream_index = 1, .upstream_session_generation = 2 });

    const removed_count = table.removeAllForUpstream(1);
    try std.testing.expectEqual(@as(u16, 2), removed_count);
    try std.testing.expectEqual(@as(u16, 1), table.count);
    try std.testing.expect(table.getByDownstream(1) != null);
    try std.testing.expect(table.getByDownstream(3) == null);
    try std.testing.expect(table.getByDownstream(5) == null);
}

test "BindingTable removes all bindings for one upstream session generation" {
    var table = BindingTable.init();
    try table.put(.{ .downstream_stream_id = 1, .upstream_stream_id = 11, .upstream_index = 1, .upstream_session_generation = 1 });
    try table.put(.{ .downstream_stream_id = 3, .upstream_stream_id = 11, .upstream_index = 1, .upstream_session_generation = 2 });

    const removed_count = table.removeAllForUpstreamSession(1, 1);
    try std.testing.expectEqual(@as(u16, 1), removed_count);
    try std.testing.expect(table.getByDownstream(1) == null);
    try std.testing.expect(table.getByDownstream(3) != null);
}

test "BindingTable removes only streams above GOAWAY last_stream_id for one session" {
    var table = BindingTable.init();
    try table.put(.{ .downstream_stream_id = 1, .upstream_stream_id = 1, .upstream_index = 2, .upstream_session_generation = 9 });
    try table.put(.{ .downstream_stream_id = 3, .upstream_stream_id = 3, .upstream_index = 2, .upstream_session_generation = 9 });
    try table.put(.{ .downstream_stream_id = 5, .upstream_stream_id = 5, .upstream_index = 2, .upstream_session_generation = 9 });
    try table.put(.{ .downstream_stream_id = 7, .upstream_stream_id = 1, .upstream_index = 2, .upstream_session_generation = 10 });

    const removed_count = table.removeAllForUpstreamSessionAboveLastStreamId(2, 9, 1);
    try std.testing.expectEqual(@as(u16, 2), removed_count);

    try std.testing.expect(table.getByDownstream(1) != null);
    try std.testing.expect(table.getByDownstream(3) == null);
    try std.testing.expect(table.getByDownstream(5) == null);
    try std.testing.expect(table.getByDownstream(7) != null);
    try std.testing.expectEqual(@as(u16, 2), table.count);
}
