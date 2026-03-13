//! HTTP/2 Stream State Machine Helpers
//!
//! Explicit bounded stream lifecycle tracking for future stream-aware HTTP/2
//! transport and proxy code.
//! TigerStyle: Fixed-capacity tables, explicit transitions, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const flow = @import("flow_control.zig");

const table_capacity: usize = config.H2_MAX_CONCURRENT_STREAMS;

pub const Role = enum {
    client,
    server,
};

pub const State = enum {
    idle,
    reserved_local,
    reserved_remote,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

pub const Error = error{
    InvalidStreamId,
    WrongStreamParity,
    StreamIdRegression,
    StreamAlreadyExists,
    StreamTableFull,
    StreamNotFound,
    InvalidTransition,
} || flow.Error;

pub const Stream = struct {
    id: u32 = 0,
    state: State = .idle,
    recv_window: flow.Window = .{ .available_bytes = config.H2_INITIAL_WINDOW_SIZE_BYTES },
    send_window: flow.Window = .{ .available_bytes = config.H2_INITIAL_WINDOW_SIZE_BYTES },

    pub fn init(id: u32) Stream {
        assert(isValidStreamId(id));
        return .{ .id = id };
    }

    pub fn openLocal(self: *Stream, end_stream: bool) Error!void {
        assert(self.id > 0);
        if (self.state != .idle) return error.InvalidTransition;
        self.state = if (end_stream) .half_closed_local else .open;
    }

    pub fn openRemote(self: *Stream, end_stream: bool) Error!void {
        assert(self.id > 0);
        if (self.state != .idle) return error.InvalidTransition;
        self.state = if (end_stream) .half_closed_remote else .open;
    }

    pub fn reserveLocal(self: *Stream) Error!void {
        assert(self.id > 0);
        if (self.state != .idle) return error.InvalidTransition;
        self.state = .reserved_local;
    }

    pub fn reserveRemote(self: *Stream) Error!void {
        assert(self.id > 0);
        if (self.state != .idle) return error.InvalidTransition;
        self.state = .reserved_remote;
    }

    pub fn activateReservedLocal(self: *Stream, end_stream: bool) Error!void {
        assert(self.id > 0);
        if (self.state != .reserved_local) return error.InvalidTransition;
        self.state = if (end_stream) .closed else .half_closed_remote;
    }

    pub fn activateReservedRemote(self: *Stream, end_stream: bool) Error!void {
        assert(self.id > 0);
        if (self.state != .reserved_remote) return error.InvalidTransition;
        self.state = if (end_stream) .closed else .half_closed_local;
    }

    pub fn endLocal(self: *Stream) Error!void {
        assert(self.id > 0);
        self.state = switch (self.state) {
            .open => .half_closed_local,
            .half_closed_remote => .closed,
            else => return error.InvalidTransition,
        };
    }

    pub fn endRemote(self: *Stream) Error!void {
        assert(self.id > 0);
        self.state = switch (self.state) {
            .open => .half_closed_remote,
            .half_closed_local => .closed,
            else => return error.InvalidTransition,
        };
    }

    pub fn reset(self: *Stream) void {
        assert(self.id > 0);
        self.state = .closed;
    }

    pub fn isClosed(self: *const Stream) bool {
        return self.state == .closed;
    }

    pub fn localCanSend(self: *const Stream) bool {
        return switch (self.state) {
            .open, .half_closed_remote => true,
            else => false,
        };
    }

    pub fn remoteCanSend(self: *const Stream) bool {
        return switch (self.state) {
            .open, .half_closed_local => true,
            else => false,
        };
    }

    pub fn configureWindows(self: *Stream, recv_initial_bytes: u32, send_initial_bytes: u32) Error!void {
        assert(self.id > 0);
        assert(recv_initial_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);

        try self.recv_window.set(recv_initial_bytes);
        try self.send_window.set(send_initial_bytes);
    }

    pub fn consumeRecvWindow(self: *Stream, bytes: u32) Error!void {
        assert(self.id > 0);
        assert(bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.recv_window.consume(bytes);
    }

    pub fn consumeSendWindow(self: *Stream, bytes: u32) Error!void {
        assert(self.id > 0);
        assert(bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.send_window.consume(bytes);
    }

    pub fn incrementSendWindow(self: *Stream, delta_bytes: u32) Error!void {
        assert(self.id > 0);
        assert(delta_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.send_window.increment(delta_bytes);
    }

    pub fn incrementRecvWindow(self: *Stream, delta_bytes: u32) Error!void {
        assert(self.id > 0);
        assert(delta_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.recv_window.increment(delta_bytes);
    }
};

const Slot = struct {
    used: bool = false,
    stream: Stream = .{},
};

pub const StreamTable = struct {
    role: Role,
    slots: [table_capacity]Slot = [_]Slot{.{}} ** table_capacity,
    active_count: u16 = 0,
    last_local_stream_id: u32 = 0,
    last_remote_stream_id: u32 = 0,

    pub fn init(role: Role) StreamTable {
        return .{ .role = role };
    }

    pub fn openLocal(self: *StreamTable, stream_id: u32, end_stream: bool) Error!*Stream {
        try validateNewStreamId(self.role, stream_id, .local, self.last_local_stream_id);
        if (self.findIndex(stream_id) != null) return error.StreamAlreadyExists;

        const index = self.allocSlot() orelse return error.StreamTableFull;
        self.slots[index].used = true;
        self.slots[index].stream = Stream.init(stream_id);
        try self.slots[index].stream.openLocal(end_stream);
        self.active_count += 1;
        self.last_local_stream_id = stream_id;
        return &self.slots[index].stream;
    }

    pub fn openRemote(self: *StreamTable, stream_id: u32, end_stream: bool) Error!*Stream {
        try validateNewStreamId(self.role, stream_id, .remote, self.last_remote_stream_id);
        if (self.findIndex(stream_id) != null) return error.StreamAlreadyExists;

        const index = self.allocSlot() orelse return error.StreamTableFull;
        self.slots[index].used = true;
        self.slots[index].stream = Stream.init(stream_id);
        try self.slots[index].stream.openRemote(end_stream);
        self.active_count += 1;
        self.last_remote_stream_id = stream_id;
        return &self.slots[index].stream;
    }

    pub fn get(self: *StreamTable, stream_id: u32) ?*Stream {
        const index = self.findIndex(stream_id) orelse return null;
        return &self.slots[index].stream;
    }

    pub fn endLocal(self: *StreamTable, stream_id: u32) Error!void {
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.endLocal();
        self.releaseIfClosed(index);
    }

    pub fn endRemote(self: *StreamTable, stream_id: u32) Error!void {
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.endRemote();
        self.releaseIfClosed(index);
    }

    pub fn reset(self: *StreamTable, stream_id: u32) Error!void {
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        self.slots[index].stream.reset();
        self.releaseIfClosed(index);
    }

    pub fn consumeRecvWindow(self: *StreamTable, stream_id: u32, bytes: u32) Error!void {
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.consumeRecvWindow(bytes);
    }

    pub fn consumeSendWindow(self: *StreamTable, stream_id: u32, bytes: u32) Error!void {
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.consumeSendWindow(bytes);
    }

    pub fn incrementSendWindow(self: *StreamTable, stream_id: u32, delta_bytes: u32) Error!void {
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.incrementSendWindow(delta_bytes);
    }

    pub fn incrementRecvWindow(self: *StreamTable, stream_id: u32, delta_bytes: u32) Error!void {
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.incrementRecvWindow(delta_bytes);
    }

    pub fn adjustAllSendWindows(self: *StreamTable, delta_bytes: i64) void {
        for (self.slots[0..]) |*slot| {
            if (!slot.used) continue;

            if (delta_bytes >= 0) {
                const delta_u32: u32 = @intCast(delta_bytes);
                const current: u64 = slot.stream.send_window.available_bytes;
                const next: u64 = current + delta_u32;
                slot.stream.send_window.available_bytes = if (next > config.H2_MAX_WINDOW_SIZE_BYTES)
                    config.H2_MAX_WINDOW_SIZE_BYTES
                else
                    @intCast(next);
            } else {
                const dec_u64: u64 = @intCast(-delta_bytes);
                const current: u64 = slot.stream.send_window.available_bytes;
                if (dec_u64 >= current) {
                    slot.stream.send_window.available_bytes = 0;
                } else {
                    slot.stream.send_window.available_bytes = @intCast(current - dec_u64);
                }
            }
        }
    }

    fn findIndex(self: *const StreamTable, stream_id: u32) ?usize {
        for (self.slots, 0..) |slot, index| {
            if (!slot.used) continue;
            if (slot.stream.id == stream_id) return index;
        }
        return null;
    }

    fn allocSlot(self: *const StreamTable) ?usize {
        if (self.active_count >= config.H2_MAX_CONCURRENT_STREAMS) return null;

        for (self.slots, 0..) |slot, index| {
            if (!slot.used) return index;
        }
        return null;
    }

    fn releaseIfClosed(self: *StreamTable, index: usize) void {
        assert(index < self.slots.len);
        if (!self.slots[index].used) return;
        if (!self.slots[index].stream.isClosed()) return;

        self.slots[index] = .{};
        assert(self.active_count > 0);
        self.active_count -= 1;
    }
};

const Initiator = enum {
    local,
    remote,
};

fn validateNewStreamId(role: Role, stream_id: u32, initiator: Initiator, last_stream_id: u32) Error!void {
    if (!isValidStreamId(stream_id)) return error.InvalidStreamId;
    if (stream_id <= last_stream_id) return error.StreamIdRegression;
    if (streamIdIsOdd(stream_id) != expectedOddParity(role, initiator)) {
        return error.WrongStreamParity;
    }
}

fn isValidStreamId(stream_id: u32) bool {
    if (stream_id == 0) return false;
    return (stream_id & 0x8000_0000) == 0;
}

fn streamIdIsOdd(stream_id: u32) bool {
    return (stream_id & 1) == 1;
}

fn expectedOddParity(role: Role, initiator: Initiator) bool {
    return switch (role) {
        .client => initiator == .local,
        .server => initiator == .remote,
    };
}

test "client local stream ids are odd" {
    var table = StreamTable.init(.client);
    _ = try table.openLocal(1, false);
    try std.testing.expectError(error.WrongStreamParity, table.openLocal(2, false));
}

test "server remote stream ids are odd" {
    var table = StreamTable.init(.server);
    _ = try table.openRemote(1, false);
    try std.testing.expectError(error.WrongStreamParity, table.openRemote(2, false));
}

test "stream transitions open to closed" {
    var stream = Stream.init(1);
    try stream.openLocal(false);
    try std.testing.expect(stream.localCanSend());
    try std.testing.expect(stream.remoteCanSend());

    try stream.endRemote();
    try std.testing.expect(stream.state == .half_closed_remote);
    try std.testing.expect(stream.localCanSend());
    try std.testing.expect(!stream.remoteCanSend());

    try stream.endLocal();
    try std.testing.expect(stream.isClosed());
}

test "reserved stream activation transitions correctly" {
    var stream = Stream.init(2);
    try stream.reserveLocal();
    try stream.activateReservedLocal(false);
    try std.testing.expect(stream.state == .half_closed_remote);
}

test "stream window helpers enforce bounded accounting" {
    var stream = Stream.init(1);
    try stream.configureWindows(32, 64);
    try stream.consumeRecvWindow(8);
    try stream.incrementRecvWindow(4);
    try stream.incrementSendWindow(8);

    try std.testing.expectEqual(@as(u32, 28), stream.recv_window.available_bytes);
    try std.testing.expectEqual(@as(u32, 72), stream.send_window.available_bytes);
}

test "stream table enforces monotonic ids" {
    var table = StreamTable.init(.client);
    _ = try table.openLocal(1, false);
    try std.testing.expectError(error.StreamIdRegression, table.openLocal(1, false));
}

test "stream table releases closed streams" {
    var table = StreamTable.init(.server);
    _ = try table.openRemote(1, false);
    try table.endLocal(1);
    try std.testing.expectEqual(@as(u16, 1), table.active_count);

    try table.endRemote(1);
    try std.testing.expectEqual(@as(u16, 0), table.active_count);
    try std.testing.expect(table.get(1) == null);
}

test "stream table rejects capacity overflow" {
    var table = StreamTable.init(.client);

    var stream_id: u32 = 1;
    var opened: u16 = 0;
    while (opened < config.H2_MAX_CONCURRENT_STREAMS) : (opened += 1) {
        _ = try table.openLocal(stream_id, false);
        stream_id += 2;
    }

    try std.testing.expectError(error.StreamTableFull, table.openLocal(stream_id, false));
}
