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
    send_window_debt_bytes: u32 = 0,

    pub fn init(id: u32) Stream {
        assert(isValidStreamId(id));
        assert(config.H2_INITIAL_WINDOW_SIZE_BYTES <= config.H2_MAX_WINDOW_SIZE_BYTES);
        return .{ .id = id };
    }

    pub fn openLocal(self: *Stream, end_stream: bool) Error!void {
        assert(self.id > 0);
        if (self.state != .idle) return error.InvalidTransition;
        self.state = if (end_stream) .half_closed_local else .open;
        assert(self.state == .half_closed_local or self.state == .open);
    }

    pub fn openRemote(self: *Stream, end_stream: bool) Error!void {
        assert(self.id > 0);
        if (self.state != .idle) return error.InvalidTransition;
        self.state = if (end_stream) .half_closed_remote else .open;
        assert(self.state == .half_closed_remote or self.state == .open);
    }

    pub fn reserveLocal(self: *Stream) Error!void {
        assert(self.id > 0);
        if (self.state != .idle) return error.InvalidTransition;
        self.state = .reserved_local;
        assert(self.state == .reserved_local);
    }

    pub fn reserveRemote(self: *Stream) Error!void {
        assert(self.id > 0);
        if (self.state != .idle) return error.InvalidTransition;
        self.state = .reserved_remote;
        assert(self.state == .reserved_remote);
    }

    pub fn activateReservedLocal(self: *Stream, end_stream: bool) Error!void {
        assert(self.id > 0);
        if (self.state != .reserved_local) return error.InvalidTransition;
        self.state = if (end_stream) .closed else .half_closed_remote;
        assert(self.state == .closed or self.state == .half_closed_remote);
    }

    pub fn activateReservedRemote(self: *Stream, end_stream: bool) Error!void {
        assert(self.id > 0);
        if (self.state != .reserved_remote) return error.InvalidTransition;
        self.state = if (end_stream) .closed else .half_closed_local;
        assert(self.state == .closed or self.state == .half_closed_local);
    }

    pub fn endLocal(self: *Stream) Error!void {
        assert(self.id > 0);
        self.state = switch (self.state) {
            .open => .half_closed_local,
            .half_closed_remote => .closed,
            else => return error.InvalidTransition,
        };
        assert(self.state == .half_closed_local or self.state == .closed);
    }

    pub fn endRemote(self: *Stream) Error!void {
        assert(self.id > 0);
        self.state = switch (self.state) {
            .open => .half_closed_remote,
            .half_closed_local => .closed,
            else => return error.InvalidTransition,
        };
        assert(self.state == .half_closed_remote or self.state == .closed);
    }

    pub fn reset(self: *Stream) void {
        assert(self.id > 0);
        self.state = .closed;
        assert(self.state == .closed);
    }

    pub fn isClosed(self: *const Stream) bool {
        assert(@intFromPtr(self) != 0);
        assert(self.id > 0);
        return self.state == .closed;
    }

    pub fn localCanSend(self: *const Stream) bool {
        assert(@intFromPtr(self) != 0);
        assert(self.id > 0);
        return switch (self.state) {
            .open, .half_closed_remote => true,
            else => false,
        };
    }

    pub fn remoteCanSend(self: *const Stream) bool {
        assert(@intFromPtr(self) != 0);
        assert(self.id > 0);
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
        self.send_window_debt_bytes = 0;
    }

    pub fn consumeRecvWindow(self: *Stream, bytes: u32) Error!void {
        assert(self.id > 0);
        assert(bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.recv_window.consume(bytes);
    }

    pub fn consumeSendWindow(self: *Stream, bytes: u32) Error!void {
        assert(self.id > 0);
        assert(bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        assert(self.send_window_debt_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);

        if (self.send_window_debt_bytes != 0) return error.WindowUnderflow;
        try self.send_window.consume(bytes);
    }

    pub fn incrementSendWindow(self: *Stream, delta_bytes: u32) Error!void {
        assert(self.id > 0);
        assert(delta_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.applySendWindowDelta(@intCast(delta_bytes));
    }

    pub fn incrementRecvWindow(self: *Stream, delta_bytes: u32) Error!void {
        assert(self.id > 0);
        assert(delta_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.recv_window.increment(delta_bytes);
    }

    fn applySendWindowDelta(self: *Stream, delta_bytes: i64) Error!void {
        assert(self.id > 0);
        assert(self.send_window.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        assert(self.send_window_debt_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);

        if (delta_bytes >= 0) {
            const credit_bytes: u32 = @intCast(delta_bytes);
            if (credit_bytes == 0) return;

            if (self.send_window_debt_bytes > 0) {
                if (credit_bytes <= self.send_window_debt_bytes) {
                    self.send_window_debt_bytes -= credit_bytes;
                    return;
                }

                const remaining_credit_bytes = credit_bytes - self.send_window_debt_bytes;
                self.send_window_debt_bytes = 0;
                try self.send_window.increment(remaining_credit_bytes);
                return;
            }

            try self.send_window.increment(credit_bytes);
            return;
        }

        var debt_delta_bytes: u64 = @intCast(-delta_bytes);
        if (debt_delta_bytes == 0) return;
        if (debt_delta_bytes > config.H2_MAX_WINDOW_SIZE_BYTES) return error.WindowOverflow;

        const available_bytes: u64 = self.send_window.available_bytes;
        if (debt_delta_bytes >= available_bytes) {
            self.send_window.available_bytes = 0;
            debt_delta_bytes -= available_bytes;
        } else {
            self.send_window.available_bytes = @intCast(available_bytes - debt_delta_bytes);
            return;
        }

        if (debt_delta_bytes == 0) return;

        const next_debt_bytes: u64 = @as(u64, self.send_window_debt_bytes) + debt_delta_bytes;
        if (next_debt_bytes > config.H2_MAX_WINDOW_SIZE_BYTES) return error.WindowOverflow;
        self.send_window_debt_bytes = @intCast(next_debt_bytes);
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
        assert(table_capacity > 0);
        assert(config.H2_MAX_CONCURRENT_STREAMS > 0);
        return .{ .role = role };
    }

    pub fn openLocal(self: *StreamTable, stream_id: u32, end_stream: bool) Error!*Stream {
        assert(@intFromPtr(self) != 0);
        assert(self.active_count <= config.H2_MAX_CONCURRENT_STREAMS);
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
        assert(@intFromPtr(self) != 0);
        assert(self.active_count <= config.H2_MAX_CONCURRENT_STREAMS);
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
        assert(@intFromPtr(self) != 0);
        assert(stream_id != 0);
        const index = self.findIndex(stream_id) orelse return null;
        return &self.slots[index].stream;
    }

    pub fn endLocal(self: *StreamTable, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id != 0);
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.endLocal();
        self.releaseIfClosed(index);
    }

    pub fn endRemote(self: *StreamTable, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id != 0);
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.endRemote();
        self.releaseIfClosed(index);
    }

    pub fn reset(self: *StreamTable, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id != 0);
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        self.slots[index].stream.reset();
        self.releaseIfClosed(index);
    }

    pub fn consumeRecvWindow(self: *StreamTable, stream_id: u32, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id != 0);
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.consumeRecvWindow(bytes);
    }

    pub fn consumeSendWindow(self: *StreamTable, stream_id: u32, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id != 0);
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.consumeSendWindow(bytes);
    }

    pub fn incrementSendWindow(self: *StreamTable, stream_id: u32, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id != 0);
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.incrementSendWindow(delta_bytes);
    }

    pub fn incrementRecvWindow(self: *StreamTable, stream_id: u32, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id != 0);
        const index = self.findIndex(stream_id) orelse return error.StreamNotFound;
        try self.slots[index].stream.incrementRecvWindow(delta_bytes);
    }

    pub fn adjustAllSendWindows(self: *StreamTable, delta_bytes: i64) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.active_count <= config.H2_MAX_CONCURRENT_STREAMS);

        for (self.slots[0..]) |*slot| {
            if (!slot.used) continue;
            try slot.stream.applySendWindowDelta(delta_bytes);
        }
    }

    fn findIndex(self: *const StreamTable, stream_id: u32) ?usize {
        assert(@intFromPtr(self) != 0);
        assert(stream_id != 0);

        for (self.slots, 0..) |slot, index| {
            if (!slot.used) continue;
            if (slot.stream.id == stream_id) return index;
        }
        return null;
    }

    fn allocSlot(self: *const StreamTable) ?usize {
        assert(@intFromPtr(self) != 0);
        assert(self.active_count <= config.H2_MAX_CONCURRENT_STREAMS);

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
    assert(last_stream_id <= 0x7fff_ffff);
    assert(stream_id <= 0x7fff_ffff or stream_id == 0);

    if (!isValidStreamId(stream_id)) return error.InvalidStreamId;
    if (stream_id <= last_stream_id) return error.StreamIdRegression;
    if (streamIdIsOdd(stream_id) != expectedOddParity(role, initiator)) {
        return error.WrongStreamParity;
    }
}

fn isValidStreamId(stream_id: u32) bool {
    assert((stream_id & 0x8000_0000) == 0 or stream_id == 0);
    assert((stream_id & 0x7fff_ffff) == stream_id or stream_id == 0);
    if (stream_id == 0) return false;
    return (stream_id & 0x8000_0000) == 0;
}

fn streamIdIsOdd(stream_id: u32) bool {
    assert(stream_id > 0);
    assert((stream_id & 0x8000_0000) == 0);
    return (stream_id & 1) == 1;
}

fn expectedOddParity(role: Role, initiator: Initiator) bool {
    assert(role == .client or role == .server);
    assert(initiator == .local or initiator == .remote);
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
    try std.testing.expectEqual(@as(u32, 0), stream.send_window_debt_bytes);
}

test "stream table tracks send-window debt across settings deltas" {
    var table = StreamTable.init(.client);
    _ = try table.openLocal(1, false);

    const decrease_bytes: i64 = @as(i64, config.H2_INITIAL_WINDOW_SIZE_BYTES) + 10;
    try table.adjustAllSendWindows(-decrease_bytes);

    const stream = table.get(1).?;
    try std.testing.expectEqual(@as(u32, 0), stream.send_window.available_bytes);
    try std.testing.expectEqual(@as(u32, 10), stream.send_window_debt_bytes);
    try std.testing.expectError(error.WindowUnderflow, table.consumeSendWindow(1, 1));

    try table.adjustAllSendWindows(5);
    try std.testing.expectEqual(@as(u32, 0), stream.send_window.available_bytes);
    try std.testing.expectEqual(@as(u32, 5), stream.send_window_debt_bytes);

    try table.adjustAllSendWindows(8);
    try std.testing.expectEqual(@as(u32, 3), stream.send_window.available_bytes);
    try std.testing.expectEqual(@as(u32, 0), stream.send_window_debt_bytes);
}

test "stream table rejects overflow on positive settings delta" {
    var table = StreamTable.init(.client);
    const stream = try table.openLocal(1, false);

    const growth = config.H2_MAX_WINDOW_SIZE_BYTES - config.H2_INITIAL_WINDOW_SIZE_BYTES;
    try stream.incrementSendWindow(growth);
    try std.testing.expectEqual(config.H2_MAX_WINDOW_SIZE_BYTES, stream.send_window.available_bytes);

    try std.testing.expectError(error.WindowOverflow, table.adjustAllSendWindows(1));
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

test "stream randomized operation corpus preserves invariants" {
    var prng = std.Random.DefaultPrng.init(0x57ee_0001);
    const random = prng.random();

    var table = StreamTable.init(.client);
    var next_stream_id: u32 = 1;

    var iteration: u32 = 0;
    while (iteration < 1024) : (iteration += 1) {
        const action = random.intRangeAtMost(u8, 0, 4);
        switch (action) {
            0 => {
                if (next_stream_id <= 0x7fff_ffff) {
                    _ = table.openLocal(next_stream_id, false) catch |err| switch (err) {
                        error.StreamTableFull => {},
                        else => return err,
                    };
                    next_stream_id +|= 2;
                }
            },
            1 => {
                const stream_id = random.intRangeAtMost(u32, 1, 127) | 1;
                _ = table.endLocal(stream_id) catch |err| switch (err) {
                    error.StreamNotFound,
                    error.InvalidTransition,
                    => {},
                    else => return err,
                };
            },
            2 => {
                const stream_id = random.intRangeAtMost(u32, 1, 127) | 1;
                _ = table.endRemote(stream_id) catch |err| switch (err) {
                    error.StreamNotFound,
                    error.InvalidTransition,
                    => {},
                    else => return err,
                };
            },
            3 => {
                const stream_id = random.intRangeAtMost(u32, 1, 127) | 1;
                _ = table.reset(stream_id) catch |err| switch (err) {
                    error.StreamNotFound => {},
                    else => return err,
                };
            },
            else => {
                const delta = random.intRangeAtMost(i16, -200, 200);
                _ = table.adjustAllSendWindows(delta) catch |err| switch (err) {
                    error.WindowOverflow => {},
                    else => return err,
                };
            },
        }

        try std.testing.expect(table.active_count <= config.H2_MAX_CONCURRENT_STREAMS);
        var active_count_computed: u16 = 0;
        for (table.slots) |slot| {
            if (!slot.used) continue;
            active_count_computed += 1;
            try std.testing.expect(slot.stream.id > 0);
            try std.testing.expect(slot.stream.send_window.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
            try std.testing.expect(slot.stream.recv_window.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
            try std.testing.expect(slot.stream.send_window_debt_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        }
        try std.testing.expectEqual(active_count_computed, table.active_count);
    }
}
