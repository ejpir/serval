//! Minimal HPACK Helpers
//!
//! Supports a bounded safe subset sufficient for Serval's current h2c/gRPC
//! parsing and client/server helpers.
//!
//! Supported:
//! - indexed header fields from static and dynamic tables
//! - literal header field with incremental indexing
//! - literal header field without indexing
//! - literal header field never indexed
//! - indexed header names from static and dynamic tables
//! - dynamic-table size updates (bounded, ordered)
//! - Huffman string decoding

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const config = core.config;
const log = core.log.scoped(.hpack);
const limits = @import("limits.zig");
const huffman = @import("huffman.zig");

/// A decoded HTTP header field.
/// `name` and `value` are borrowed slices; this type does not allocate or own storage.
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

/// Errors returned by HPACK encoding and decoding operations.
/// Covers incomplete input, buffer exhaustion, integer and Huffman decoding failures, header-count limits, and invalid dynamic-table updates.
pub const Error = error{
    NeedMoreData,
    BufferTooSmall,
    TooManyHeaders,
    IntegerOverflow,
    InvalidStringLength,
    InvalidIndex,
    UnsupportedDynamicTableIndex,
    DynamicTableSizeTooLarge,
    InvalidDynamicTableSizeUpdate,
    InvalidHuffman,
};

const default_dynamic_table_size_bytes: u32 = 4096;
const dynamic_entry_overhead_size_bytes: u32 = 32;
const dynamic_storage_capacity_bytes: usize = limits.header_block_capacity_bytes;
const dynamic_entry_capacity: usize = 256;
const huffman_scratch_capacity_bytes: usize = limits.header_block_capacity_bytes * 2;

const DynamicEntry = struct {
    name_offset: u16,
    name_len: u16,
    value_offset: u16,
    value_len: u16,
    size_bytes: u32,
};

/// HPACK decoder state, including dynamic-table metadata and scratch storage.
/// Reuse a single instance when decoding multiple blocks that share table state.
/// The embedded buffers are owned by the decoder value itself.
pub const Decoder = struct {
    max_dynamic_table_size_bytes: u32 = default_dynamic_table_size_bytes,
    dynamic_table_size_limit_bytes: u32 = default_dynamic_table_size_bytes,
    current_dynamic_table_size_bytes: u32 = 0,
    dynamic_entry_count: u16 = 0,
    dynamic_entries: [dynamic_entry_capacity]DynamicEntry = [_]DynamicEntry{.{
        .name_offset = 0,
        .name_len = 0,
        .value_offset = 0,
        .value_len = 0,
        .size_bytes = 0,
    }} ** dynamic_entry_capacity,
    dynamic_storage_len: u16 = 0,
    dynamic_storage_buf: [dynamic_storage_capacity_bytes]u8 = undefined,
    compact_storage_buf: [dynamic_storage_capacity_bytes]u8 = undefined,
    huffman_scratch_len: u16 = 0,
    huffman_scratch_buf: [huffman_scratch_capacity_bytes]u8 = undefined,

    /// Initializes a decoder with default dynamic-table limits and empty state.
    /// The returned value can be used immediately with the decode and table-size APIs.
    /// No allocation is performed.
    pub fn init() Decoder {
        assert(dynamic_entry_capacity > 0);
        assert(dynamic_storage_capacity_bytes > 0);
        return .{};
    }

    /// Sets the decoder's maximum dynamic-table size in bytes.
    /// If the new limit is below the current table size, oldest entries are evicted until the table fits.
    /// Returns `error.DynamicTableSizeTooLarge` when `max_size_bytes` exceeds the decoder's storage capacity.
    pub fn setMaxDynamicTableSize(self: *Decoder, max_size_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.dynamic_entry_count <= dynamic_entry_capacity);

        if (max_size_bytes > dynamic_storage_capacity_bytes) return error.DynamicTableSizeTooLarge;
        self.max_dynamic_table_size_bytes = max_size_bytes;
        if (self.dynamic_table_size_limit_bytes > max_size_bytes) {
            self.dynamic_table_size_limit_bytes = max_size_bytes;
        }

        while (self.current_dynamic_table_size_bytes > self.dynamic_table_size_limit_bytes) {
            evictOldestDynamicEntry(self);
        }
    }

    /// Decodes one HPACK header block using `self` and writes decoded fields into `out_fields`.
    /// Supports indexed headers, literal headers with and without incremental indexing, and dynamic-table size updates.
    /// Returns a slice of `out_fields`; mutates the decoder's dynamic table and may return `error.TooManyHeaders` or malformed-input errors.
    pub fn decodeHeaderBlock(self: *Decoder, input: []const u8, out_fields: []HeaderField) Error![]const HeaderField {
        assert(@intFromPtr(self) != 0);
        assert(out_fields.len > 0);

        self.huffman_scratch_len = 0;
        log.debug("hpack: decodeHeaderBlock input_len={d} out_cap={d}", .{ input.len, out_fields.len });

        var cursor: usize = 0;
        var count: u32 = 0;
        var saw_field = false;

        while (cursor < input.len) {
            if (count >= out_fields.len) return error.TooManyHeaders;

            const first = input[cursor];
            log.debug("hpack: field[{d}] cursor={d} first=0x{x}", .{ count, cursor, first });
            if ((first & 0x80) != 0) {
                const index = try decodeInteger(input, &cursor, 7);
                log.debug("hpack: indexed field index={d}", .{index});
                const field = try resolveIndexedHeader(self, index);
                out_fields[count] = field;
                count += 1;
                saw_field = true;
                continue;
            }

            if ((first & 0x40) != 0) {
                const name = try decodeHeaderName(self, input, &cursor, 6);
                const value = try decodeString(self, input, &cursor);
                log.debug("hpack: literal+indexing name_len={d} value_len={d}", .{ name.len, value.len });
                out_fields[count] = .{ .name = name, .value = value };
                count += 1;
                saw_field = true;
                try insertDynamicEntry(self, name, value);
                continue;
            }

            if ((first & 0x20) != 0) {
                if (saw_field) return error.InvalidDynamicTableSizeUpdate;
                const dynamic_table_size = try decodeInteger(input, &cursor, 5);
                try applyDynamicTableSizeUpdate(self, dynamic_table_size);
                continue;
            }

            const name = try decodeHeaderName(self, input, &cursor, 4);
            const value = try decodeString(self, input, &cursor);
            log.debug("hpack: literal name_len={d} value_len={d}", .{ name.len, value.len });
            out_fields[count] = .{ .name = name, .value = value };
            count += 1;
            saw_field = true;
        }

        return out_fields[0..count];
    }
};

/// Decodes an HPACK header block using a fresh decoder instance.
/// This is a convenience wrapper for one-shot decoding when no decoder state needs to be reused.
/// The returned slice aliases `out_fields`; decoder state is not retained after the call.
pub fn decodeHeaderBlock(input: []const u8, out_fields: []HeaderField) Error![]const HeaderField {
    assert(dynamic_entry_capacity > 0);
    assert(huffman_scratch_capacity_bytes >= dynamic_storage_capacity_bytes);
    var decoder = Decoder.init();
    return decoder.decodeHeaderBlock(input, out_fields);
}

/// Decodes `input` with the provided `decoder` and writes results into `out_fields`.
/// The decoder's dynamic-table state is preserved and updated by the decode operation.
/// The returned slice aliases `out_fields` and contains only the headers that were decoded.
pub fn decodeHeaderBlockWithDecoder(
    decoder: *Decoder,
    input: []const u8,
    out_fields: []HeaderField,
) Error![]const HeaderField {
    assert(@intFromPtr(decoder) != 0);
    assert(dynamic_entry_capacity > 0);
    return decoder.decodeHeaderBlock(input, out_fields);
}

/// Encodes a literal header field without indexing into `out`.
/// The header name must be non-empty; the name is encoded in lowercase before the value is written.
/// On success, the returned slice aliases `out`. Returns `error.BufferTooSmall` if `out` cannot hold the full encoding.
pub fn encodeLiteralHeaderWithoutIndexing(
    out: []u8,
    name: []const u8,
    value: []const u8,
) Error![]const u8 {
    assert(name.len > 0);
    assert(dynamic_entry_overhead_size_bytes == 32);

    var cursor: usize = 0;
    if (cursor >= out.len) return error.BufferTooSmall;

    out[cursor] = 0x00;
    cursor += 1;
    cursor = try encodeHeaderNameLowercase(out, cursor, name);
    cursor = try encodeString(out, cursor, value);
    return out[0..cursor];
}

/// Encodes a literal header field with incremental indexing into `out`.
/// The header name must be non-empty; the name is encoded in lowercase before the value is written.
/// On success, the returned slice aliases `out`. Returns `error.BufferTooSmall` if `out` cannot hold the full encoding.
pub fn encodeLiteralHeaderWithIncrementalIndexing(
    out: []u8,
    name: []const u8,
    value: []const u8,
) Error![]const u8 {
    assert(name.len > 0);
    assert(dynamic_entry_overhead_size_bytes == 32);

    var cursor: usize = 0;
    if (cursor >= out.len) return error.BufferTooSmall;

    out[cursor] = 0x40;
    cursor += 1;
    cursor = try encodeHeaderNameLowercase(out, cursor, name);
    cursor = try encodeString(out, cursor, value);
    return out[0..cursor];
}

/// Encodes an HPACK indexed header field into `out` and returns the written prefix.
/// `index` must be nonzero and refer to a valid static or dynamic table entry; otherwise returns `error.InvalidIndex`.
/// The returned slice aliases `out` and is valid until `out` is reused or modified.
pub fn encodeIndexedHeaderField(out: []u8, index: u32) Error![]const u8 {
    assert(static_table.len > 0);
    assert(dynamic_entry_capacity > 0);
    if (index == 0) return error.InvalidIndex;
    const cursor = try encodeInteger(out, 0, 7, 0x80, index);
    return out[0..cursor];
}

fn decodeHeaderName(self: *Decoder, input: []const u8, cursor: *usize, prefix_bits: u8) Error![]const u8 {
    assert(@intFromPtr(self) != 0);
    assert(prefix_bits > 0 and prefix_bits < 8);

    const name_index = try decodeInteger(input, cursor, prefix_bits);
    if (name_index == 0) {
        return try decodeString(self, input, cursor);
    }

    const field = try resolveIndexedHeader(self, name_index);
    return field.name;
}

fn resolveIndexedHeader(self: *const Decoder, index: u32) Error!HeaderField {
    assert(@intFromPtr(self) != 0);
    assert(self.dynamic_entry_count <= dynamic_entry_capacity);

    if (index == 0) return error.InvalidIndex;
    if (index <= static_table.len) {
        const table_index: usize = @intCast(index - 1);
        return static_table[table_index];
    }

    const dynamic_index_1_based = index - static_table.len;
    if (dynamic_index_1_based == 0) return error.InvalidIndex;
    if (dynamic_index_1_based > self.dynamic_entry_count) return error.UnsupportedDynamicTableIndex;

    const slot: usize = @intCast(dynamic_index_1_based - 1);
    const entry = self.dynamic_entries[slot];

    const name_start: usize = entry.name_offset;
    const name_len: usize = entry.name_len;
    const value_start: usize = entry.value_offset;
    const value_len: usize = entry.value_len;

    return .{
        .name = self.dynamic_storage_buf[name_start .. name_start + name_len],
        .value = self.dynamic_storage_buf[value_start .. value_start + value_len],
    };
}

fn applyDynamicTableSizeUpdate(self: *Decoder, dynamic_table_size_bytes: u32) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(self.current_dynamic_table_size_bytes <= dynamic_storage_capacity_bytes);

    if (dynamic_table_size_bytes > self.max_dynamic_table_size_bytes) {
        return error.DynamicTableSizeTooLarge;
    }

    self.dynamic_table_size_limit_bytes = dynamic_table_size_bytes;
    while (self.current_dynamic_table_size_bytes > self.dynamic_table_size_limit_bytes) {
        evictOldestDynamicEntry(self);
    }
}

fn insertDynamicEntry(self: *Decoder, name: []const u8, value: []const u8) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(self.dynamic_entry_count <= dynamic_entry_capacity);

    const entry_size_bytes = try dynamicEntrySize(name.len, value.len);
    if (entry_size_bytes > self.dynamic_table_size_limit_bytes) {
        clearDynamicTable(self);
        return;
    }

    while (self.current_dynamic_table_size_bytes + entry_size_bytes > self.dynamic_table_size_limit_bytes) {
        evictOldestDynamicEntry(self);
    }

    while (self.dynamic_entry_count >= dynamic_entry_capacity) {
        evictOldestDynamicEntry(self);
    }

    const required_storage_bytes = name.len + value.len;
    try ensureDynamicStorageSpace(self, required_storage_bytes);

    const start: usize = self.dynamic_storage_len;
    const name_start = start;
    const value_start = start + name.len;

    @memcpy(self.dynamic_storage_buf[name_start..][0..name.len], name);
    @memcpy(self.dynamic_storage_buf[value_start..][0..value.len], value);

    var index: usize = self.dynamic_entry_count;
    while (index > 0) {
        self.dynamic_entries[index] = self.dynamic_entries[index - 1];
        index -= 1;
    }

    self.dynamic_entries[0] = .{
        .name_offset = @intCast(name_start),
        .name_len = @intCast(name.len),
        .value_offset = @intCast(value_start),
        .value_len = @intCast(value.len),
        .size_bytes = entry_size_bytes,
    };
    self.dynamic_entry_count += 1;
    self.current_dynamic_table_size_bytes += entry_size_bytes;
    self.dynamic_storage_len = @intCast(start + required_storage_bytes);
}

fn ensureDynamicStorageSpace(self: *Decoder, required_storage_bytes: usize) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(self.dynamic_storage_len <= dynamic_storage_capacity_bytes);

    const current_len: usize = self.dynamic_storage_len;
    if (current_len + required_storage_bytes <= dynamic_storage_capacity_bytes) return;

    compactDynamicStorage(self);

    const compacted_len: usize = self.dynamic_storage_len;
    if (compacted_len + required_storage_bytes > dynamic_storage_capacity_bytes) {
        return error.BufferTooSmall;
    }
}

fn compactDynamicStorage(self: *Decoder) void {
    assert(@intFromPtr(self) != 0);
    assert(self.dynamic_entry_count <= dynamic_entry_capacity);

    var write_offset: usize = 0;

    var reverse_index: usize = self.dynamic_entry_count;
    while (reverse_index > 0) {
        reverse_index -= 1;
        const entry = self.dynamic_entries[reverse_index];

        const name_src_start: usize = entry.name_offset;
        const name_len: usize = entry.name_len;
        const value_src_start: usize = entry.value_offset;
        const value_len: usize = entry.value_len;

        @memcpy(self.compact_storage_buf[write_offset..][0..name_len], self.dynamic_storage_buf[name_src_start..][0..name_len]);
        self.dynamic_entries[reverse_index].name_offset = @intCast(write_offset);
        self.dynamic_entries[reverse_index].name_len = @intCast(name_len);
        write_offset += name_len;

        @memcpy(self.compact_storage_buf[write_offset..][0..value_len], self.dynamic_storage_buf[value_src_start..][0..value_len]);
        self.dynamic_entries[reverse_index].value_offset = @intCast(write_offset);
        self.dynamic_entries[reverse_index].value_len = @intCast(value_len);
        write_offset += value_len;
    }

    @memcpy(self.dynamic_storage_buf[0..write_offset], self.compact_storage_buf[0..write_offset]);
    self.dynamic_storage_len = @intCast(write_offset);
}

fn evictOldestDynamicEntry(self: *Decoder) void {
    assert(@intFromPtr(self) != 0);
    assert(self.dynamic_entry_count <= dynamic_entry_capacity);

    if (self.dynamic_entry_count == 0) {
        self.current_dynamic_table_size_bytes = 0;
        self.dynamic_storage_len = 0;
        return;
    }

    const oldest_index: usize = self.dynamic_entry_count - 1;
    const oldest = self.dynamic_entries[oldest_index];

    if (oldest.size_bytes <= self.current_dynamic_table_size_bytes) {
        self.current_dynamic_table_size_bytes -= oldest.size_bytes;
    } else {
        self.current_dynamic_table_size_bytes = 0;
    }

    self.dynamic_entry_count -= 1;
    if (self.dynamic_entry_count == 0) {
        self.current_dynamic_table_size_bytes = 0;
        self.dynamic_storage_len = 0;
    }
}

fn clearDynamicTable(self: *Decoder) void {
    assert(@intFromPtr(self) != 0);
    assert(self.dynamic_entry_count <= dynamic_entry_capacity);

    self.current_dynamic_table_size_bytes = 0;
    self.dynamic_entry_count = 0;
    self.dynamic_storage_len = 0;
}

fn dynamicEntrySize(name_len: usize, value_len: usize) Error!u32 {
    assert(dynamic_entry_overhead_size_bytes == 32);
    assert(dynamic_storage_capacity_bytes <= huffman_scratch_capacity_bytes);

    const name_u32 = std.math.cast(u32, name_len) orelse return error.IntegerOverflow;
    const value_u32 = std.math.cast(u32, value_len) orelse return error.IntegerOverflow;

    const payload = std.math.add(u32, name_u32, value_u32) catch return error.IntegerOverflow;
    return std.math.add(u32, payload, dynamic_entry_overhead_size_bytes) catch return error.IntegerOverflow;
}

fn decodeInteger(input: []const u8, cursor: *usize, prefix_bits: u8) Error!u32 {
    assert(prefix_bits > 0);
    assert(prefix_bits < 8);
    assert(cursor.* < input.len);

    const prefix_mask: u8 = (@as(u8, 1) << @intCast(prefix_bits)) - 1;
    const first = input[cursor.*];
    var value: u32 = first & prefix_mask;
    cursor.* += 1;

    if (value < prefix_mask) return value;

    var shift: u6 = 0;
    while (true) {
        if (cursor.* >= input.len) return error.NeedMoreData;
        if (shift >= 28) return error.IntegerOverflow;

        const b = input[cursor.*];
        cursor.* += 1;
        value += (@as(u32, b & 0x7f) << @as(u5, @intCast(shift)));
        if ((b & 0x80) == 0) return value;
        shift += 7;
    }
}

fn decodeString(self: *Decoder, input: []const u8, cursor: *usize) Error![]const u8 {
    assert(@intFromPtr(self) != 0);
    assert(self.huffman_scratch_len <= huffman_scratch_capacity_bytes);

    if (cursor.* >= input.len) return error.NeedMoreData;

    const huffman_encoded = (input[cursor.*] & 0x80) != 0;

    const len_u32 = try decodeInteger(input, cursor, 7);
    const len: usize = @intCast(len_u32);
    if (cursor.* + len > input.len) return error.InvalidStringLength;

    const str = input[cursor.* .. cursor.* + len];
    cursor.* += len;

    log.debug(
        "hpack: decodeString huffman={} encoded_len={d} scratch_len={d}",
        .{ huffman_encoded, len, self.huffman_scratch_len },
    );
    if (!huffman_encoded) return str;

    const scratch_start: usize = self.huffman_scratch_len;
    const decoded = huffman.decode(str, self.huffman_scratch_buf[scratch_start..]) catch |err| switch (err) {
        error.InvalidHuffman => return error.InvalidHuffman,
        error.BufferTooSmall => return error.BufferTooSmall,
    };
    log.debug("hpack: huffman decoded_len={d}", .{decoded.len});

    self.huffman_scratch_len = @intCast(scratch_start + decoded.len);
    return self.huffman_scratch_buf[scratch_start .. scratch_start + decoded.len];
}

fn encodeInteger(out: []u8, cursor_start: usize, prefix_bits: u8, first_prefix: u8, value: u32) Error!usize {
    assert(prefix_bits > 0);
    assert(prefix_bits < 8);
    assert(cursor_start < out.len);

    const prefix_max: u32 = (@as(u32, 1) << @intCast(prefix_bits)) - 1;
    var cursor = cursor_start;

    if (value < prefix_max) {
        out[cursor] = first_prefix | @as(u8, @intCast(value));
        return cursor + 1;
    }

    out[cursor] = first_prefix | @as(u8, @intCast(prefix_max));
    cursor += 1;

    var remaining = value - prefix_max;
    while (remaining >= 128) {
        if (cursor >= out.len) return error.BufferTooSmall;
        out[cursor] = @as(u8, @intCast((remaining & 0x7f) | 0x80));
        remaining >>= 7;
        cursor += 1;
    }

    if (cursor >= out.len) return error.BufferTooSmall;
    out[cursor] = @as(u8, @intCast(remaining));
    return cursor + 1;
}

fn encodeString(out: []u8, cursor_start: usize, data: []const u8) Error!usize {
    assert(cursor_start <= out.len);
    assert(dynamic_entry_overhead_size_bytes == 32);
    var cursor = try encodeInteger(out, cursor_start, 7, 0x00, @intCast(data.len));
    if (cursor + data.len > out.len) return error.BufferTooSmall;
    @memcpy(out[cursor..][0..data.len], data);
    cursor += data.len;
    return cursor;
}

fn encodeHeaderNameLowercase(out: []u8, cursor_start: usize, name: []const u8) Error!usize {
    assert(cursor_start <= out.len);
    assert(name.len > 0);

    var cursor = try encodeInteger(out, cursor_start, 7, 0x00, @intCast(name.len));
    if (cursor + name.len > out.len) return error.BufferTooSmall;

    var index: usize = 0;
    while (index < name.len) : (index += 1) {
        out[cursor + index] = std.ascii.toLower(name[index]);
    }

    cursor += name.len;
    return cursor;
}

const static_table = [_]HeaderField{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

test "encode and decode literal header without indexing" {
    var encoded_buf: [128]u8 = undefined;
    const encoded = try encodeLiteralHeaderWithoutIndexing(&encoded_buf, ":path", "/grpc.Health/Check");

    var fields_buf: [4]HeaderField = undefined;
    const fields = try decodeHeaderBlock(encoded, &fields_buf);

    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings(":path", fields[0].name);
    try std.testing.expectEqualStrings("/grpc.Health/Check", fields[0].value);
}

test "encodeLiteralHeaderWithoutIndexing lowercases header names" {
    var encoded_buf: [128]u8 = undefined;
    const encoded = try encodeLiteralHeaderWithoutIndexing(&encoded_buf, "Server", "nginx");

    var fields_buf: [4]HeaderField = undefined;
    const fields = try decodeHeaderBlock(encoded, &fields_buf);

    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings("server", fields[0].name);
    try std.testing.expectEqualStrings("nginx", fields[0].value);
}

test "decodeHeaderBlock decodes indexed static header fields" {
    var fields_buf: [4]HeaderField = undefined;
    const fields = try decodeHeaderBlock(&[_]u8{ 0x83, 0x84 }, &fields_buf);

    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings(":method", fields[0].name);
    try std.testing.expectEqualStrings("POST", fields[0].value);
    try std.testing.expectEqualStrings(":path", fields[1].name);
    try std.testing.expectEqualStrings("/", fields[1].value);
}

test "decodeHeaderBlock decodes literal with indexed static name" {
    const encoded = [_]u8{
        0x5f, // literal with incremental indexing, name index = 31 (content-type)
        0x10, // value length = 16
        'a',
        'p',
        'p',
        'l',
        'i',
        'c',
        'a',
        't',
        'i',
        'o',
        'n',
        '/',
        'g',
        'r',
        'p',
        'c',
    };

    var fields_buf: [2]HeaderField = undefined;
    const fields = try decodeHeaderBlock(&encoded, &fields_buf);

    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings("content-type", fields[0].name);
    try std.testing.expectEqualStrings("application/grpc", fields[0].value);
}

test "decodeHeaderBlock accepts dynamic table size update" {
    var encoded_buf: [128]u8 = undefined;
    encoded_buf[0] = 0x20; // dynamic table size update: size = 0
    const literal = try encodeLiteralHeaderWithoutIndexing(encoded_buf[1..], "te", "trailers");

    var fields_buf: [2]HeaderField = undefined;
    const fields = try decodeHeaderBlock(encoded_buf[0 .. 1 + literal.len], &fields_buf);

    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings("te", fields[0].name);
    try std.testing.expectEqualStrings("trailers", fields[0].value);
}

test "decodeHeaderBlock rejects dynamic-table indexed headers without persistent decoder" {
    var fields_buf: [1]HeaderField = undefined;
    try std.testing.expectError(error.UnsupportedDynamicTableIndex, decodeHeaderBlock(&[_]u8{0xbe}, &fields_buf));
}

test "Decoder resolves dynamic indexed header across blocks" {
    var decoder = Decoder.init();

    const first_block = [_]u8{
        0x5f, // literal with incremental indexing, name index = 31 (content-type)
        0x10, // value length = 16
        'a',
        'p',
        'p',
        'l',
        'i',
        'c',
        'a',
        't',
        'i',
        'o',
        'n',
        '/',
        'g',
        'r',
        'p',
        'c',
    };

    var fields_buf: [4]HeaderField = undefined;
    const fields1 = try decoder.decodeHeaderBlock(&first_block, &fields_buf);
    try std.testing.expectEqual(@as(usize, 1), fields1.len);

    const fields2 = try decoder.decodeHeaderBlock(&[_]u8{0xbe}, &fields_buf); // index 62 => newest dynamic
    try std.testing.expectEqual(@as(usize, 1), fields2.len);
    try std.testing.expectEqualStrings("content-type", fields2[0].name);
    try std.testing.expectEqualStrings("application/grpc", fields2[0].value);
}

test "Decoder enforces dynamic table size update ordering" {
    var decoder = Decoder.init();

    var encoded_buf: [64]u8 = undefined;
    const literal = try encodeLiteralHeaderWithoutIndexing(&encoded_buf, "te", "trailers");
    encoded_buf[literal.len] = 0x20; // dynamic table size update after a field

    var fields_buf: [2]HeaderField = undefined;
    try std.testing.expectError(
        error.InvalidDynamicTableSizeUpdate,
        decoder.decodeHeaderBlock(encoded_buf[0 .. literal.len + 1], &fields_buf),
    );
}

test "Decoder applies dynamic table size updates to subsequent insertions" {
    var decoder = Decoder.init();

    var fields_buf: [4]HeaderField = undefined;
    _ = try decoder.decodeHeaderBlock(&[_]u8{0x20}, &fields_buf); // size update to 0

    var block: [64]u8 = undefined;
    const encoded = try encodeLiteralHeaderWithIncrementalIndexing(&block, "x", "1");
    _ = try decoder.decodeHeaderBlock(encoded, &fields_buf);

    try std.testing.expectError(
        error.UnsupportedDynamicTableIndex,
        decoder.decodeHeaderBlock(&[_]u8{0xbe}, &fields_buf),
    );
}

test "Decoder evicts existing dynamic entries after cross-block size shrink" {
    var decoder = Decoder.init();
    try decoder.setMaxDynamicTableSize(64);

    var fields_buf: [4]HeaderField = undefined;
    var insert_block: [64]u8 = undefined;
    const inserted = try encodeLiteralHeaderWithIncrementalIndexing(&insert_block, "x", "1");
    _ = try decoder.decodeHeaderBlock(inserted, &fields_buf);

    const indexed_before = try decoder.decodeHeaderBlock(&[_]u8{0xbe}, &fields_buf);
    try std.testing.expectEqual(@as(usize, 1), indexed_before.len);
    try std.testing.expectEqualStrings("x", indexed_before[0].name);
    try std.testing.expectEqualStrings("1", indexed_before[0].value);

    _ = try decoder.decodeHeaderBlock(&[_]u8{0x20}, &fields_buf); // size update to 0
    try std.testing.expectEqual(@as(u16, 0), decoder.dynamic_entry_count);
    try std.testing.expectEqual(@as(u32, 0), decoder.current_dynamic_table_size_bytes);

    try std.testing.expectError(
        error.UnsupportedDynamicTableIndex,
        decoder.decodeHeaderBlock(&[_]u8{0xbe}, &fields_buf),
    );
}

test "Decoder accepts multiple dynamic table size updates before first field" {
    var decoder = Decoder.init();
    try decoder.setMaxDynamicTableSize(64);

    var block: [128]u8 = undefined;
    var len: usize = 0;
    len = try encodeInteger(&block, len, 5, 0x20, 32);
    len = try encodeInteger(&block, len, 5, 0x20, 0);

    const literal = try encodeLiteralHeaderWithoutIndexing(block[len..], "te", "trailers");
    len += literal.len;

    var fields_buf: [2]HeaderField = undefined;
    const fields = try decoder.decodeHeaderBlock(block[0..len], &fields_buf);
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings("te", fields[0].name);
    try std.testing.expectEqualStrings("trailers", fields[0].value);
    try std.testing.expectEqual(@as(u32, 0), decoder.dynamic_table_size_limit_bytes);
}

test "Decoder applies cross-block shrink then regrow before indexed lookup" {
    var decoder = Decoder.init();
    try decoder.setMaxDynamicTableSize(128);

    var fields_buf: [4]HeaderField = undefined;
    _ = try decoder.decodeHeaderBlock(&[_]u8{0x20}, &fields_buf); // shrink to 0

    var grow_block: [8]u8 = undefined;
    const grow_len = try encodeInteger(&grow_block, 0, 5, 0x20, 64);
    _ = try decoder.decodeHeaderBlock(grow_block[0..grow_len], &fields_buf);

    var insert_block: [64]u8 = undefined;
    const inserted = try encodeLiteralHeaderWithIncrementalIndexing(&insert_block, "x-regrow", "v");
    _ = try decoder.decodeHeaderBlock(inserted, &fields_buf);

    const indexed = try decoder.decodeHeaderBlock(&[_]u8{0xbe}, &fields_buf);
    try std.testing.expectEqual(@as(usize, 1), indexed.len);
    try std.testing.expectEqualStrings("x-regrow", indexed[0].name);
    try std.testing.expectEqualStrings("v", indexed[0].value);
}

test "Decoder evicts dynamic entries when size bound shrinks" {
    var decoder = Decoder.init();
    try decoder.setMaxDynamicTableSize(64);

    var block_a: [64]u8 = undefined;
    const encoded_a = try encodeLiteralHeaderWithIncrementalIndexing(&block_a, "te", "trailers");

    var fields_buf: [4]HeaderField = undefined;
    _ = try decoder.decodeHeaderBlock(encoded_a, &fields_buf);

    var block_b: [64]u8 = undefined;
    const encoded_b = try encodeLiteralHeaderWithIncrementalIndexing(&block_b, "x", "1");
    _ = try decoder.decodeHeaderBlock(encoded_b, &fields_buf);

    const indexed_newest = try decoder.decodeHeaderBlock(&[_]u8{0xbe}, &fields_buf); // static(61) + 1
    try std.testing.expectEqualStrings("x", indexed_newest[0].name);
    try std.testing.expectEqualStrings("1", indexed_newest[0].value);

    try std.testing.expectError(
        error.UnsupportedDynamicTableIndex,
        decoder.decodeHeaderBlock(&[_]u8{0xbf}, &fields_buf), // static(61) + 2
    );
}

test "decodeHeaderBlock decodes Huffman string values" {
    const encoded = [_]u8{
        0x01, // literal without indexing, indexed name :authority (index 1)
        0x8c, // Huffman value length = 12 bytes
        0xf1,
        0xe3,
        0xc2,
        0xe5,
        0xf2,
        0x3a,
        0x6b,
        0xa0,
        0xab,
        0x90,
        0xf4,
        0xff,
    };

    var fields_buf: [2]HeaderField = undefined;
    const fields = try decodeHeaderBlock(&encoded, &fields_buf);

    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings(":authority", fields[0].name);
    try std.testing.expectEqualStrings("www.example.com", fields[0].value);
}

test "decodeHeaderBlock rejects invalid Huffman padding" {
    const encoded = [_]u8{
        0x01, // :authority indexed name
        0x81, // Huffman value length = 1
        0xff, // overlong EOS padding only => invalid
    };

    var fields_buf: [2]HeaderField = undefined;
    try std.testing.expectError(error.InvalidHuffman, decodeHeaderBlock(&encoded, &fields_buf));
}

test "decodeHeaderBlock rejects dynamic table size update above peer max" {
    var decoder = Decoder.init();
    try decoder.setMaxDynamicTableSize(32);

    var buf: [16]u8 = undefined;
    const encoded_len = try encodeInteger(&buf, 0, 5, 0x20, 33);

    var fields_buf: [2]HeaderField = undefined;
    try std.testing.expectError(
        error.DynamicTableSizeTooLarge,
        decoder.decodeHeaderBlock(buf[0..encoded_len], &fields_buf),
    );
}

test "decodeHeaderBlock rejects oversized integer representation" {
    const encoded = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    var fields_buf: [1]HeaderField = undefined;
    try std.testing.expectError(error.IntegerOverflow, decodeHeaderBlock(&encoded, &fields_buf));
}

test "HPACK literal roundtrip property over deterministic corpus" {
    var prng = std.Random.DefaultPrng.init(0x5eed_2026);
    const random = prng.random();

    var name_buf: [24]u8 = undefined;
    var value_buf: [48]u8 = undefined;
    var encoded_buf: [128]u8 = undefined;
    var fields_buf: [4]HeaderField = undefined;

    var iteration: u32 = 0;
    while (iteration < 256) : (iteration += 1) {
        const name_len = random.intRangeAtMost(u8, 1, 16);
        const value_len = random.intRangeAtMost(u8, 0, 32);

        var i: u8 = 0;
        while (i < name_len) : (i += 1) {
            name_buf[i] = 'a' + @as(u8, @intCast(i % 26));
        }

        i = 0;
        while (i < value_len) : (i += 1) {
            const alphabet_offset: u8 = random.intRangeAtMost(u8, 0, 25);
            value_buf[i] = 'a' + alphabet_offset;
        }

        const encoded = try encodeLiteralHeaderWithoutIndexing(
            &encoded_buf,
            name_buf[0..name_len],
            value_buf[0..value_len],
        );
        const decoded = try decodeHeaderBlock(encoded, &fields_buf);

        try std.testing.expectEqual(@as(usize, 1), decoded.len);
        try std.testing.expectEqualStrings(name_buf[0..name_len], decoded[0].name);
        try std.testing.expectEqualStrings(value_buf[0..value_len], decoded[0].value);
    }
}

test "HPACK fuzz corpus maintains decoder invariants" {
    var prng = std.Random.DefaultPrng.init(0xabad_1dea);
    const random = prng.random();

    var decoder = Decoder.init();
    var input: [96]u8 = undefined;
    var fields_buf: [config.MAX_HEADERS]HeaderField = undefined;

    var iteration: u32 = 0;
    while (iteration < 512) : (iteration += 1) {
        const len = random.intRangeAtMost(u8, 0, @as(u8, @intCast(input.len)));
        random.bytes(input[0..len]);

        _ = decoder.decodeHeaderBlock(input[0..len], &fields_buf) catch |err| switch (err) {
            error.NeedMoreData,
            error.BufferTooSmall,
            error.TooManyHeaders,
            error.IntegerOverflow,
            error.InvalidStringLength,
            error.InvalidIndex,
            error.UnsupportedDynamicTableIndex,
            error.DynamicTableSizeTooLarge,
            error.InvalidDynamicTableSizeUpdate,
            error.InvalidHuffman,
            => {},
        };

        try std.testing.expect(decoder.dynamic_entry_count <= dynamic_entry_capacity);
        try std.testing.expect(decoder.current_dynamic_table_size_bytes <= decoder.dynamic_table_size_limit_bytes);
        try std.testing.expect(decoder.dynamic_storage_len <= dynamic_storage_capacity_bytes);
    }
}
