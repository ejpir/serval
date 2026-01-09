// lib/serval-core/context.zig
//! Per-Request Context
//!
//! Passed to all handler hooks. Allows sharing state within request lifecycle.
//! TigerStyle: Fixed-size, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("types.zig");
const time = @import("time.zig");
const span_handle_mod = @import("span_handle.zig");
const config = @import("config.zig");
const Upstream = types.Upstream;
const SpanHandle = span_handle_mod.SpanHandle;
const BodyFraming = types.BodyFraming;

// =============================================================================
// BodyReader - Lazy Body Reading
// =============================================================================

/// BodyReader enables lazy request body reading in direct response handlers.
///
/// Industry standard pattern: Body is only read when handler explicitly requests it.
/// This avoids reading large request bodies that may not be needed (e.g., rejecting
/// requests based on headers alone).
///
/// TigerStyle: No allocation, uses caller-provided buffer, bounded by content_length.
///
/// Example usage in onRequest hook:
/// ```zig
/// pub fn onRequest(self: *@This(), ctx: *serval.Context, request: *serval.Request, response_buf: []u8) serval.Action {
///     var body_buf: [8192]u8 = undefined;
///     const body = ctx.readBody(&body_buf) catch |err| {
///         return .{ .reject = .{ .status = 400, .reason = "Body read failed" } };
///     };
///     // Process body...
/// }
/// ```
pub const BodyReader = struct {
    /// Body framing mode (content_length, chunked, or none).
    framing: BodyFraming,

    /// Number of body bytes already read into initial buffer.
    /// These bytes are in initial_body and must be copied first.
    bytes_already_read: u64,

    /// Initial body bytes already in request buffer (after headers).
    /// Points into server's recv_buf - valid only for this request.
    initial_body: []const u8,

    /// Opaque pointer to server-specific read context (TLS stream, io, etc.).
    /// TigerStyle: Erased pointer to avoid generics leaking into serval-core.
    read_ctx: ?*anyopaque,

    /// Function pointer for reading more data from the connection.
    /// Returns number of bytes read into buf, or null on error/EOF.
    /// TigerStyle: Function pointer enables server to provide platform-specific I/O.
    read_fn: ?*const fn (ctx: *anyopaque, buf: []u8) ?usize,

    /// Total bytes read so far (including initial_body).
    total_bytes_read: u64 = 0,

    /// Whether initial body has been consumed.
    initial_consumed: bool = false,

    /// Read request body into provided buffer.
    ///
    /// Returns slice of body data read into buf.
    /// Multiple calls will read more data (for chunked or large bodies).
    ///
    /// TigerStyle: Bounded by content_length if present, caller provides buffer.
    ///
    /// Arguments:
    ///   buf: Buffer to read body into. Must be large enough for expected body.
    ///
    /// Returns:
    ///   - Slice of buf containing body data read.
    ///   - Empty slice if no body or body fully read.
    ///
    /// Errors:
    ///   - error.BodyReaderNotConfigured: read_fn not set (server doesn't support lazy reading).
    ///   - error.BodyTooLarge: Content-Length exceeds buf size.
    ///   - error.ReadFailed: I/O error during read.
    pub fn read(self: *BodyReader, buf: []u8) ![]const u8 {
        // S1: Precondition - buffer must be provided
        assert(buf.len > 0);

        // Handle body framing modes
        switch (self.framing) {
            .none => return buf[0..0], // No body expected
            .chunked => return error.ChunkedNotSupported, // Chunked requires streaming
            .content_length => |content_length| {
                // S1: Precondition - check bounds
                if (content_length > buf.len) return error.BodyTooLarge;
                if (content_length == 0) return buf[0..0];

                const body_len: usize = @intCast(content_length);

                // Copy initial body bytes first (if not already consumed)
                var dest_offset: usize = 0;
                if (!self.initial_consumed and self.initial_body.len > 0) {
                    const copy_len = @min(self.initial_body.len, body_len);
                    @memcpy(buf[0..copy_len], self.initial_body[0..copy_len]);
                    dest_offset = copy_len;
                    self.initial_consumed = true;
                    self.total_bytes_read = copy_len;
                }

                // Read remaining body bytes if needed
                if (dest_offset < body_len) {
                    const read_ctx = self.read_ctx orelse return error.BodyReaderNotConfigured;
                    const read_fn = self.read_fn orelse return error.BodyReaderNotConfigured;

                    // S3: Bounded loop - max iterations based on content_length
                    const max_iterations: u32 = 1024;
                    var iterations: u32 = 0;

                    while (dest_offset < body_len and iterations < max_iterations) {
                        iterations += 1;

                        const remaining = body_len - dest_offset;
                        const n = read_fn(read_ctx, buf[dest_offset..][0..remaining]) orelse {
                            return error.ReadFailed;
                        };
                        if (n == 0) return error.ReadFailed; // Unexpected EOF

                        dest_offset += n;
                        self.total_bytes_read += n;
                    }

                    // S3: Check loop bound wasn't exceeded
                    if (iterations >= max_iterations and dest_offset < body_len) {
                        return error.ReadFailed;
                    }
                }

                // S2: Postcondition - read exactly content_length bytes
                assert(dest_offset == body_len);
                return buf[0..body_len];
            },
        }
    }

    /// Check if body reading is available.
    /// TigerStyle: Explicit availability check.
    pub fn isAvailable(self: *const BodyReader) bool {
        return self.read_fn != null and self.read_ctx != null;
    }

    /// Get expected body length if known.
    /// TigerStyle: Trivial accessor, no assertions needed.
    pub fn getContentLength(self: *const BodyReader) ?u64 {
        return self.framing.getContentLength();
    }
};

/// Errors that can occur during body reading.
/// TigerStyle: Explicit error set with all possible body read failures.
pub const BodyReadError = error{
    /// BodyReader not available - server hasn't set up body reader.
    BodyReaderNotAvailable,
    /// BodyReader not configured - read function not set.
    BodyReaderNotConfigured,
    /// Content-Length exceeds provided buffer size.
    BodyTooLarge,
    /// I/O error or unexpected EOF during read.
    ReadFailed,
    /// Chunked transfer encoding not supported for lazy reading.
    ChunkedNotSupported,
};

pub const Context = struct {
    // Timing - i128 matches std.time.Instant.timestamp/realtimeNanos() return type,
    // which can represent nanoseconds since epoch including pre-1970 dates.
    start_time_ns: i128 = 0,

    // Request metadata
    request_id: u64 = 0,

    // User-defined storage - caller owns lifetime; must remain valid for request duration.
    // Server does not free or manage this pointer.
    user_data: ?*anyopaque = null,

    // Set after selectUpstream
    upstream: ?Upstream = null,

    // Set by router when route matches with strip_prefix=true.
    // Points to slice of original request path (zero-copy).
    // If null, forwarder uses original request path.
    rewritten_path: ?[]const u8 = null,

    // Metrics (updated by server)
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,

    // Response status (set after response)
    response_status: u16 = 0,
    duration_ns: u64 = 0,

    // Error tracking - points to comptime string literal from @errorName().
    // Valid for program lifetime (static string table).
    error_name: ?[]const u8 = null,

    // Connection-scoped fields (set once per connection, preserved across requests)
    connection_id: u64 = 0,
    connection_start_ns: i128 = 0,
    request_number: u32 = 0,
    client_addr: [46]u8 = std.mem.zeroes([46]u8),
    client_port: u16 = 0,

    // Request timing
    parse_duration_ns: u64 = 0,

    // Tracing - span handle for the current request
    // Set by server, can be used by handlers to create child spans.
    // TigerStyle: Fixed-size (32 bytes), no allocation.
    span_handle: SpanHandle = .{},

    // Body reader for lazy body reading in direct response handlers.
    // Set by server before calling onRequest hook.
    // TigerStyle: Optional pointer - null means body reading not available.
    _body_reader: ?*BodyReader = null,

    pub fn init() Context {
        const ctx = Context{
            .start_time_ns = time.realtimeNanos(),
        };

        // Postcondition: time must be valid (realtimeNanos always returns positive nanoseconds)
        std.debug.assert(ctx.start_time_ns > 0);

        return ctx;
    }

    /// Reset context for a new request while preserving connection-scoped fields.
    /// Connection-scoped fields (connection_id, connection_start_ns, client_addr,
    /// client_port) are preserved. Per-request fields are reset, and request_number
    /// is incremented.
    pub fn reset(self: *Context) void {
        // Preserve connection-scoped fields
        const connection_id = self.connection_id;
        const connection_start_ns = self.connection_start_ns;
        const client_addr = self.client_addr;
        const client_port = self.client_port;
        const request_number = self.request_number;

        // Reset all fields to defaults
        self.* = .{
            .start_time_ns = time.realtimeNanos(),
        };

        // Restore connection-scoped fields
        self.connection_id = connection_id;
        self.connection_start_ns = connection_start_ns;
        self.client_addr = client_addr;
        self.client_port = client_port;
        self.request_number = request_number + 1;

        // Postcondition: connection-scoped fields preserved, per-request fields reset
        assert(self.connection_id == connection_id);
        assert(self.bytes_received == 0 and self.response_status == 0);
    }

    /// Read request body into provided buffer.
    ///
    /// This enables lazy body reading - body is only read when handler explicitly
    /// requests it. Industry standard pattern used by Express.js, Go's http.Request, etc.
    ///
    /// TigerStyle: Caller provides buffer, bounded by Content-Length.
    ///
    /// Arguments:
    ///   buf: Buffer to read body into. Should be at least as large as expected
    ///        Content-Length. Use config.DIRECT_REQUEST_BODY_SIZE_BYTES as max.
    ///
    /// Returns:
    ///   - Slice of buf containing body data.
    ///   - Empty slice if no body present.
    ///
    /// Errors:
    ///   - error.BodyReaderNotAvailable: Server hasn't set up body reader.
    ///   - error.BodyTooLarge: Content-Length exceeds buffer size.
    ///   - error.ReadFailed: I/O error during read.
    ///   - error.ChunkedNotSupported: Chunked transfer encoding not supported.
    ///
    /// Example:
    /// ```zig
    /// var body_buf: [config.DIRECT_REQUEST_BODY_SIZE_BYTES]u8 = undefined;
    /// const body = ctx.readBody(&body_buf) catch |err| {
    ///     return .{ .reject = .{ .status = 400, .reason = "Body read failed" } };
    /// };
    /// ```
    pub fn readBody(self: *Context, buf: []u8) BodyReadError![]const u8 {
        // S1: Precondition - buffer must be provided
        assert(buf.len > 0);

        const reader = self._body_reader orelse return error.BodyReaderNotAvailable;
        return reader.read(buf);
    }

    /// Check if body reading is available for this request.
    /// TigerStyle: Explicit availability check before attempting read.
    pub fn canReadBody(self: *const Context) bool {
        if (self._body_reader) |reader| {
            return reader.isAvailable();
        }
        return false;
    }

    /// Get expected body length if known (from Content-Length header).
    /// Returns null for chunked encoding or no body.
    /// TigerStyle: Useful for pre-checking buffer size requirements.
    pub fn getBodyLength(self: *const Context) ?u64 {
        if (self._body_reader) |reader| {
            return reader.getContentLength();
        }
        return null;
    }
};

test "Context init" {
    const ctx = Context.init();
    try std.testing.expect(ctx.start_time_ns > 0);
    try std.testing.expectEqual(@as(?Upstream, null), ctx.upstream);
}

test "Context reset preserves connection-scoped fields" {
    var ctx = Context.init();

    // Set connection-scoped fields
    ctx.connection_id = 12345;
    ctx.connection_start_ns = 9999;
    ctx.client_addr[0] = '1';
    ctx.client_addr[1] = '2';
    ctx.client_addr[2] = '7';
    ctx.client_port = 8080;
    ctx.request_number = 5;

    // Set per-request fields that should be reset
    ctx.bytes_received = 1000;
    ctx.parse_duration_ns = 500;
    ctx.response_status = 200;
    ctx.rewritten_path = "/api/users";

    // Reset for new request
    ctx.reset();

    // Connection-scoped fields should be preserved
    try std.testing.expectEqual(@as(u64, 12345), ctx.connection_id);
    try std.testing.expectEqual(@as(i128, 9999), ctx.connection_start_ns);
    try std.testing.expectEqual(@as(u8, '1'), ctx.client_addr[0]);
    try std.testing.expectEqual(@as(u8, '2'), ctx.client_addr[1]);
    try std.testing.expectEqual(@as(u8, '7'), ctx.client_addr[2]);
    try std.testing.expectEqual(@as(u16, 8080), ctx.client_port);

    // Request number should be incremented
    try std.testing.expectEqual(@as(u32, 6), ctx.request_number);

    // Per-request fields should be reset
    try std.testing.expectEqual(@as(u64, 0), ctx.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), ctx.parse_duration_ns);
    try std.testing.expectEqual(@as(u16, 0), ctx.response_status);
    try std.testing.expectEqual(@as(?[]const u8, null), ctx.rewritten_path);

    // Start time should be refreshed
    try std.testing.expect(ctx.start_time_ns > 0);

    // Body reader should be reset to null
    try std.testing.expectEqual(@as(?*BodyReader, null), ctx._body_reader);
}

// =============================================================================
// BodyReader Tests
// =============================================================================

test "BodyReader read with no body" {
    var reader = BodyReader{
        .framing = .none,
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
    };

    var buf: [64]u8 = undefined;
    const result = try reader.read(&buf);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "BodyReader read with content_length zero" {
    var reader = BodyReader{
        .framing = .{ .content_length = 0 },
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
    };

    var buf: [64]u8 = undefined;
    const result = try reader.read(&buf);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "BodyReader read from initial_body only" {
    const initial = "Hello, World!";
    var reader = BodyReader{
        .framing = .{ .content_length = initial.len },
        .bytes_already_read = initial.len,
        .initial_body = initial,
        .read_ctx = null,
        .read_fn = null,
    };

    var buf: [64]u8 = undefined;
    const result = try reader.read(&buf);
    try std.testing.expectEqualStrings("Hello, World!", result);
    try std.testing.expectEqual(@as(u64, initial.len), reader.total_bytes_read);
}

test "BodyReader read with content_length exceeds buffer" {
    var reader = BodyReader{
        .framing = .{ .content_length = 1000 },
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
    };

    var buf: [64]u8 = undefined;
    const result = reader.read(&buf);
    try std.testing.expectError(error.BodyTooLarge, result);
}

test "BodyReader read with chunked encoding returns error" {
    var reader = BodyReader{
        .framing = .chunked,
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
    };

    var buf: [64]u8 = undefined;
    const result = reader.read(&buf);
    try std.testing.expectError(error.ChunkedNotSupported, result);
}

test "BodyReader isAvailable" {
    var reader = BodyReader{
        .framing = .none,
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
    };

    try std.testing.expect(!reader.isAvailable());
}

test "BodyReader getContentLength" {
    var reader1 = BodyReader{
        .framing = .{ .content_length = 42 },
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
    };
    try std.testing.expectEqual(@as(u64, 42), reader1.getContentLength().?);

    var reader2 = BodyReader{
        .framing = .chunked,
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
    };
    try std.testing.expect(reader2.getContentLength() == null);
}

// =============================================================================
// Context.readBody Tests
// =============================================================================

test "Context readBody without body reader returns error" {
    var ctx = Context.init();
    var buf: [64]u8 = undefined;
    const result = ctx.readBody(&buf);
    try std.testing.expectError(error.BodyReaderNotAvailable, result);
}

test "Context canReadBody without body reader" {
    const ctx = Context.init();
    try std.testing.expect(!ctx.canReadBody());
}

test "Context getBodyLength without body reader" {
    const ctx = Context.init();
    try std.testing.expect(ctx.getBodyLength() == null);
}

test "Context readBody with body reader" {
    const initial = "test body";
    var reader = BodyReader{
        .framing = .{ .content_length = initial.len },
        .bytes_already_read = initial.len,
        .initial_body = initial,
        .read_ctx = null,
        .read_fn = null,
    };

    var ctx = Context.init();
    ctx._body_reader = &reader;

    var buf: [64]u8 = undefined;
    const result = try ctx.readBody(&buf);
    try std.testing.expectEqualStrings("test body", result);
}

test "Context getBodyLength with body reader" {
    var reader = BodyReader{
        .framing = .{ .content_length = 100 },
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
    };

    var ctx = Context.init();
    ctx._body_reader = &reader;

    try std.testing.expectEqual(@as(u64, 100), ctx.getBodyLength().?);
}
