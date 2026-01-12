//! Kubernetes Watch Stream Implementation
//!
//! WatchStream and LazyWatchStream types for streaming watch events
//! from the Kubernetes API server.
//!
//! TigerStyle: Bounded buffers, explicit error handling, no allocation after init.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_client = @import("serval-client");
const serval_core = @import("serval-core");

const BodyFraming = serval_core.types.BodyFraming;
const debugLog = serval_core.debugLog;

const mod = @import("mod.zig");
const ClientError = mod.ClientError;

// Forward declare Client to avoid circular import
const Client = @import("client.zig").Client;

// =============================================================================
// Constants
// =============================================================================

/// Maximum size of a single watch event line.
/// Secrets with TLS certificates can be 500KB+, so we allow 1MB.
pub const MAX_WATCH_EVENT_SIZE: u32 = 1024 * 1024;

/// Maximum iterations for reading chunks in a single readEvent call.
const MAX_CHUNK_READ_ITERATIONS: u32 = 1000;

// =============================================================================
// Watch Stream
// =============================================================================

/// Represents a streaming watch connection to K8s API.
/// Maintains an open connection and reads newline-delimited JSON events.
/// TigerStyle: Pre-allocated buffer, bounded operations.
pub const WatchStream = struct {
    /// Connection to K8s API (owned, must be closed by caller).
    conn: serval_client.client.Connection,
    /// Body framing type (stored for lazy BodyReader initialization).
    body_framing: BodyFraming,
    /// Whether body_reader has been initialized.
    body_reader_initialized: bool,
    /// Body reader for incremental chunked reading.
    /// Initialized lazily on first readEvent to avoid dangling pointer.
    body_reader: serval_client.BodyReader,
    /// Buffer for accumulating partial lines.
    line_buffer: []u8,
    /// Current position in line_buffer (data from 0..line_pos).
    line_pos: u32,
    /// Whether the stream has ended.
    done: bool,

    const Self = @This();

    /// Read the next event from the watch stream.
    /// Returns a complete JSON line (one event), or null if stream ended.
    /// The returned slice points into the provided buffer.
    ///
    /// TigerStyle: Bounded iterations, explicit error handling.
    pub fn readEvent(self: *Self, buffer: []u8, io: Io) ClientError!?[]const u8 {
        assert(buffer.len > 0); // S1: buffer must have capacity
        _ = io; // Io runtime is embedded in connection's socket

        if (self.done) return null;

        // Lazily initialize body_reader on first call.
        // This must happen after the WatchStream is in its final location.
        if (!self.body_reader_initialized) {
            self.body_reader = serval_client.BodyReader.init(&self.conn.socket, self.body_framing);
            self.body_reader_initialized = true;
            debugLog("watcher: body_reader initialized", .{});
        }

        // Check if we already have a complete line in the buffer.
        if (self.findNewline()) |newline_pos| {
            return self.extractLine(buffer, newline_pos);
        }

        // Read more data until we get a complete line.
        var iterations: u32 = 0;
        while (iterations < MAX_CHUNK_READ_ITERATIONS) : (iterations += 1) {
            // Read next chunk from body.
            const remaining_space = self.line_buffer.len - self.line_pos;
            if (remaining_space == 0) {
                // Buffer full but no newline found - event too large.
                debugLog("watcher: event exceeds buffer size", .{});
                return ClientError.ResponseTooLarge;
            }

            debugLog("watcher: calling body_reader.readChunk, line_pos={d}, space={d}", .{
                self.line_pos,
                self.line_buffer.len - self.line_pos,
            });

            const chunk = self.body_reader.readChunk(self.line_buffer[self.line_pos..]) catch |err| {
                debugLog("watcher: chunk read error: {s}", .{@errorName(err)});
                self.done = true;
                return switch (err) {
                    error.UnexpectedEof => null, // Stream ended gracefully.
                    error.BufferTooSmall => ClientError.ResponseTooLarge,
                    error.InvalidChunkedEncoding => ClientError.ResponseParseFailed,
                    error.ChunkTooLarge => ClientError.ResponseTooLarge,
                    error.ReadFailed => ClientError.RequestFailed,
                    error.IterationLimitExceeded => ClientError.ReadIterationsExceeded,
                    error.WriteFailed, error.SpliceFailed, error.PipeCreationFailed => ClientError.RequestFailed,
                };
            };

            debugLog("watcher: readChunk returned", .{});

            if (chunk) |data| {
                self.line_pos += @intCast(data.len);
                debugLog("watcher: read chunk len={d} total={d}", .{ data.len, self.line_pos });

                // Check for complete line.
                if (self.findNewline()) |newline_pos| {
                    return self.extractLine(buffer, newline_pos);
                }
            } else {
                // Stream ended.
                debugLog("watcher: stream ended", .{});
                self.done = true;

                // Return any remaining data as final event (if non-empty).
                if (self.line_pos > 0) {
                    const len = @min(self.line_pos, @as(u32, @intCast(buffer.len)));
                    @memcpy(buffer[0..len], self.line_buffer[0..len]);
                    self.line_pos = 0;
                    return buffer[0..len];
                }
                return null;
            }
        }

        // Too many iterations without finding a newline.
        debugLog("watcher: max iterations without complete event", .{});
        return ClientError.ReadIterationsExceeded;
    }

    /// Find the position of the first newline in the buffer.
    fn findNewline(self: *Self) ?u32 {
        var i: u32 = 0;
        while (i < self.line_pos) : (i += 1) {
            if (self.line_buffer[i] == '\n') {
                return i;
            }
        }
        return null;
    }

    /// Extract a complete line from the buffer and copy to output.
    /// Shifts remaining data to start of buffer.
    fn extractLine(self: *Self, buffer: []u8, newline_pos: u32) []const u8 {
        // Copy line to output buffer (excluding newline).
        const line_len = @min(newline_pos, @as(u32, @intCast(buffer.len)));
        @memcpy(buffer[0..line_len], self.line_buffer[0..line_len]);

        // Shift remaining data to start of buffer.
        const remaining = self.line_pos - newline_pos - 1;
        if (remaining > 0) {
            const src_start = newline_pos + 1;
            // Use a loop instead of memcpy for overlapping regions.
            var j: u32 = 0;
            while (j < remaining) : (j += 1) {
                self.line_buffer[j] = self.line_buffer[src_start + j];
            }
        }
        self.line_pos = remaining;

        debugLog("watcher: extracted event len={d} remaining={d}", .{ line_len, remaining });
        return buffer[0..line_len];
    }

    /// Close the watch stream connection.
    pub fn close(self: *Self) void {
        self.conn.socket.close();
        self.done = true;
    }
};

// =============================================================================
// Lazy Watch Stream
// =============================================================================

/// Lazy watch stream that opens connection on first readEvent call.
/// This maintains backward compatibility with existing watcher code.
/// Allocates its own internal line buffer for proper streaming.
pub const LazyWatchStream = struct {
    client: *Client,
    path: []const u8,
    stream: ?WatchStream,
    /// Internal line buffer for accumulating partial events.
    /// Allocated on first readEvent, freed on close.
    internal_buffer: ?[]u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(client: *Client, path: []const u8, allocator: std.mem.Allocator) Self {
        return Self{
            .client = client,
            .path = path,
            .stream = null,
            .internal_buffer = null,
            .allocator = allocator,
        };
    }

    pub fn readEvent(self: *Self, buffer: []u8, io: Io) ClientError!?[]const u8 {
        // Allocate internal buffer on first call if needed.
        if (self.internal_buffer == null) {
            self.internal_buffer = self.allocator.alloc(u8, MAX_WATCH_EVENT_SIZE) catch {
                return ClientError.OutOfMemory;
            };
        }

        // Open stream on first call.
        if (self.stream == null) {
            self.stream = self.client.watchStream(self.path, self.internal_buffer.?, io) catch |err| {
                return err;
            };
        }

        return self.stream.?.readEvent(buffer, io);
    }

    pub fn close(self: *Self) void {
        if (self.stream) |*s| {
            s.close();
        }
        if (self.internal_buffer) |buf| {
            self.allocator.free(buf);
            self.internal_buffer = null;
        }
    }
};

// =============================================================================
// Unit Tests
// =============================================================================

test "WatchStream constants are reasonable" {
    // MAX_WATCH_EVENT_SIZE should accommodate large K8s resources (Secrets with TLS certs)
    try std.testing.expect(MAX_WATCH_EVENT_SIZE >= 512 * 1024); // At least 512KB
    try std.testing.expect(MAX_WATCH_EVENT_SIZE <= 16 * 1024 * 1024); // At most 16MB

    // MAX_CHUNK_READ_ITERATIONS provides bounded loop safety
    try std.testing.expect(MAX_CHUNK_READ_ITERATIONS >= 100);
    try std.testing.expect(MAX_CHUNK_READ_ITERATIONS <= 10000);
}
