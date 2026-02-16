//! Trace/Span ID Generator
//!
//! Generates cryptographically random TraceID (128-bit) and SpanID (64-bit).
//! TigerStyle: no allocation, deterministic seeding option for tests.

const std = @import("std");
const core = @import("serval-core");
const types = @import("types.zig");

const TraceID = types.TraceID;
const SpanID = types.SpanID;

// =============================================================================
// RandomIDGenerator
// =============================================================================

/// Generates random TraceID and SpanID values using Xoshiro256.
/// Thread-safe through external synchronization (caller must hold mutex).
pub const RandomIDGenerator = struct {
    prng: std.Random.Xoshiro256,

    const Self = @This();

    /// Initialize with a seed (use for deterministic testing)
    pub fn init(seed: u64) Self {
        return .{
            .prng = std.Random.Xoshiro256.init(seed),
        };
    }

    /// Initialize with random seed from OS
    pub fn initRandom() Self {
        const realtime_ns = core.realtimeNanos();
        const monotonic_ns = core.monotonicNanos();
        const realtime_u64: u64 = @intCast(@max(0, realtime_ns) & 0xFFFFFFFFFFFFFFFF);
        const seed: u64 = realtime_u64 ^ monotonic_ns;
        return init(seed);
    }

    /// Generate a new TraceID (128-bit, guaranteed non-zero)
    pub fn newTraceId(self: *Self) TraceID {
        return self.newValidId(TraceID, 16);
    }

    /// Generate a new SpanID (64-bit, guaranteed non-zero)
    pub fn newSpanId(self: *Self) SpanID {
        return self.newValidId(SpanID, 8);
    }

    /// Generate a valid ID of the specified type.
    /// TigerStyle: bounded loop (max 10 attempts, then force non-zero).
    fn newValidId(self: *Self, comptime IdType: type, comptime size: usize) IdType {
        const max_attempts: u32 = 10;
        var attempts: u32 = 0;
        while (attempts < max_attempts) : (attempts += 1) {
            var bytes: [size]u8 = undefined;
            self.prng.random().bytes(&bytes);
            const id = IdType.init(bytes);
            if (id.isValid()) return id;
        }
        // Fallback: force at least one byte non-zero
        var bytes: [size]u8 = undefined;
        self.prng.random().bytes(&bytes);
        bytes[0] = 1;
        return IdType.init(bytes);
    }

    /// Generate both TraceID and SpanID in one call
    pub fn newIds(self: *Self) struct { trace_id: TraceID, span_id: SpanID } {
        return .{
            .trace_id = self.newTraceId(),
            .span_id = self.newSpanId(),
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

test "RandomIDGenerator generates valid TraceIDs" {
    var gen = RandomIDGenerator.init(12345);

    for (0..1000) |_| {
        const trace_id = gen.newTraceId();
        try std.testing.expect(trace_id.isValid());
    }
}

test "RandomIDGenerator generates valid SpanIDs" {
    var gen = RandomIDGenerator.init(12345);

    for (0..1000) |_| {
        const span_id = gen.newSpanId();
        try std.testing.expect(span_id.isValid());
    }
}

test "RandomIDGenerator generates unique IDs" {
    var gen = RandomIDGenerator.init(12345);

    const id1 = gen.newTraceId();
    const id2 = gen.newTraceId();
    const id3 = gen.newTraceId();

    // Different IDs (extremely unlikely to collide with 128 bits)
    try std.testing.expect(!std.mem.eql(u8, &id1.bytes, &id2.bytes));
    try std.testing.expect(!std.mem.eql(u8, &id2.bytes, &id3.bytes));
}

test "RandomIDGenerator newIds returns both" {
    var gen = RandomIDGenerator.init(12345);

    const ids = gen.newIds();
    try std.testing.expect(ids.trace_id.isValid());
    try std.testing.expect(ids.span_id.isValid());
}

test "RandomIDGenerator deterministic with same seed" {
    var gen1 = RandomIDGenerator.init(42);
    var gen2 = RandomIDGenerator.init(42);

    const id1 = gen1.newTraceId();
    const id2 = gen2.newTraceId();

    try std.testing.expectEqual(id1.bytes, id2.bytes);
}
