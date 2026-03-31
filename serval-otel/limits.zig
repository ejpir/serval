//! OpenTelemetry module-owned limits.
//!
//! These bounds are part of `serval-otel`'s public surface and should be owned
//! here rather than re-exported from `serval-core`.

pub const MAX_ACTIVE_SPANS: u32 = 16;
pub const MAX_ATTRIBUTES: u32 = 32;
pub const MAX_EVENTS: u32 = 8;
pub const MAX_LINKS: u32 = 4;
pub const MAX_KEY_LEN: u32 = 64;
pub const MAX_NAME_LEN: u32 = 128;
pub const MAX_STRING_VALUE_LEN: u32 = 256;

pub const MAX_TRACE_STATE_ENTRIES: u32 = 8;
pub const MAX_TRACE_STATE_KEY_LEN: u32 = 64;
pub const MAX_TRACE_STATE_VALUE_LEN: u32 = 256;

pub const MAX_QUEUE_SIZE: u32 = 2048;
pub const MAX_EXPORT_BATCH_SIZE: u32 = 512;
pub const DEFAULT_BATCH_DELAY_MS: u32 = 5000;
pub const MAX_EXPORT_BUFFER_SIZE: u32 = 1024 * 1024;
pub const HTTP_TIMEOUT_MS: u32 = 30000;
pub const DEFAULT_ENDPOINT: []const u8 = "http://localhost:4318/v1/traces";

test "otel limits remain bounded" {
    try @import("std").testing.expect(MAX_ACTIVE_SPANS > 0);
    try @import("std").testing.expect(MAX_EXPORT_BATCH_SIZE <= MAX_QUEUE_SIZE);
}
