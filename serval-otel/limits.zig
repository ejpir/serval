//! OpenTelemetry module-owned limits.
//!
//! These bounds are part of `serval-otel`'s public surface and should be owned
//! here rather than re-exported from `serval-core`.

/// Maximum simultaneously tracked in-memory spans before backpressure/drop policy applies.
pub const MAX_ACTIVE_SPANS: u32 = 16;
/// Maximum attributes accepted per span.
pub const MAX_ATTRIBUTES: u32 = 32;
/// Maximum events accepted per span.
pub const MAX_EVENTS: u32 = 8;
/// Maximum links accepted per span.
pub const MAX_LINKS: u32 = 4;
/// Maximum attribute key length in bytes.
pub const MAX_KEY_LEN: u32 = 64;
/// Maximum span/attribute/event name length in bytes.
pub const MAX_NAME_LEN: u32 = 128;
/// Maximum string attribute/event value length in bytes.
pub const MAX_STRING_VALUE_LEN: u32 = 256;

/// Maximum W3C `tracestate` entries retained per span context.
pub const MAX_TRACE_STATE_ENTRIES: u32 = 8;
/// Maximum `tracestate` key length in bytes.
pub const MAX_TRACE_STATE_KEY_LEN: u32 = 64;
/// Maximum `tracestate` value length in bytes.
pub const MAX_TRACE_STATE_VALUE_LEN: u32 = 256;

/// Maximum queued spans waiting for exporter flush.
pub const MAX_QUEUE_SIZE: u32 = 2048;
/// Maximum spans exported in a single batch request.
pub const MAX_EXPORT_BATCH_SIZE: u32 = 512;
/// Default exporter batch delay in milliseconds.
pub const DEFAULT_BATCH_DELAY_MS: u32 = 5000;
/// Maximum serialized export payload size in bytes.
pub const MAX_EXPORT_BUFFER_SIZE: u32 = 1024 * 1024;
/// HTTP exporter request timeout in milliseconds.
pub const HTTP_TIMEOUT_MS: u32 = 30000;
/// Default OTLP/HTTP traces endpoint URL.
pub const DEFAULT_ENDPOINT: []const u8 = "http://localhost:4318/v1/traces";

test "otel limits remain bounded" {
    try @import("std").testing.expect(MAX_ACTIVE_SPANS > 0);
    try @import("std").testing.expect(MAX_EXPORT_BATCH_SIZE <= MAX_QUEUE_SIZE);
}
