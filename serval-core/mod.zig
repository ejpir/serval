// lib/serval-core/mod.zig
//! Serval Core - Foundation Types
//!
//! Zero-dependency foundation for serval library.
//! Contains types, errors, config, and context.
//! TigerStyle: Explicit types, no allocation.

// Types
pub const types = @import("types.zig");
pub const Request = types.Request;
pub const Response = types.Response;
pub const Upstream = types.Upstream;
pub const Action = types.Action;
pub const Method = types.Method;
pub const Version = types.Version;
pub const Header = types.Header;
pub const HeaderMap = types.HeaderMap;
pub const ConnectionInfo = types.ConnectionInfo;
pub const UpstreamConnectInfo = types.UpstreamConnectInfo;

// Config
pub const config = @import("config.zig");
pub const Config = config.Config;

// Logging
pub const log = @import("log.zig");
pub const debugLog = log.debugLog;
pub const LogEntry = log.LogEntry;

// Errors
pub const errors = @import("errors.zig");
pub const ParseError = errors.ParseError;
pub const ConnectionError = errors.ConnectionError;
pub const UpstreamError = errors.UpstreamError;
pub const RequestError = errors.RequestError;
pub const ErrorContext = errors.ErrorContext;

// Context
pub const context = @import("context.zig");
pub const Context = context.Context;

// Handler hook verification
pub const hooks = @import("hooks.zig");
pub const verifyHandler = hooks.verifyHandler;
pub const hasHook = hooks.hasHook;

// Span handle (for tracing context propagation)
pub const span_handle = @import("span_handle.zig");
pub const SpanHandle = span_handle.SpanHandle;

// Time utilities
pub const time = @import("time.zig");
pub const realtimeNanos = time.realtimeNanos;
pub const monotonicNanos = time.monotonicNanos;
pub const elapsedNanos = time.elapsedNanos;
pub const elapsedSince = time.elapsedSince;

test {
    _ = @import("types.zig");
    _ = @import("errors.zig");
    _ = @import("config.zig");
    _ = @import("context.zig");
    _ = @import("log.zig");
    _ = @import("hooks.zig");
    _ = @import("time.zig");
    _ = @import("span_handle.zig");
}
