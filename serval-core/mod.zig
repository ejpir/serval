// lib/serval-core/mod.zig
//! Serval Core - Foundation Types
//!
//! Zero-dependency foundation for serval library.
//! Contains types, errors, config, and context.
//! TigerStyle: Explicit types, no allocation.

// Types
/// Re-exports `types.zig` as the `types` namespace for `serval-core`.
/// Use this to access shared core type declarations via `serval_core.types`.
/// This is a compile-time module alias; it performs no runtime work and has no error behavior.
pub const types = @import("types.zig");
/// Re-export of `types.Request`, the zero-copy HTTP request container.
/// Its fields hold the parsed method, path, version, headers, and optional body for an inbound request.
/// Slice fields borrow parser-owned storage, so the backing buffers must remain valid while the request is in use.
pub const Request = types.Request;
/// Re-export of `types.Response`, the HTTP response container used by handlers and server internals.
/// It carries a status code, parsed headers, and an optional body slice.
/// Any slice fields borrow their storage; keep that storage valid for as long as the response is observed.
pub const Response = types.Response;
/// Re-export of `types.Upstream`, the destination description used when selecting a backend.
/// `host` is a borrowed slice, `port` identifies the target endpoint, and `idx` selects the connection-pool slot.
/// `tls` and `http_protocol` describe the transport and application protocol; the default is plaintext HTTP/1.1.
pub const Upstream = types.Upstream;
/// Re-export of `types.HttpProtocol`, the application protocol spoken by an upstream.
/// `.h1` selects HTTP/1.1, `.h2c` selects cleartext HTTP/2 prior knowledge, and `.h2` selects HTTP/2 over TLS via ALPN.
/// Use this instead of encoding protocol choice in TLS flags.
pub const HttpProtocol = types.HttpProtocol;
/// Re-export of `types.Action` for hook return values that control request processing.
/// Use `continue_request` to proceed, `send_response` to return a direct response,
/// `reject` to block the request, or `stream` for incrementally generated chunked responses.
/// This is a compile-time alias only and introduces no ownership or allocation semantics.
pub const Action = types.Action;
/// Re-export of `types.BodyAction` for `onRequestBody` and `onResponseBody` hooks.
/// Use `continue_body` to keep processing the current body chunk, or `reject` to stop with a status.
/// The `reject` payload is a borrowed `RejectResponse`; this type owns no memory.
/// This is a compile-time alias only and adds no runtime behavior.
pub const BodyAction = types.BodyAction;
/// Re-export of `types.ErrorAction` for `onError` handlers.
/// Use `default` to keep the built-in 502 response, `send_response` to override it,
/// or `retry` after selecting a different upstream in `selectUpstream`.
/// This alias is zero-cost and carries no ownership or runtime behavior by itself.
pub const ErrorAction = types.ErrorAction;
/// Re-export of `types.RejectResponse` for hook rejection responses.
/// Use it with `Action.reject` or `BodyAction.reject` to report why a request was blocked.
/// `status` defaults to `403` and `reason` defaults to `"Forbidden"`.
/// The `reason` field is a borrowed `[]const u8` slice; this type does not allocate.
pub const RejectResponse = types.RejectResponse;
/// Re-export of `types.DirectResponse`, the fixed-size response payload used when a hook answers without forwarding upstream.
/// The response body must point into server-provided storage, and `extra_headers` must already be formatted as HTTP header lines.
/// Use `response_mode` to choose content-length or chunked framing; this alias adds no ownership or allocation behavior.
pub const DirectResponse = types.DirectResponse;
/// Re-export of `types.Method`, the HTTP method enum used in parsed requests and handler logic.
/// It includes the standard verbs supported by Serval core, such as `GET`, `POST`, `PUT`, and `CONNECT`.
/// The value is an enum only; it carries no payload and performs no parsing or validation by itself.
pub const Method = types.Method;
/// Re-export of `types.Version`, the HTTP version supported by Serval core request and response parsing.
/// The enum currently distinguishes `HTTP/1.0` and `HTTP/1.1` only.
/// Use this type when the wire version must be carried explicitly instead of inferred from other fields.
pub const Version = types.Version;
/// Re-export of `types.Header`, a single HTTP header name/value pair.
/// Both fields are borrowed slices and the struct performs no normalization or allocation on its own.
/// Keep the backing storage for both slices valid for as long as the header is observed.
pub const Header = types.Header;
/// Re-export of `types.HeaderMap`, the fixed-size HTTP header container used by core request and response types.
/// It stores headers in a bounded array and supports cached lookups for common fields such as `Content-Length`, `Host`, `Connection`, and `Transfer-Encoding`.
/// Header values are borrowed slices; the map itself does not allocate, but mutating methods can return header-related errors.
pub const HeaderMap = types.HeaderMap;
/// Re-export of `types.ConnectionInfo`, the fixed-size connection metadata passed to logging hooks.
/// It identifies the client and local ports, connection ID, and TCP RTT/variance values for the active connection.
/// The struct owns no memory and contains only value fields plus a fixed-size client address buffer.
pub const ConnectionInfo = types.ConnectionInfo;
/// Re-export of `types.UpstreamConnectInfo`, the timing snapshot reported to `onUpstreamConnect` hooks.
/// It captures DNS, TCP, TLS, pool-wait, and local-port information for a single upstream connection attempt.
/// TLS fields are empty for plaintext connections; this alias adds no allocation, ownership, or runtime behavior.
pub const UpstreamConnectInfo = types.UpstreamConnectInfo;
/// Re-export of `types.BodyFraming`, the tagged union that describes how request body length is determined.
/// Use `.content_length` for fixed-size bodies, `.chunked` for Transfer-Encoding chunked, and `.none` when no body is present.
/// `getContentLength()` returns the length only for `.content_length`; the other variants carry no body size.
pub const BodyFraming = types.BodyFraming;

// Config
/// Imports `config.zig` as the `config` namespace for `serval-core`.
/// Use this to access global limits, server configuration, TLS settings, and transport helpers via `serval_core.config`.
/// This is a compile-time alias only and performs no runtime work.
pub const config = @import("config.zig");
/// Re-export of `config.Config`, the top-level server configuration record.
/// It defines listener settings, keep-alive and request limits, TLS and h2c behavior, and optional ACME or L4 transport config.
/// String and nested config fields are borrowed or optional; keep referenced storage valid while the server uses the config.
pub const Config = config.Config;
/// Re-export of `config.AcmeConfig`, the ACME/Let's Encrypt automation configuration.
/// It enables automatic certificate lifecycle management and controls directory, state, retry, and renewal settings.
/// String fields are borrowed slices; the caller owns their storage for the lifetime of the config.
pub const AcmeConfig = config.AcmeConfig;

// Logging
/// Imports `log.zig` as the `log` namespace for `serval-core`.
/// Use this to access scoped logging helpers, `debugLog`, and `LogEntry` through `serval_core.log`.
/// This is a compile-time alias only and has no runtime cost.
pub const log = @import("log.zig");
/// Comptime-conditional debug logging helper.
/// Calls are compiled out when `config.DEBUG_LOGGING` is false, so release builds pay no runtime cost.
/// Prefer `log.scoped(...).debug()` for scoped output; `fmt` must be a non-empty compile-time format string.
pub const debugLog = log.debugLog;
/// Re-export of `log.LogEntry`, the structured request record passed to the `onLog` hook.
/// It captures request and response metadata, timings, upstream details, connection data, and error context.
/// `path` and `error_name` are borrowed slices that remain valid only for the logging callback.
pub const LogEntry = log.LogEntry;

// Errors
/// Imports `errors.zig` as the `errors` namespace for `serval-core`.
/// Use this to access the parser, connection, upstream, and error-context types from one place.
/// This is a compile-time alias only and has no runtime cost.
pub const errors = @import("errors.zig");
/// Re-export of `errors.ParseError`, the error set for request parsing and validation.
/// It covers malformed request lines, invalid headers, body-size limits, and request-smuggling protection checks.
/// Use these errors when rejecting malformed or ambiguous client input.
pub const ParseError = errors.ParseError;
/// Re-export of `errors.ConnectionError`, the error set for establishing a backend connection.
/// It represents connection setup failures such as refusal, reset, timeout, or other connect errors.
/// Use it to distinguish dial-time failures from request or response I/O failures.
pub const ConnectionError = errors.ConnectionError;
/// Re-export of `errors.UpstreamError`, the error set for failures while talking to an upstream.
/// It covers send, receive, empty-response, invalid-response, and stale-connection cases.
/// Use these errors when a backend connection succeeds but the request or response exchange fails.
pub const UpstreamError = errors.UpstreamError;
/// Re-export of `errors.RequestError`, the combined request failure set.
/// It includes parse, connection, and upstream error categories so callers can handle failures uniformly.
/// Match the underlying category when you need phase-specific recovery or logging.
pub const RequestError = errors.RequestError;
/// Re-export of `errors.ErrorContext`, the structured error payload passed to `onError` hooks.
/// It records the request error, the handling phase, the upstream involved, and whether the request is a retry.
/// Use it for error-policy decisions; it carries no ownership and does not allocate.
pub const ErrorContext = errors.ErrorContext;

// Context
/// Imports `context.zig` as the `context` namespace for `serval-core`.
/// Use this to access request-context types and helpers through `serval_core.context`.
/// This is a compile-time alias only and has no runtime cost or error behavior.
pub const context = @import("context.zig");
/// Re-export of `context.Context`, the per-request state object passed to handler hooks.
/// It carries request-scoped metadata, timing, upstream selection, tracing, and optional body-reading access.
/// Connection-scoped fields are preserved across `reset`; slice fields continue to borrow server-owned storage.
pub const Context = context.Context;
/// Re-export of `context.BodyReader`, the lazy request-body reader used by direct-response handlers.
/// It reads from the caller-provided buffer and only advances when the handler explicitly asks for body data.
/// Body reads are bounded by the request's framing; chunked bodies return `error.ChunkedNotSupported` here.
pub const BodyReader = context.BodyReader;
/// Re-export of `context.BodyReadError`, the error set for lazy request-body reading.
/// Use this when a `BodyReader` is unavailable, misconfigured, too small for the body, or cannot read the stream safely.
/// The error set includes `BodyReaderNotAvailable`, `BodyReaderNotConfigured`, `BodyTooLarge`, `ReadFailed`, and `ChunkedNotSupported`.
pub const BodyReadError = context.BodyReadError;

// Handler hook verification
/// Imports `hooks.zig` as the `hooks` namespace for handler interface verification helpers.
/// This module contains compile-time checks for required and optional handler hook signatures.
/// It is a compile-time alias only and has no runtime behavior.
pub const hooks = @import("hooks.zig");
/// Re-export of `hooks.verifyHandler` for compile-time handler interface validation.
/// Verifies that a handler type provides `selectUpstream` and that any declared optional hooks match the expected signatures.
/// Invalid declarations trigger compile errors during build, not runtime errors.
pub const verifyHandler = hooks.verifyHandler;
/// Re-export of `hooks.hasHook` for compile-time hook presence checks.
/// Use it to test whether a handler type declares a hook with a given name before wiring behavior around it.
/// It performs comptime reflection only and does not allocate or fail at runtime.
pub const hasHook = hooks.hasHook;

// Span handle (for tracing context propagation)
/// Imports `span_handle.zig` as the `span_handle` namespace.
/// This module defines the lightweight tracing handle used for context propagation.
/// It is a compile-time alias only and has no runtime behavior or error path.
pub const span_handle = @import("span_handle.zig");
/// Re-export of `span_handle.SpanHandle`, the fixed-size tracing context handle.
/// Stores trace, span, and parent-span identifiers in caller-owned byte arrays with zero default values.
/// The type allocates nothing; buffer-based hex helpers return slices into caller-provided storage.
pub const SpanHandle = span_handle.SpanHandle;

// Time utilities
/// Imports `time.zig` as the `time` namespace for centralized timing utilities.
/// Use this namespace for clock reads, elapsed-time helpers, sleep, and unit conversions.
/// This is a compile-time module alias only and has no runtime cost.
pub const time = @import("time.zig");
/// Re-export of `time.realtimeNanos` for reading wall-clock time in nanoseconds since the Unix epoch.
/// Use this for timestamps and logging rather than duration measurement.
/// The function returns `i128`, asserts the clock value is non-negative, and does not report errors.
pub const realtimeNanos = time.realtimeNanos;
/// Re-export of `time.monotonicNanos` for reading a monotonic timestamp in nanoseconds.
/// Use this for duration measurement and other interval tracking where wall-clock jumps would be harmful.
/// The function returns `u64`, asserts the clock value is non-negative, and does not report errors.
pub const monotonicNanos = time.monotonicNanos;
/// Re-export of `time.elapsedNanos` for subtracting two monotonic timestamps.
/// Returns the difference in nanoseconds when `end_ns >= start_ns`; otherwise it returns `0` to avoid underflow.
/// This helper is pure, does not allocate, and has no error path.
pub const elapsedNanos = time.elapsedNanos;
/// Re-export of `time.elapsedSince` for measuring elapsed monotonic time.
/// Computes the duration from a captured monotonic start timestamp to the current monotonic clock value.
/// It returns `u64` nanoseconds, clamps negative deltas to `0`, and does not return errors.
pub const elapsedSince = time.elapsedSince;

// POSIX compatibility
/// Imports `posix_compat.zig` as the `posix_compat` namespace.
/// This module contains thin compatibility wrappers for POSIX APIs removed from newer Zig stdlib releases.
/// It is a compile-time alias only and introduces no runtime work or error behavior.
pub const posix_compat = @import("posix_compat.zig");
/// Re-export of `posix_compat.closeFd` for closing POSIX file descriptors.
/// The underlying function asserts that `fd` is valid and then closes it directly through the OS layer.
/// It returns no value, ignores `EINTR`, and does not allocate.
pub const closeFd = posix_compat.closeFd;

// String utilities
/// Imports `strings.zig` as the `strings` namespace for shared string helpers.
/// Use this namespace to access the module's case-insensitive comparison and search utilities.
/// This is a compile-time module alias only and has no runtime behavior or errors.
pub const strings = @import("strings.zig");
/// Re-export of `strings.eqlIgnoreCase` for ASCII case-insensitive equality checks.
/// Compares two byte slices for equal length and matching contents, folding only ASCII letters.
/// Non-ASCII bytes must match exactly; the function returns `false` on mismatch and does not allocate.
pub const eqlIgnoreCase = strings.eqlIgnoreCase;
/// Re-export of `strings.containsIgnoreCase` for ASCII case-insensitive substring checks.
/// Returns `true` when `needle` appears anywhere in `haystack`; an empty `needle` always matches.
/// The comparison is bytewise for non-ASCII input and does not allocate or return errors.
pub const containsIgnoreCase = strings.containsIgnoreCase;

test {
    _ = @import("header_map.zig");
    _ = @import("types.zig");
    _ = @import("errors.zig");
    _ = @import("config.zig");
    _ = @import("context.zig");
    _ = @import("log.zig");
    _ = @import("hooks.zig");
    _ = @import("time.zig");
    _ = @import("span_handle.zig");
    _ = @import("strings.zig");
    _ = @import("posix_compat.zig");
}
