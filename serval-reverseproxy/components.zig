//! Runtime-selectable binary components for reverseproxy server wiring.
//!
//! Provides facade types that satisfy Pool/Metrics/Tracer interfaces while
//! selecting concrete built-in implementations from DSL config.

const std = @import("std");
const assert = std.debug.assert;
const pool_mod = @import("serval-pool");
const metrics_mod = @import("serval-metrics");
const tracing_mod = @import("serval-tracing");
const otel_mod = @import("serval-otel");
const core = @import("serval-core");

/// Selects the runtime pool implementation.
///
/// `simple` uses the simple connection pool backend, while `none` disables pooling behavior.
/// Used by `RuntimePool.init` to choose the concrete backend.
pub const PoolKind = enum(u8) {
    simple,
    none,
};

/// Selects the runtime metrics implementation.
///
/// `noop` suppresses metrics emission, while `prometheus` enables the Prometheus-backed metrics path.
/// Used by `RuntimeMetrics.init` to choose the concrete backend.
pub const MetricsKind = enum(u8) {
    noop,
    prometheus,
};

/// Selects the runtime tracer implementation.
///
/// `noop` disables tracing work, while `otel` configures the OpenTelemetry-backed tracer path.
/// Used by `RuntimeTracer.init` to choose the concrete backend.
pub const TracerKind = enum(u8) {
    noop,
    otel,
};

/// OpenTelemetry tracer configuration used when `TracerKind.otel` is selected.
///
/// `endpoint` must be provided for OTEL initialization; the remaining fields default to the reverseproxy service and scope identifiers.
/// The string fields are borrowed slices and are not copied by this struct.
pub const TracerOtelConfig = struct {
    endpoint: ?[]const u8 = null,
    service_name: []const u8 = "serval-reverseproxy",
    service_version: []const u8 = "1.0.0",
    scope_name: []const u8 = "serval.reverseproxy",
    scope_version: []const u8 = "1.0.0",
};

/// Runtime-selected pool facade used by the reverse proxy wiring.
///
/// Stores the configured pool kind plus the concrete pool implementations needed for dispatch.
/// Call `init` to construct it, then use `acquire`, `release`, and `drain` against the chosen backend.
pub const RuntimePool = struct {
    kind: PoolKind,
    simple: pool_mod.SimplePool,
    none: pool_mod.NoPool,

    /// Creates a runtime pool facade for the requested `kind`.
    ///
    /// The returned value embeds both concrete pool implementations and selects one at call time via `kind`.
    /// This initializer does not fail and performs no heap allocation.
    pub fn init(kind: PoolKind) RuntimePool {
        return .{
            .kind = kind,
            .simple = pool_mod.SimplePool.init(),
            .none = .{},
        };
    }

    /// Acquires a connection from the selected runtime pool for `upstream_idx`.
    ///
    /// Returns `null` when the active backend cannot provide a connection at the moment.
    /// The returned connection remains owned by the caller until it is passed back to `release`.
    pub fn acquire(self: *RuntimePool, upstream_idx: core.config.UpstreamIndex) ?pool_mod.Connection {
        assert(@intFromPtr(self) != 0);
        return switch (self.kind) {
            .simple => self.simple.acquire(upstream_idx),
            .none => self.none.acquire(upstream_idx),
        };
    }

    /// Releases `conn` back to the selected runtime pool for `upstream_idx`.
    ///
    /// The `healthy` flag is forwarded to the backend so it can decide whether the connection is reusable.
    /// Requires a valid `RuntimePool` pointer and a connection that came from the same pool family.
    pub fn release(self: *RuntimePool, upstream_idx: core.config.UpstreamIndex, conn: pool_mod.Connection, healthy: bool) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .simple => self.simple.release(upstream_idx, conn, healthy),
            .none => self.none.release(upstream_idx, conn, healthy),
        }
    }

    /// Drains the selected runtime pool implementation.
    ///
    /// Requires a non-null `RuntimePool` pointer and dispatches to the backend chosen by `kind`.
    /// This does not transfer ownership of any connection state; it only asks the active pool to flush or discard its internal state.
    pub fn drain(self: *RuntimePool) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .simple => self.simple.drain(),
            .none => self.none.drain(),
        }
    }
};

/// Runtime metrics facade that dispatches to either the no-op or Prometheus implementation.
/// The selected backend is fixed by `kind`; both backend fields are embedded in the value.
/// This type does not own external resources and has no `deinit` method.
pub const RuntimeMetrics = struct {
    kind: MetricsKind,
    noop: metrics_mod.NoopMetrics,
    prometheus: metrics_mod.PrometheusMetrics,

    /// Initializes a runtime metrics facade for the requested backend.
    /// The returned value contains both backend implementations and dispatches according to `kind`.
    /// This constructor does not allocate and cannot fail.
    pub fn init(kind: MetricsKind) RuntimeMetrics {
        return .{
            .kind = kind,
            .noop = .{},
            .prometheus = .{},
        };
    }

    /// Signals the start of a request on the selected metrics backend.
    /// This is intended to be paired with `requestEnd` for the same request lifecycle.
    /// This function does not allocate and cannot fail.
    pub fn requestStart(self: *RuntimeMetrics) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.requestStart(),
            .prometheus => self.prometheus.requestStart(),
        }
    }

    /// Records the end of a request with its final HTTP status and total duration.
    /// `status` is the response status code and `duration_ns` is the elapsed time in nanoseconds.
    /// This function does not allocate and cannot fail.
    pub fn requestEnd(self: *RuntimeMetrics, status: u16, duration_ns: u64) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.requestEnd(status, duration_ns),
            .prometheus => self.prometheus.requestEnd(status, duration_ns),
        }
    }

    /// Signals that a connection has been opened.
    /// The call is dispatched to the currently selected metrics backend.
    /// This function does not allocate and cannot fail.
    pub fn connectionOpened(self: *RuntimeMetrics) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.connectionOpened(),
            .prometheus => self.prometheus.connectionOpened(),
        }
    }

    /// Signals that a connection has been closed.
    /// The call is dispatched to the currently selected metrics backend.
    /// This function does not allocate and cannot fail.
    pub fn connectionClosed(self: *RuntimeMetrics) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.connectionClosed(),
            .prometheus => self.prometheus.connectionClosed(),
        }
    }

    /// Records upstream latency for the selected backend.
    /// `upstream_idx` identifies the upstream slot being measured and `duration_ns` is the elapsed time in nanoseconds.
    /// This is a forwarding operation only; it does not allocate or return an error.
    pub fn upstreamLatency(self: *RuntimeMetrics, upstream_idx: u32, duration_ns: u64) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.upstreamLatency(upstream_idx, duration_ns),
            .prometheus => self.prometheus.upstreamLatency(upstream_idx, duration_ns),
        }
    }
};

/// Errors returned when constructing a `RuntimeTracer` with OTEL support enabled.
/// `MissingOtelEndpoint` is returned when the endpoint is absent or empty.
/// The remaining errors indicate which OTEL component failed to initialize.
pub const RuntimeTracerInitError = error{
    MissingOtelEndpoint,
    OtelExporterInitFailed,
    OtelProcessorInitFailed,
    OtelTracerInitFailed,
};

/// Runtime tracer facade that dispatches to either the no-op or OTEL implementation.
/// The selected backend is fixed by `kind`; OTEL fields are populated only when initialization succeeds.
/// Call `deinit` to release any owned OTEL resources before the value goes out of scope.
pub const RuntimeTracer = struct {
    kind: TracerKind,
    allocator: std.mem.Allocator,

    noop: tracing_mod.NoopTracer,

    otel_exporter: ?*otel_mod.OTLPExporter,
    otel_processor: ?*otel_mod.BatchingProcessor,
    otel_tracer: ?*otel_mod.OtelTracer,

    /// Initializes a runtime tracer for the requested backend.
    /// `.noop` returns an inert tracer; `.otel` requires a non-empty endpoint and creates exporter, processor, and tracer components.
    /// The returned tracer owns any OTEL resources it creates and must be released with `deinit`.
    pub fn init(kind: TracerKind, cfg: TracerOtelConfig) RuntimeTracerInitError!RuntimeTracer {
        var service = RuntimeTracer{
            .kind = kind,
            .allocator = std.heap.page_allocator,
            .noop = .{},
            .otel_exporter = null,
            .otel_processor = null,
            .otel_tracer = null,
        };

        switch (kind) {
            .noop => {},
            .otel => {
                const endpoint = cfg.endpoint orelse return error.MissingOtelEndpoint;
                if (endpoint.len == 0) return error.MissingOtelEndpoint;

                const exporter = otel_mod.OTLPExporter.init(service.allocator, .{
                    .endpoint = endpoint,
                    .service_name = cfg.service_name,
                    .service_version = cfg.service_version,
                }) catch return error.OtelExporterInitFailed;
                errdefer exporter.deinit();

                const processor = otel_mod.BatchingProcessor.init(
                    service.allocator,
                    exporter.asSpanExporter(),
                    .{},
                ) catch return error.OtelProcessorInitFailed;
                errdefer {
                    processor.shutdown();
                    processor.deinit();
                }

                const tracer = otel_mod.OtelTracer.create(
                    service.allocator,
                    processor.asSpanProcessor(),
                    cfg.scope_name,
                    cfg.scope_version,
                ) catch return error.OtelTracerInitFailed;

                service.otel_exporter = exporter;
                service.otel_processor = processor;
                service.otel_tracer = tracer;
            },
        }

        return service;
    }

    /// Releases any owned OTEL tracer, processor, and exporter resources.
    /// When `kind` is `.otel`, each component is shut down or destroyed before its field is cleared.
    /// This function is safe to call on a tracer that has already been partially torn down, and it does not return an error.
    pub fn deinit(self: *RuntimeTracer) void {
        assert(@intFromPtr(self) != 0);

        switch (self.kind) {
            .noop => {},
            .otel => {
                if (self.otel_tracer) |tracer| {
                    tracer.destroy(self.allocator);
                    self.otel_tracer = null;
                }
                if (self.otel_processor) |processor| {
                    processor.shutdown();
                    processor.deinit();
                    self.otel_processor = null;
                }
                if (self.otel_exporter) |exporter| {
                    exporter.deinit();
                    self.otel_exporter = null;
                }
            },
        }
    }

    /// Starts a new span on the active tracer implementation and returns its handle.
    /// If `parent` is provided, it is forwarded to the backend as the parent span handle.
    /// The returned handle belongs to the active tracer and should be used with the matching RuntimeTracer methods.
    pub fn startSpan(self: *RuntimeTracer, name: []const u8, parent: ?tracing_mod.SpanHandle) tracing_mod.SpanHandle {
        assert(@intFromPtr(self) != 0);
        std.log.debug("runtime tracer: startSpan kind={s} name_len={d}", .{ @tagName(self.kind), name.len });
        return switch (self.kind) {
            .noop => self.noop.startSpan(name, parent),
            .otel => self.otel_tracer.?.startSpan(name, parent),
        };
    }

    /// Ends a span on the active tracer implementation.
    /// If `err` is non-null, it is forwarded as the span's error description.
    /// This function does not allocate and cannot fail.
    pub fn endSpan(self: *RuntimeTracer, handle: tracing_mod.SpanHandle, err: ?[]const u8) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.endSpan(handle, err),
            .otel => self.otel_tracer.?.endSpan(handle, err),
        }
    }

    /// Sets a string attribute on the active span in the selected tracer backend.
    /// `key` and `value` are borrowed for the duration of the call and are forwarded unchanged.
    /// This function does not allocate and cannot fail.
    pub fn setStringAttribute(self: *RuntimeTracer, handle: tracing_mod.SpanHandle, key: []const u8, value: []const u8) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.setStringAttribute(handle, key, value),
            .otel => self.otel_tracer.?.setStringAttribute(handle, key, value),
        }
    }

    /// Sets an integer attribute on the active span in the selected tracer backend.
    /// `key` is forwarded to the backend as provided; the handle must refer to a live span.
    /// This function does not allocate and cannot fail.
    pub fn setIntAttribute(self: *RuntimeTracer, handle: tracing_mod.SpanHandle, key: []const u8, value: i64) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.setIntAttribute(handle, key, value),
            .otel => self.otel_tracer.?.setIntAttribute(handle, key, value),
        }
    }

    /// Records a span event on the active tracer implementation.
    /// The span handle must come from this tracer instance and remain valid for the duration of the call.
    /// This is a forwarding operation only; it does not allocate or return an error.
    pub fn addEvent(self: *RuntimeTracer, handle: tracing_mod.SpanHandle, name: []const u8) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.addEvent(handle, name),
            .otel => self.otel_tracer.?.addEvent(handle, name),
        }
    }
};

test "runtime component facades initialize" {
    var pool = RuntimePool.init(.simple);
    _ = &pool;

    var metrics = RuntimeMetrics.init(.prometheus);
    _ = &metrics;

    var tracer = try RuntimeTracer.init(.noop, .{});
    defer tracer.deinit();
}
