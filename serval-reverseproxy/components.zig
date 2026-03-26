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

pub const PoolKind = enum(u8) {
    simple,
    none,
};

pub const MetricsKind = enum(u8) {
    noop,
    prometheus,
};

pub const TracerKind = enum(u8) {
    noop,
    otel,
};

pub const TracerOtelConfig = struct {
    endpoint: ?[]const u8 = null,
    service_name: []const u8 = "serval-reverseproxy",
    service_version: []const u8 = "1.0.0",
    scope_name: []const u8 = "serval.reverseproxy",
    scope_version: []const u8 = "1.0.0",
};

pub const RuntimePool = struct {
    kind: PoolKind,
    simple: pool_mod.SimplePool,
    none: pool_mod.NoPool,

    pub fn init(kind: PoolKind) RuntimePool {
        return .{
            .kind = kind,
            .simple = pool_mod.SimplePool.init(),
            .none = .{},
        };
    }

    pub fn acquire(self: *RuntimePool, upstream_idx: core.config.UpstreamIndex) ?pool_mod.Connection {
        assert(@intFromPtr(self) != 0);
        return switch (self.kind) {
            .simple => self.simple.acquire(upstream_idx),
            .none => self.none.acquire(upstream_idx),
        };
    }

    pub fn release(self: *RuntimePool, upstream_idx: core.config.UpstreamIndex, conn: pool_mod.Connection, healthy: bool) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .simple => self.simple.release(upstream_idx, conn, healthy),
            .none => self.none.release(upstream_idx, conn, healthy),
        }
    }

    pub fn drain(self: *RuntimePool) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .simple => self.simple.drain(),
            .none => self.none.drain(),
        }
    }
};

pub const RuntimeMetrics = struct {
    kind: MetricsKind,
    noop: metrics_mod.NoopMetrics,
    prometheus: metrics_mod.PrometheusMetrics,

    pub fn init(kind: MetricsKind) RuntimeMetrics {
        return .{
            .kind = kind,
            .noop = .{},
            .prometheus = .{},
        };
    }

    pub fn requestStart(self: *RuntimeMetrics) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.requestStart(),
            .prometheus => self.prometheus.requestStart(),
        }
    }

    pub fn requestEnd(self: *RuntimeMetrics, status: u16, duration_ns: u64) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.requestEnd(status, duration_ns),
            .prometheus => self.prometheus.requestEnd(status, duration_ns),
        }
    }

    pub fn connectionOpened(self: *RuntimeMetrics) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.connectionOpened(),
            .prometheus => self.prometheus.connectionOpened(),
        }
    }

    pub fn connectionClosed(self: *RuntimeMetrics) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.connectionClosed(),
            .prometheus => self.prometheus.connectionClosed(),
        }
    }

    pub fn upstreamLatency(self: *RuntimeMetrics, upstream_idx: u32, duration_ns: u64) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.upstreamLatency(upstream_idx, duration_ns),
            .prometheus => self.prometheus.upstreamLatency(upstream_idx, duration_ns),
        }
    }
};

pub const RuntimeTracerInitError = error{
    MissingOtelEndpoint,
    OtelExporterInitFailed,
    OtelProcessorInitFailed,
    OtelTracerInitFailed,
};

pub const RuntimeTracer = struct {
    kind: TracerKind,
    allocator: std.mem.Allocator,

    noop: tracing_mod.NoopTracer,

    otel_exporter: ?*otel_mod.OTLPExporter,
    otel_processor: ?*otel_mod.BatchingProcessor,
    otel_tracer: ?*otel_mod.OtelTracer,

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

    pub fn startSpan(self: *RuntimeTracer, name: []const u8, parent: ?tracing_mod.SpanHandle) tracing_mod.SpanHandle {
        assert(@intFromPtr(self) != 0);
        return switch (self.kind) {
            .noop => self.noop.startSpan(name, parent),
            .otel => self.otel_tracer.?.startSpan(name, parent),
        };
    }

    pub fn endSpan(self: *RuntimeTracer, handle: tracing_mod.SpanHandle, err: ?[]const u8) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.endSpan(handle, err),
            .otel => self.otel_tracer.?.endSpan(handle, err),
        }
    }

    pub fn setStringAttribute(self: *RuntimeTracer, handle: tracing_mod.SpanHandle, key: []const u8, value: []const u8) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.setStringAttribute(handle, key, value),
            .otel => self.otel_tracer.?.setStringAttribute(handle, key, value),
        }
    }

    pub fn setIntAttribute(self: *RuntimeTracer, handle: tracing_mod.SpanHandle, key: []const u8, value: i64) void {
        assert(@intFromPtr(self) != 0);
        switch (self.kind) {
            .noop => self.noop.setIntAttribute(handle, key, value),
            .otel => self.otel_tracer.?.setIntAttribute(handle, key, value),
        }
    }

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
