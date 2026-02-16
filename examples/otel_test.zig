//! OTLP Export Test
//!
//! Simple test to verify serval-otel can send spans to a collector.
//!
//! Usage:
//!   1. Start an OTLP collector (e.g., Jaeger):
//!      docker run -d --name jaeger \
//!        -p 4318:4318 \
//!        -p 16686:16686 \
//!        jaegertracing/all-in-one:latest
//!
//!   2. Run this test:
//!      zig build run-otel-test
//!
//!   3. View traces at http://localhost:16686

const std = @import("std");
const otel = @import("serval-otel");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== serval-otel OTLP Export Test ===\n\n", .{});

    // Create exporter
    std.debug.print("Creating OTLP exporter (endpoint: http://localhost:4318/v1/traces)...\n", .{});
    var exporter = try otel.OTLPExporter.init(allocator, .{
        .endpoint = "http://localhost:4318/v1/traces",
        .service_name = "serval-otel-test",
        .service_version = "1.0.0",
    });
    defer exporter.deinit();

    // Create a simple processor (exports immediately)
    var processor = otel.SimpleProcessor.init(exporter.asSpanExporter());

    // Create provider and tracer
    var provider = otel.TracerProvider.init(processor.asSpanProcessor());
    var tracer = provider.getTracer("otel-test", "1.0.0");

    std.debug.print("Creating test spans...\n", .{});

    // Create a parent span (simulating an incoming HTTP request)
    var request_span = tracer.startServerSpan("HTTP GET /api/users");
    request_span.setStringAttribute("http.method", "GET");
    request_span.setStringAttribute("http.url", "/api/users");
    request_span.setStringAttribute("http.host", "localhost:8080");
    request_span.setIntAttribute("http.request_content_length", 0);

    // Simulate some work
    std.Io.sleep(std.Options.debug_io, .fromNanoseconds(10_000_000), .awake) catch {};

    // Create a child span (simulating a database query)
    var db_span = tracer.startChildSpan(&request_span, "SELECT * FROM users", .Client);
    db_span.setStringAttribute("db.system", "postgresql");
    db_span.setStringAttribute("db.name", "myapp");
    db_span.setStringAttribute("db.statement", "SELECT * FROM users WHERE active = true");

    // Simulate DB query time
    std.Io.sleep(std.Options.debug_io, .fromNanoseconds(25_000_000), .awake) catch {};

    db_span.setIntAttribute("db.rows_affected", 42);
    db_span.setOk();
    tracer.endSpan(&db_span);

    // Create another child span (simulating JSON serialization)
    var serialize_span = tracer.startChildSpan(&request_span, "serialize response", .Internal);
    std.Io.sleep(std.Options.debug_io, .fromNanoseconds(2_000_000), .awake) catch {};
    serialize_span.setIntAttribute("response.size_bytes", 4096);
    serialize_span.setOk();
    tracer.endSpan(&serialize_span);

    // Complete the request span
    request_span.setIntAttribute("http.status_code", 200);
    request_span.setIntAttribute("http.response_content_length", 4096);
    request_span.setOk();
    tracer.endSpan(&request_span);

    std.debug.print("\nSpans sent! Check your collector:\n", .{});
    std.debug.print("  - Jaeger UI: http://localhost:16686\n", .{});
    std.debug.print("  - Service: serval-otel-test\n", .{});

    // Print trace ID for reference
    var trace_buf: [32]u8 = undefined;
    std.debug.print("  - Trace ID: {s}\n\n", .{request_span.span_context.trace_id.toHex(&trace_buf)});

    // Shutdown
    processor.shutdown();
    std.debug.print("Done!\n", .{});
}
