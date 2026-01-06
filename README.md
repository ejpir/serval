# Serval

High-performance HTTP/1.1 reverse proxy library for Zig, following [TigerStyle](https://tigerstyle.dev/) principles.

## Features

- **Modular architecture** — Use the full server or individual components (parser, pool, forwarder)
- **Compile-time composition** — Generic interfaces verified at build time, zero runtime dispatch
- **Zero-copy forwarding** — Linux splice() for body transfer when available
- **Connection pooling** — Reuse upstream connections across requests
- **Pluggable components** — Custom handlers, metrics, and tracing implementations
- **No runtime allocation** — All memory allocated at startup

## Quick Start

```zig
const serval = @import("serval");
const serval_lb = @import("serval-lb");

const upstreams = [_]serval.Upstream{
    .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
};

var handler = serval_lb.LbHandler.init(&upstreams);
var pool = serval.SimplePool.init();
var metrics = serval.NoopMetrics{};
var tracer = serval.NoopTracer{};

var server = serval.Server(
    serval_lb.LbHandler,
    serval.SimplePool,
    serval.NoopMetrics,
    serval.NoopTracer,
).init(&handler, &pool, &metrics, &tracer, .{ .port = 8080 });

var shutdown = std.atomic.Value(bool).init(false);
try server.run(io, &shutdown);
```

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .serval = .{
        .url = "https://github.com/ejpir/serval/archive/refs/heads/main.tar.gz",
        .hash = "...", // Run: zig fetch <url>
    },
},
```

Then in `build.zig`:

```zig
const serval = b.dependency("serval", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("serval", serval.module("serval"));
exe.root_module.addImport("serval-lb", serval.module("serval-lb"));
```

## Modules

| Module | Purpose |
|--------|---------|
| `serval` | Umbrella module — re-exports everything |
| `serval-core` | Types, config, errors, context |
| `serval-http` | HTTP/1.1 request parser |
| `serval-pool` | Connection pooling |
| `serval-proxy` | Upstream forwarding |
| `serval-server` | HTTP/1.1 server |
| `serval-lb` | Load balancer handler (round-robin) |
| `serval-metrics` | Metrics interfaces |
| `serval-tracing` | Distributed tracing interfaces |
| `serval-otel` | OpenTelemetry implementation |
| `serval-cli` | CLI argument parsing |

## Handler Interface

Implement `selectUpstream` to route requests:

```zig
const MyHandler = struct {
    pub fn selectUpstream(self: *@This(), ctx: *serval.Context, req: *const serval.Request) serval.Upstream {
        // Route based on path, headers, etc.
        return self.upstreams[0];
    }

    // Optional hooks
    pub fn onRequest(self: *@This(), ctx: *serval.Context, req: *serval.Request, response_buf: []u8) serval.Action {
        _ = response_buf;
        return .continue_request;
    }

    pub fn onLog(self: *@This(), ctx: *serval.Context, entry: serval.LogEntry) void {
        std.log.info("{s} {s} -> {d}", .{ @tagName(entry.method), entry.path, entry.status });
    }
};
```

## Building

```bash
zig build              # Build lb_example
zig build test         # Run all tests
zig build run-lb-example -- --port 8080 --backends 127.0.0.1:9001,127.0.0.1:9002
```

## Documentation

- [Architecture Guide](serval/ARCHITECTURE.md) — Module structure, request flow, interfaces
- Module READMEs in each `serval-*/` directory

## Implementation Status

| Feature | Status |
|---------|--------|
| HTTP/1.1 parsing | Complete |
| Keep-alive connections | Complete |
| Upstream forwarding | Complete |
| Connection pooling | Complete |
| Zero-copy (splice) | Complete |
| Request body streaming | Complete |
| Metrics collection | Complete |
| OpenTelemetry tracing | Complete |
| HTTP/2 | Not implemented |
| TLS termination | Not implemented |
| Chunked encoding | Not implemented |

## License

MIT
