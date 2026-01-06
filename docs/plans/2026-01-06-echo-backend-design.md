# Echo Backend Server Design

## Overview

A simple HTTP backend using `serval-server` with a custom `EchoHandler`. Instead of forwarding requests to an upstream (like `LbHandler` does), it responds directly with request details in plain text.

**File:** `examples/echo_backend.zig`

**Purpose:** Testing the load balancer by providing backends that echo request details and identify themselves.

## Usage

```bash
# Run two backends for lb_example to forward to
zig build run-echo-backend -- --port 8001 --id backend-1
zig build run-echo-backend -- --port 8002 --id backend-2

# Then run lb_example
zig build run-lb-example -- --backends 127.0.0.1:8001,127.0.0.1:8002

# Test
curl http://localhost:8080/test
```

## EchoHandler Implementation

The handler implements the required `selectUpstream` interface but returns a sentinel value since we're not forwarding. The `onRequest` hook intercepts requests and responds directly.

```zig
const EchoHandler = struct {
    id: []const u8,
    port: u16,

    pub fn selectUpstream(self: *@This(), ctx: *Context, req: *const Request) Upstream {
        _ = self; _ = ctx; _ = req;
        // Never called - onRequest handles everything
        return .{ .host = "0.0.0.0", .port = 0, .idx = 0 };
    }

    pub fn onRequest(self: *@This(), ctx: *Context, req: *Request) Action {
        // Build and send response directly, then signal done
        sendEchoResponse(ctx, req, self.id, self.port);
        return .send_response;
    }
};
```

## Response Format

Plain text, human-readable:

```
=== Echo Backend: backend-1 (port 8001) ===
Method: GET
Path: /api/users
Headers:
  Host: 127.0.0.1:8080
  User-Agent: curl/8.0
  Accept: */*
Body: (empty)
```

HTTP response includes `X-Backend-Id` header for programmatic detection:

```
HTTP/1.1 200 OK
Content-Type: text/plain
X-Backend-Id: backend-1
Content-Length: <len>
Connection: keep-alive

<echo body>
```

## CLI Options

Reuses `serval-cli` with custom extra options:

```zig
const EchoExtra = struct {
    id: []const u8 = "echo-1",  // Instance identifier
};
```

Full options: `--port`, `--id`, `--debug`, `--help`, `--version`

## Build Integration

Add to `build.zig`:
- New executable `echo_backend` from `examples/echo_backend.zig`
- New run step `run-echo-backend`

## Implementation Steps

1. Create `examples/echo_backend.zig` with EchoHandler
2. Implement response formatting (plain text with headers/body)
3. Add build targets to `build.zig`
4. Test with lb_example
