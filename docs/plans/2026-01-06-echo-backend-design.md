# Echo Backend Server Design

## Overview

A simple HTTP backend using `serval-server` with a custom `EchoHandler`. Instead of forwarding requests to an upstream (like `LbHandler` does), it responds directly with request details in plain text using the new `DirectResponse` feature.

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

## DirectResponse Feature

This implementation required extending serval-server to support direct responses without forwarding:

### Action Union (serval-core/types.zig)

Changed `Action` from enum to tagged union:

```zig
pub const Action = union(enum) {
    continue_request,
    send_response: DirectResponse,
};

pub const DirectResponse = struct {
    status: u16 = 200,
    body: []const u8 = "",
    content_type: []const u8 = "text/plain",
    extra_headers: []const u8 = "",
};
```

### Updated onRequest Hook Signature

```zig
pub fn onRequest(self: *@This(), ctx: *Context, request: *Request, response_buf: []u8) Action
```

The server provides a per-connection `response_buf` (8KB) that handlers can use to format response bodies. Buffer is only allocated when handler implements `onRequest` (comptime conditional).

## EchoHandler Implementation

```zig
const EchoHandler = struct {
    id: []const u8,
    port: u16,
    debug: bool,

    pub fn selectUpstream(self: *@This(), ctx: *Context, req: *const Request) Upstream {
        // Never called - onRequest handles everything
        std.debug.assert(false);
        return .{ .host = "0.0.0.0", .port = 0, .idx = 0 };
    }

    pub fn onRequest(self: *@This(), ctx: *Context, req: *Request, response_buf: []u8) Action {
        const body_len = formatEchoBody(response_buf, req, self.id, self.port);
        return .{ .send_response = .{
            .status = 200,
            .body = response_buf[0..body_len],
            .content_type = "text/plain",
            .extra_headers = "X-Backend-Id: ...\r\n",
        } };
    }
};
```

## Response Format

Plain text, human-readable:

```
=== Echo Backend: backend-1 (port 8001) ===

Method: GET
Path: /api/users
Version: HTTP/1.1

Headers:
  Host: 127.0.0.1:8080
  User-Agent: curl/8.0
  Accept: */*

Body: (empty)
```

HTTP response includes `X-Backend-Id` header for programmatic detection.

## CLI Options

Reuses `serval-cli` with custom extra options:

```zig
const EchoExtra = struct {
    id: []const u8 = "echo-1",  // Instance identifier
};
```

Full options: `--port`, `--id`, `--debug`, `--help`, `--version`

## Build Integration

Added to `build.zig`:
- Executable `echo_backend` from `examples/echo_backend.zig`
- Build step `build-echo-backend`
- Run step `run-echo-backend`

## Files Changed

1. `serval-core/types.zig` - Action union, DirectResponse struct
2. `serval-core/config.zig` - DIRECT_RESPONSE_BUFFER_SIZE_BYTES
3. `serval-core/hooks.zig` - Updated onRequest signature
4. `serval-server/h1/response.zig` - sendDirectResponse function
5. `serval-server/h1/server.zig` - Response buffer, direct response handling
6. `examples/echo_backend.zig` - Echo backend implementation
7. `build.zig` - Build targets
8. Documentation updates
