# Streaming Response Callback

Add streaming response support for large dynamic content (SSE, LLM responses, database cursors).

## Design

### Types (serval-core/types.zig)

```zig
/// Streaming response for incrementally-generated content.
/// TigerStyle: Caller-owned buffer, bounded iterations, explicit termination.
pub const StreamResponse = struct {
    status: u16 = 200,
    content_type: []const u8 = "application/octet-stream",
    extra_headers: []const u8 = "",
};

pub const Action = union(enum) {
    continue_request,
    send_response: DirectResponse,
    reject: RejectResponse,
    stream: StreamResponse,  // NEW
};
```

### Config Constant (serval-core/config.zig)

Add after `MAX_CHUNK_ITERATIONS`:

```zig
/// Maximum chunks for streaming response callbacks.
/// TigerStyle S3: Bounded loop limit for handler-generated streams.
/// 64K chunks * 8KB buffer = 512MB max streamed response.
pub const MAX_STREAM_CHUNK_COUNT: u32 = 65536;
```

### Handler Interface

Handler declares streaming via comptime:

```zig
const MyHandler = struct {
    /// Generate next chunk of streaming response.
    /// TigerStyle: Caller-owned buffer, explicit termination.
    /// Returns: bytes written, null when done, error on failure.
    pub fn nextChunk(self: *MyHandler, ctx: *Context, buf: []u8) !?usize {
        assert(buf.len > 0);  // S1: precondition - buffer must have capacity

        // Fill buf, return bytes written
        // Return null when done
    }

    pub fn onRequest(self: *MyHandler, ctx: *Context, req: *Request, buf: []u8) !Action {
        return .{ .stream = .{ .status = 200, .content_type = "text/event-stream" } };
    }
};
```

Server checks at comptime:

```zig
if (action == .stream) {
    if (!@hasDecl(Handler, "nextChunk")) {
        @compileError("Handler returns .stream but has no nextChunk method");
    }
    // call handler.nextChunk in loop
}
```

### Server Loop (serval-server/h1/server.zig)

```zig
.stream => |stream_resp| {
    // 1. Send headers (chunked encoding)
    sendStreamHeaders(stream, stream_resp);

    // 2. Bounded streaming loop
    var chunk_count: u32 = 0;
    const max_chunk_count: u32 = config.MAX_STREAM_CHUNK_COUNT;  // TigerStyle: bounded

    while (chunk_count < max_chunk_count) : (chunk_count += 1) {
        const maybe_len = handler.nextChunk(&ctx, &response_buf) catch |err| {
            // S6: Log error before terminating stream
            log.err("streaming response failed at chunk {d}: {}", .{ chunk_count, err });
            sendFinalChunk(stream);
            break;
        };

        if (maybe_len) |len| {
            assert(len <= response_buf.len);  // S1: postcondition
            sendChunk(stream, response_buf[0..len]);
        } else {
            // null = done
            sendFinalChunk(stream);
            break;
        }
    }

    // TigerStyle: if we hit max_chunk_count, log and terminate cleanly
    if (chunk_count >= max_chunk_count) {
        log.warn("streaming response hit max chunk count: {d}", .{max_chunk_count});
        sendFinalChunk(stream);
    }
},
```

### Chunk Helpers (serval-server/h1/response.zig)

```zig
/// Send chunked transfer encoding headers.
/// RFC 7230 Section 4.1: MUST include Transfer-Encoding: chunked
/// RFC 7230 Section 3.3.2: MUST NOT include Content-Length with chunked
pub fn sendStreamHeaders(stream: anytype, resp: StreamResponse) void {
    assert(resp.status >= 100 and resp.status < 600);  // S1: valid HTTP status
    // Status line + headers + Transfer-Encoding: chunked + CRLF
    // NOTE: Do NOT send Content-Length header
}

/// Send a single chunk: length (hex) + CRLF + data + CRLF
pub fn sendChunk(stream: anytype, data: []const u8) void {
    assert(data.len > 0);  // S1: don't send empty chunks mid-stream
    // Format: "{x}\r\n{data}\r\n"
}

/// Send final chunk: "0\r\n\r\n"
pub fn sendFinalChunk(stream: anytype) void {
    // Terminates chunked response
}
```

## Files Changed

| File | Change |
|------|--------|
| serval-core/types.zig | Add StreamResponse, Action.stream |
| serval-core/config.zig | Add MAX_STREAM_CHUNK_COUNT constant |
| serval-server/h1/server.zig | Handle .stream case in action switch |
| serval-server/h1/response.zig | Add sendStreamHeaders, sendChunk, sendFinalChunk |

## RFC 7230 Compliance

Per [RFC 7230 Section 4.1](https://datatracker.ietf.org/doc/html/rfc7230#section-4.1):

| Requirement | Implementation |
|-------------|----------------|
| Chunk format: `{hex size}\r\n{data}\r\n` | sendChunk formats correctly |
| Final chunk: `0\r\n\r\n` | sendFinalChunk sends this |
| Transfer-Encoding: chunked header | sendStreamHeaders includes it |
| No Content-Length with chunked | sendStreamHeaders omits it |
| Trailers after final chunk | Not supported (v1), document as limitation |

Note: RFC 7230 is obsoleted by RFC 9112, but chunked encoding format is unchanged.

## TigerStyle Compliance

| Rule | Status | Implementation |
|------|--------|----------------|
| S1 assertions | PASS | Preconditions in nextChunk, sendChunk, sendStreamHeaders; postcondition on len |
| S2 explicit-types | PASS | chunk_count: u32, max_chunk_count: u32, status: u16 |
| S3 no-recursion | PASS | No recursive calls |
| S4 bounded-loops | PASS | MAX_STREAM_CHUNK_COUNT bounds iterations |
| S5 memory-safety | PASS | Caller-owned response_buf, no runtime allocation |
| S6 error-handling | PASS | Errors logged with context before stream termination |
| S7 no-unbounded-queues | PASS | Fixed-size buffer, bounded chunk count |
| Y3 units-in-names | PASS | MAX_STREAM_CHUNK_COUNT (count suffix) |

## Related Designs

- **BodyReader** (`docs/plans/2026-01-10-body-reader-design.md`) - Client-side chunked decoding. BodyReader reads/decodes chunked responses from upstreams; StreamResponse writes/encodes chunked responses to clients. Both use RFC 9112 chunked format but in opposite directions.

- **Shared chunked encoding** - `serval-http/chunked.zig` provides chunk size parsing. The `sendChunk`/`sendFinalChunk` helpers here could potentially move to serval-http for consistency, but are simple enough to keep inline for now.

## Testing

1. Unit: StreamResponse defaults, chunk formatting
2. Integration: Handler returns .stream, verify chunked output
3. Edge: Handler errors mid-stream (verify error logged), max chunks reached (verify warning logged)
4. SSE example: Event stream with multiple events
