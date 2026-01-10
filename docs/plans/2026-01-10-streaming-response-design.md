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

### Handler Interface

Handler declares streaming via comptime:

```zig
const MyHandler = struct {
    // Required for .stream action
    pub fn nextChunk(self: *MyHandler, ctx: *Context, buf: []u8) !?usize {
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
    var chunks_sent: u32 = 0;
    const max_chunks: u32 = config.MAX_STREAM_CHUNKS;  // TigerStyle: bounded

    while (chunks_sent < max_chunks) : (chunks_sent += 1) {
        const maybe_len = handler.nextChunk(&ctx, &response_buf) catch |err| {
            // Send error chunk and terminate
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

    // TigerStyle: if we hit max_chunks, still send final chunk
    if (chunks_sent >= max_chunks) {
        sendFinalChunk(stream);
    }
},
```

### Chunk Helpers (serval-server/h1/response.zig)

```zig
/// Send chunked transfer encoding headers.
pub fn sendStreamHeaders(stream: anytype, resp: StreamResponse) void {
    // Status line + headers + Transfer-Encoding: chunked + CRLF
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
| serval-core/config.zig | Add MAX_STREAM_CHUNKS constant |
| serval-server/h1/server.zig | Handle .stream case in action switch |
| serval-server/h1/response.zig | Add sendStreamHeaders, sendChunk, sendFinalChunk |

## TigerStyle Compliance

- **S1 Assertions**: len <= buf.len, chunks_sent bounded
- **S3 Bounded loops**: MAX_STREAM_CHUNKS limit
- **S4 No catch {}**: Error from nextChunk terminates stream cleanly
- **Caller ownership**: Server owns response_buf, handler fills it
- **Comptime checks**: Handler must have nextChunk if returning .stream
- **Explicit termination**: null return = done, max chunks = forced done

## Testing

1. Unit: StreamResponse defaults, chunk formatting
2. Integration: Handler returns .stream, verify chunked output
3. Edge: Handler errors mid-stream, max chunks reached
4. SSE example: Event stream with multiple events
