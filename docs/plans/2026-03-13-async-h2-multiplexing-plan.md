# Async H2 Multiplexing & Fiber I/O Plan

## Cascade Fallback Problem

Both gRPC and WebSocket suffer the same cascade of fallbacks:

```
NetBird client connects via ALPN h2

  gRPC path:  /signalexchange.SignalExchange/* → h2c://signal:10000
  ─────────── DEADLOCKS (h2 half-duplex, Problem 1)
       ↓ fallback
  gRPC-Web/WebSocket path:  /ws-proxy/signal → http://signal:80
  ─────────── NO RFC 8441 (Problem 2) → can't upgrade over h2
       ↓ fallback  
  gRPC-Web/WebSocket over h1 (downgrade ALPN)
  ─────────── WORKS but worst path (h1 tunnel with poll, Problem 3)
```

Same for management (`ManagementService.Sync` = server-streaming).

With all fixes:
- **Group A**: gRPC over h2 works natively → no fallback needed
- **Group C**: WebSocket over h2 works (RFC 8441) → fallback path also works on h2
- **Group B**: Even the h1 WebSocket tunnel is clean (fibers, no poll)

## Problems

### Problem 1: H2 Half-Duplex Deadlock (gRPC Streaming)

The h2 server frame loop in `serval-server/h2/server.zig` uses **blocking I/O** 
(`posix.read()` / `SSL_read()`) for both downstream reads and upstream reads.
For streaming gRPC RPCs (server-streaming, bidirectional), this creates a 
**half-duplex deadlock**:

1. The frame loop blocks in `ensureFrame()` → `readSome()` → `SSL_read()` 
   waiting for downstream client frames
2. Meanwhile, the upstream h2c backend has response data ready but nobody reads it
3. The client sends PING frames that go unread → times out after ~60s → reconnects
4. Management `Sync` (server-streaming) and Signal `ConnectStream` (bidirectional) 
   both hit this pattern

NetBird route:
- `/signalexchange.SignalExchange/*` → `h2c://signal:10000` (native gRPC)
- `/management.ManagementService/*` → `h2c://management:80` (native gRPC)

**Current workaround**: Poll-based multiplexing (`pollBothFds`) added as a 
quick fix. Works partially but:
- Not idiomatic Zig — uses raw `poll(2)` instead of `std.Io`
- TLS complication: `poll()` watches the raw fd, not SSL internal buffers
- Fragile pump/idle/complete state machine in the frame loop

### Problem 2: WebSocket/gRPC-Web Falls Back to H1.1 on H2 Connections

When ALPN negotiates `h2`, WebSocket upgrade requests can't use the traditional
HTTP/1.1 `Upgrade: websocket` mechanism. Currently serval has no 
WebSocket-over-h2 support (RFC 8441 Extended CONNECT), so WebSocket is forced
to fall back to h1.1. This is wrong — if the client negotiated h2, WebSocket 
should work natively over h2 streams.

NetBird falls back to these routes when native gRPC fails:
- `/ws-proxy/signal` → `http://signal:80` (gRPC-Web over WebSocket)
- `/ws-proxy/management` → `http://management:80` (gRPC-Web over WebSocket)

RFC 8441 defines:
1. Server sends `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x8) = 1 in SETTINGS
2. Client sends Extended CONNECT with `:protocol` pseudo-header = `websocket`
3. Server responds with 200 OK on the stream
4. The h2 stream carries bidirectional WebSocket frames

This requires the same bidirectional streaming capability as gRPC — the h2 
server must read from both downstream (WebSocket frames from client) and 
upstream (WebSocket frames from backend) concurrently.

### Problem 3: Tunnel Relay Uses poll(2)

The WebSocket tunnel (`serval-proxy/tunnel.zig`) uses raw `poll(2)` for 
bidirectional byte relay between client and upstream sockets. This is the 
last-resort path for gRPC-Web/WebSocket when h2 isn't available. Should use
`std.Io` fibers instead:
- Two reader fibers (client→upstream, upstream→client) via `Group.async()`
- Yields naturally during I/O waits
- Consistent with the rest of the Io-based architecture

## Solution: Fiber-based async I/O via `std.Io`

### Architecture

Adopt the same pattern as zig-loadbalancer's h2 client:
- **Fibers** (cooperative coroutines via `std.Io`) instead of threads or poll
- **Reader task** spawned via `Group.async()` for upstream reading
- **`Io.Mutex`/`Io.Condition`** for synchronization between fibers
- I/O operations yield the fiber via io_uring, allowing other fibers to run

### Key Insight: SSL_read + Non-blocking fd + Io Yield

Serval uses OpenSSL (`SSL_read`/`SSL_write`), not Zig's native TLS.
OpenSSL does its own `read()` syscall internally. To make it Io-cooperative:

1. Set the downstream fd to `O_NONBLOCK`
2. `SSL_read()` returns `SSL_ERROR_WANT_READ` when fd has no data
3. Use `socket.receiveTimeout(io, peek_buf, timeout)` with **peek flag** to 
   yield the fiber until the fd is readable (peek doesn't consume data)
4. When fd is readable, retry `SSL_read()` which now succeeds
5. Meanwhile, the upstream reader fiber runs during the yield

For plain TCP connections (h2c), use `Io.net.Stream.reader()` directly — 
it yields via io_uring `RECVMSG`.

### Why Not Threads

- SSL object is not safe for concurrent `SSL_read` + `SSL_write` without careful
  locking (OpenSSL 1.1.0+ allows it from different threads, but adds mutex overhead)
- Thread creation overhead per connection
- Zig's `std.Io` provides fibers (lightweight, zero allocation, single-threaded 
  cooperative scheduling) — the right abstraction

### Why Not poll(2) (Current Approach)

- Doesn't integrate with `std.Io` event loop
- `poll()` watches raw fd, misses data in SSL internal buffers
- Complex state machine (pump iterations, idle detection)
- Not composable with other Io async patterns

## Changes Required

### Phase 1: Pass `Io` Through the H2 Server

**Files**: `serval-server/h2/server.zig`, `serval-server/frontend/generic_h2.zig`,
`serval-server/h1/server.zig`

The h2 server currently has no access to `Io`. All callers have `Io` available
but don't pass it through.

1. Add `io: Io` parameter to all h2 server entry points:
   - `servePlainConnection` → `servePlainConnection(..., io: Io)`
   - `serveTlsConnection` → `serveTlsConnection(..., io: Io)`
   - `servePlainConnectionWithInitialBytes` → add `io: Io`
   - `serveTlsConnectionWithInitialBytes` → add `io: Io`
   - `servePlainConnectionWithInitialBytesOptions` → add `io: Io`
   - `serveTlsConnectionWithInitialBytesOptions` → add `io: Io`
   - `serveConnectionWithInitialBytesOptions` → add `io: Io`

2. Store `io: Io` in `ConnectionIo` (or pass alongside it):
   ```zig
   const ConnectionIo = union(enum) {
       plain_fd: i32,
       tls_stream: *TLSStream,
   };
   ```
   Option A: Add `io` field to the union (changes semantics).
   Option B: Pass `io` as separate parameter to `readSome`/`writeAll`.
   **Decision: Option B** — cleaner, ConnectionIo stays a simple I/O target.

3. Update all callers:
   - `tryServeTlsAlpnConnection` in `generic_h2.zig` — already has `io: Io`
   - `tryHandleTerminatedH2TlsAlpn` in `h1/server.zig` — needs to receive `io`
   - `tryHandleTerminatedH2PriorKnowledge` in `h1/server.zig` — needs `io`
   - gRPC h2c upgrade paths in `h1/server.zig` — already have `io`

### Phase 2: Io-Aware Reads in the H2 Server

**Files**: `serval-server/h2/server.zig`

Replace blocking `readSome()` with Io-yielding reads:

```zig
fn readSome(io_conn: *ConnectionIo, io: Io, out: []u8) Error!usize {
    switch (io_conn.*) {
        .plain_fd => |fd| {
            // Io-aware: use Stream reader which yields via io_uring
            const stream = Io.net.Stream{ .socket = .{
                .handle = fd,
                .address = .{ .ip4 = .unspecified(0) },
            }};
            var read_buf: [1]u8 = undefined; 
            var reader = stream.reader(io, &read_buf);
            var bufs: [1][]u8 = .{out};
            const n = reader.interface.readVec(&bufs) catch |err| {
                // Map errors
                return error.ReadFailed;
            };
            if (n == 0) return error.ConnectionClosed;
            return n;
        },
        .tls_stream => |tls_stream| {
            // Non-blocking SSL_read with Io yield on WANT_READ
            return readTlsWithIoYield(tls_stream, io, out);
        },
    }
}

fn readTlsWithIoYield(tls_stream: *TLSStream, io: Io, out: []u8) Error!usize {
    // Check SSL pending first — may have buffered decrypted data
    if (tls_stream.hasPendingRead()) {
        return tls_stream.read(out) catch return error.ReadFailed;
    }
    
    var retries: u32 = 0;
    while (retries < max_tls_read_retries) : (retries += 1) {
        const n = tls_stream.read(out) catch |err| switch (err) {
            error.WouldBlock => {
                // Yield fiber until fd is readable
                yieldUntilReadable(tls_stream.fd, io) catch return error.ReadFailed;
                continue;
            },
            error.ConnectionReset => return error.ConnectionClosed,
            else => return error.ReadFailed,
        };
        return @intCast(n);
    }
    return error.ReadFailed;
}

fn yieldUntilReadable(fd: i32, io: Io) !void {
    // Use Io.net.Stream reader with a 1-byte peek-style read
    // to yield the fiber until the fd has data.
    // The io_uring RECVMSG op will complete when data arrives.
    const stream = Io.net.Stream{ .socket = .{
        .handle = fd,
        .address = .{ .ip4 = .unspecified(0) },
    }};
    var peek_buf: [1]u8 = undefined;
    // receiveManyTimeout with peek flag — waits for data without consuming
    var msg: [1]Io.net.IncomingMessage = .{Io.net.IncomingMessage.init};
    _ = stream.socket.receiveManyTimeout(
        io, &msg, &peek_buf,
        .{ .peek = true },
        .none, // no timeout — wait indefinitely
    );
}
```

**Note**: The fd must be set to `O_NONBLOCK` before entering the h2 loop.
`SSL_read` on a non-blocking fd returns `SSL_ERROR_WANT_READ` instead of blocking.

### Phase 3: Io-Aware Writes in the H2 Server

**Files**: `serval-server/h2/server.zig`

Replace blocking `writeAll()` with Io-yielding writes:

```zig
fn writeAll(io_conn: *ConnectionIo, io: Io, data: []const u8) Error!void {
    switch (io_conn.*) {
        .plain_fd => |fd| {
            const stream = Io.net.Stream{ .socket = .{
                .handle = fd,
                .address = .{ .ip4 = .unspecified(0) },
            }};
            var write_buf: [16384]u8 = undefined;
            var writer = stream.writer(io, &write_buf);
            writer.interface.writeAll(data) catch return error.WriteFailed;
            writer.interface.flush() catch return error.WriteFailed;
        },
        .tls_stream => |tls_stream| {
            // SSL_write with yield on WANT_WRITE
            writeTlsWithIoYield(tls_stream, io, data) catch return error.WriteFailed;
        },
    }
}
```

### Phase 4: Set fd Non-blocking Before H2 Loop

**Files**: `serval-server/h2/server.zig`

At the start of `serveConnectionWithInitialBytesOptions`, set the downstream 
fd to non-blocking:

```zig
// Set fd non-blocking for Io-cooperative SSL_read/SSL_write
const fd = connectionIoFd(io_conn);
const flags = std.posix.fcntl(fd, .GETFL);
_ = std.posix.fcntl(fd, .SETFL, flags | O.NONBLOCK);
```

**Important**: This does NOT affect the h1 path. The h2 entry points set 
non-blocking; h1 never touches this. If ALPN dispatches to h2, the fd is 
already non-blocking. If it stays h1, the fd remains blocking.

### Phase 5: Remove Poll-Based Pump Mechanism

**Files**: `serval-server/h2/server.zig`, `serval-server/h1/server.zig`

Remove the current poll-based workaround:
- Remove `PumpResult` enum
- Remove `connectionIoHasData()`, `pollFdReadable()`, `pollBothFds()` helpers
- Remove the pump section from the frame loop
- Remove `getUpstreamPollFd()` and `handleH2Pump()` from `GrpcH2cBridgeHandler`
- Remove `dispatchPumpAction()` helper
- Remove `H2_BRIDGE_PUMP_POLL_TIMEOUT_MS` and `H2_BRIDGE_MAX_PUMP_ITERATIONS`
  from `serval-core/config.zig`

### Phase 6: Upstream Reader Fiber

**Files**: `serval-server/h1/server.zig` (GrpcH2cBridgeHandler), 
`serval-server/frontend/generic_h2.zig`

The upstream reader is spawned as a fiber that continuously reads from the 
upstream h2c connection and writes responses to the downstream h2 connection.

```zig
// In GrpcH2cBridgeHandler:
io: Io,
write_mutex: Io.Mutex = .init,
response_condition: Io.Condition = .init,
upstream_reader_group: Io.Group = .init,
pending_responses: RingBuffer, // Fixed-size queue of ReceiveActions

fn startUpstreamReader(self: *@This()) void {
    self.upstream_reader_group.async(self.io, upstreamReaderTask, .{self});
}

fn upstreamReaderTask(self: *@This()) Io.Cancelable!void {
    while (self.bridge.activeBindingCount() > 0) {
        // This read yields the fiber via Io when no upstream data available
        const action = self.bridge.receiveForDownstream(...) catch |err| {
            // Signal error to main task
            return;
        };
        
        // Queue the response
        self.write_mutex.lock(self.io);
        defer self.write_mutex.unlock(self.io);
        self.pending_responses.push(action);
        self.response_condition.signal(self.io);
    }
}
```

**Alternative (simpler)**: Instead of a separate reader fiber, make the h2 
server frame loop itself cooperative. Since `readSome` now yields, the upstream 
reads in `receiveForDownstream` also need to yield. The bridge's upstream 
connection (`ClientConnection`) uses `readSome` which does `posix.read()` or 
`socket.read()`. These need the same Io-yield treatment.

**Chosen approach**: The **simpler alternative**. Instead of spawning a separate 
reader fiber, thread `Io` through to the client-side h2 reads too. Then the 
frame loop naturally alternates:
1. Try to read downstream frame (yields if no data → upstream reader runs)
2. But wait — only one fiber is running (the frame loop). We need TWO 
   concurrent readers.

**Revised approach**: We DO need a separate fiber for upstream reading. The 
frame loop handles downstream; an async reader fiber handles upstream. They 
communicate via a shared response queue + Io.Condition.

### Phase 7: Thread Io Through Client H2 Connection

**Files**: `serval-client/h2/connection.zig`, `serval-client/h2/session.zig`

The upstream h2c client connection also uses blocking reads. For the upstream 
reader fiber to yield properly, these reads must go through `Io` too.

1. Add `io: Io` to `ClientConnection.readIntoBuffer()` / `readSome()`
2. Use `Io.net.Stream.reader()` for plain TCP upstream reads
3. The upstream connection is always plain TCP (h2c), so no SSL complexity

### Phase 8: Upstream Reader Fiber Integration

**Files**: `serval-server/h1/server.zig` (GrpcH2cBridgeHandler),
`serval-server/h2/server.zig`

The h2 server frame loop needs a way to check for pending upstream responses 
between frame reads, without blocking. Design:

1. **Handler hook**: `handlePendingResponses(writer: *ResponseWriter) bool`
   - Called by the frame loop after each downstream frame
   - Returns true if there are responses to flush
   - The handler checks its shared queue (populated by upstream reader fiber)

2. **Timeout on downstream reads**: Instead of blocking indefinitely in 
   `readSome`, use a timeout. If timeout expires, check for pending upstream 
   responses, then resume reading.

3. **Better**: Use `Io.Group` to run both tasks concurrently:
   ```zig
   var group: Io.Group = .init;
   defer group.cancel(io);
   
   // Downstream frame reader fiber
   group.async(io, downstreamFrameLoop, .{...});
   
   // Upstream response reader fiber  
   group.async(io, upstreamReaderLoop, .{...});
   
   // Wait for either to complete (connection close or error)
   group.await(io);
   ```
   
   Both fibers share the downstream `ConnectionIo` write path, protected by 
   an `Io.Mutex` (cooperative, no OS overhead). The downstream fiber reads 
   frames and dispatches (PING ACK, SETTINGS ACK, handler callbacks). The 
   upstream fiber reads responses and writes them downstream.

### Phase 9: Fiber-Based Tunnel Relay

**Files**: `serval-proxy/tunnel.zig`

Replace the `poll(2)` loop in `relayWithConfig` with two fibers:

```zig
pub fn relayWithIo(
    io: Io,
    client_socket: *Socket,
    upstream_socket: *Socket,
    initial_client_to_upstream: []const u8,
    initial_upstream_to_client: []const u8,
    idle_timeout_ns: u64,
) TunnelStats {
    var stats = TunnelStats{};
    var group: Io.Group = .init;
    defer group.cancel(io);
    
    // Fiber 1: client → upstream
    group.async(io, clientToUpstreamRelay, .{
        io, client_socket, upstream_socket, 
        initial_client_to_upstream, &stats, idle_timeout_ns,
    });
    
    // Fiber 2: upstream → client
    group.async(io, upstreamToClientRelay, .{
        io, upstream_socket, client_socket,
        initial_upstream_to_client, &stats, idle_timeout_ns,
    });
    
    // Wait for both to complete (one side closes → cancel other)
    group.await(io);
    return stats;
}

fn clientToUpstreamRelay(io: Io, src: *Socket, dst: *Socket, ...) Io.Cancelable!void {
    // Yield-aware read from src, write to dst
    // Uses Io.net.Stream.reader() for plain TCP
    // Uses readTlsWithIoYield() for TLS
}
```

This requires:
1. Add `io: Io` parameter to `relay()` and `relayWithConfig()`
2. Thread `Io` through `Socket.read()` / `Socket.write()` (or create 
   Io-aware wrappers)
3. Update callers in `serval-proxy/forwarder.zig`
4. Remove `pollAndTransfer()`, `wantsRead()`, `wantsWrite()` helpers

### Phase 10: WebSocket-over-H2 (RFC 8441 Extended CONNECT)

**Files**: `serval-h2/settings.zig`, `serval-h2/request.zig`, 
`serval-server/h2/server.zig`, `serval-server/frontend/generic_h2.zig`

Add support for WebSocket over h2 streams:

1. **Settings**: Add `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x8) to `SettingId`
   enum and include it in server's initial SETTINGS frame.

2. **Request parsing**: The h2 request parser already handles CONNECT method
   (`serval-h2/request.zig:277`). Extend it to accept `:protocol` 
   pseudo-header for Extended CONNECT (currently rejects `:path` and 
   `:scheme` on CONNECT — Extended CONNECT REQUIRES them).

3. **H2 server dispatch**: When receiving an Extended CONNECT with 
   `:protocol = websocket`:
   - Validate the request (origin, path, etc.)
   - Open upstream WebSocket connection (h1.1 Upgrade to backend)
   - Respond with 200 OK on the h2 stream
   - Enter bidirectional relay on the stream using the fiber infrastructure

4. **Bidirectional relay on h2 stream**: This reuses the same fiber-based
   upstream reader pattern from Phase 6/8. The upstream reader fiber reads 
   WebSocket frames from the backend and writes them as h2 DATA frames on 
   the stream. The downstream frame loop reads h2 DATA frames from the 
   client and forwards them as WebSocket frames to the backend.

**Note**: This is the largest phase and depends on Phases 1-8 being complete.
The h2 multiplexing infrastructure (fibers, Io-aware reads/writes, concurrent
upstream reader) is the prerequisite.

## Impact on H1

### No changes needed for h1 reads

The h1 server's `connectionRead()` function:
- For TLS: calls `TLSStream.read()` (blocking `SSL_read`)
- For plain: calls `posix.read()` with WouldBlock retry loop

The h1 path does NOT need Io-aware reads because:
1. H1 is request-response — no multiplexing needed
2. The fd is only set to `O_NONBLOCK` when entering the h2 path
3. ALPN dispatch happens BEFORE any reads, so h1 connections keep blocking fds

### No changes needed for h1 writes

The h1 server's `connectionWrite()` already uses `Io.net.Stream.writer()` for 
plain sockets (Io-aware). TLS writes use `TLSStream.write()` (blocking), which 
is fine for h1's sequential model.

### One consideration: h2c upgrade from h1

When h1 detects an `h2c` upgrade request, it switches to the h2 server:
```zig
h2_server.servePlainConnectionWithInitialBytesOptions(...)
```

At this point, the fd may still be blocking. The h2 entry point must set it 
to `O_NONBLOCK`. This is handled in Phase 4 (set non-blocking at h2 entry).

## File Change Summary

| File | Change | Phase |
|------|--------|-------|
| `serval-server/h2/server.zig` | Add `Io` param, Io-aware reads/writes, remove poll, h2 WS dispatch | 1,2,3,4,5,10 |
| `serval-server/h1/server.zig` | Pass `Io` to h2 calls, upstream reader fiber, remove pump | 1,6,8 |
| `serval-server/frontend/generic_h2.zig` | Pass `Io` to h2 calls, Extended CONNECT handling | 1,10 |
| `serval-client/h2/connection.zig` | Add `Io` param to reads | 7 |
| `serval-client/h2/session.zig` | Thread `Io` through | 7 |
| `serval-proxy/h2/bridge.zig` | Thread `Io` through receiveForDownstream | 7 |
| `serval-proxy/tunnel.zig` | Replace poll with fiber relay | 9 |
| `serval-proxy/forwarder.zig` | Pass `Io` to tunnel relay | 9 |
| `serval-h2/settings.zig` | Add `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x8) | 10 |
| `serval-h2/request.zig` | Extended CONNECT with `:protocol` pseudo-header | 10 |
| `serval-core/config.zig` | Remove pump constants | 5 |
| `serval-tls/stream.zig` | Ensure WouldBlock handling works | 2 |

## Risks and Mitigations

### Risk 1: SSL_read behavior with O_NONBLOCK

OpenSSL's `SSL_read` on a non-blocking fd may return `SSL_ERROR_WANT_READ` 
mid-record (partial TLS record received). The retry-after-yield pattern handles 
this correctly — SSL maintains internal state across calls.

**Mitigation**: Test with partial TLS records, verify SSL_pending() is checked 
before yielding.

### Risk 2: Fiber stack size

Each fiber needs stack space. The h2 server allocates large buffers on the stack 
(`recv_buf`, `frame_buf`). With a second fiber for upstream reading, total stack 
usage doubles.

**Mitigation**: Verify `std.Io` fiber stack size is sufficient. The default is 
typically 1MB which is ample.

### Risk 3: Write contention

Both fibers write to downstream. The h2 protocol requires frames to be sent 
atomically (no interleaving within a frame). `Io.Mutex` ensures this.

**Mitigation**: Lock the mutex around each complete frame write (header + 
payload), not individual `writeAll` calls.

### Risk 4: Io.net.Stream from raw fd

Creating an `Io.net.Stream` from a raw fd requires constructing a `Socket` 
with a handle. The address field is unused for reads/writes but must be valid.

**Mitigation**: Use `.{ .ip4 = .unspecified(0) }` as placeholder address.

## Implementation Order

**Group A: H2 fiber infrastructure (fixes gRPC streaming deadlock)**

1. **Phase 1**: Pass `Io` through h2 server (compile-time, no behavior change)
2. **Phase 4**: Set fd non-blocking at h2 entry
3. **Phase 2**: Io-aware reads (replaces blocking `readSome`)
4. **Phase 3**: Io-aware writes (replaces blocking `writeAll`)
5. **Phase 5**: Remove poll mechanism
6. **Phase 7**: Thread `Io` through client h2 connection
7. **Phase 6+8**: Upstream reader fiber
8. **Test**: Deploy to router, test `netbird up` with management Sync stream

**Group B: Tunnel relay fiber (cleans up h1 WebSocket path)**

9. **Phase 9**: Fiber-based tunnel relay (replaces poll in tunnel.zig)
10. **Test**: WebSocket upgrade over h1 still works

**Group C: WebSocket-over-H2 (requires Group A complete)**

11. **Phase 10**: RFC 8441 Extended CONNECT (settings, request parsing, dispatch)
12. **Test**: WebSocket works over h2 ALPN connections

Each phase builds and tests independently. Group A phases 1-4 maintain 
existing behavior (single-fiber, Io-aware I/O). Phases 5-8 add concurrent 
multiplexing. Group B is independent of Group A. Group C depends on Group A.

## H1 Server Analysis

Examined the h1 server (`serval-server/h1/server.zig`) for new Zig compatibility 
and async impact:

### Zig 0.16.0-dev.2821 Compatibility
- **No removed function usage**: h1 doesn't use `posix.close()` (the only 
  removed function) in non-test code
- `posix.read()` still exists and is used for plain socket reads
- `Io.net.Stream.writer()` already used for plain socket writes (Io-aware)
- TLS reads via `TLSStream.read()` are blocking — fine for h1's sequential model

### H1 Request/Response Path: No Changes Needed
1. **Reads**: h1 uses blocking reads (TLS: `SSL_read`, plain: `posix.read` 
   with WouldBlock retry). Correct for sequential request-response.
2. **Writes**: Plain writes already use Io-aware `stream.writer()`. TLS writes 
   use blocking `TLSStream.write()`. Fine for sequential h1.
3. **fd state**: ALPN dispatch to h2 sets `O_NONBLOCK`. If ALPN keeps h1, fd 
   stays blocking. No interaction.
4. **h2c upgrade from h1**: When h1 detects `Upgrade: h2c`, it calls 
   `h2_server.servePlainConnectionWithInitialBytesOptions()`. The h2 entry 
   point will set `O_NONBLOCK` on the fd (Phase 4). Safe because h1 
   processing is complete by then.

### H1 WebSocket Tunnel: Needs Fiber Conversion (Phase 9)
The tunnel relay (`serval-proxy/tunnel.zig`) is the one h1 code path that 
does bidirectional I/O. It currently uses `poll(2)` with a state machine 
(`RelayBuffer`, `pollAndTransfer`, `IoOutcome`). Phase 9 converts this to 
two fibers via `Group.async()`:
- Fiber 1: read from client socket, write to upstream socket
- Fiber 2: read from upstream socket, write to client socket
- Both yield during I/O waits, allowing natural bidirectional flow
- `Io` must be threaded through `relay()` → `forwardWebSocketWithConnection()`

The h1 caller (`forwarder.zig`) already has `io: Io` available.

### Test Code (separate concern)
Many test files use `posix.close()` in test blocks. These need updating 
separately but don't affect production builds. The `closeFd` helper from 
`serval-core.posix_compat` can be used.

## Verification

### Group A (H2 fiber infrastructure — fixes gRPC)
1. `zig build` — compiles
2. `zig build test` — all tests pass
3. `netbird up` connects and stays connected (no 60s reconnects)
4. Management `Sync` (server-streaming): stream stays alive indefinitely
5. Signal `ConnectStream` (bidirectional): stays alive, peer messages flow
6. Multiple concurrent h2 streams on same connection work
7. h2 PING/WINDOW_UPDATE frames answered promptly during streaming
8. h1 connections still work (ALPN http/1.1 or no ALPN)

### Group B (Tunnel relay — cleans up gRPC-Web/WebSocket fallback)
9. `/ws-proxy/signal` WebSocket upgrade works over h1
10. `/ws-proxy/management` WebSocket upgrade works over h1
11. Idle timeout still triggers correctly
12. Half-close propagation (one side closes, other drains then closes)

### Group C (WebSocket-over-H2 — gRPC-Web fallback works on h2 too)
13. `SETTINGS_ENABLE_CONNECT_PROTOCOL` advertised in server SETTINGS
14. Extended CONNECT with `:protocol=websocket` accepted
15. `/ws-proxy/signal` works when client connects via h2 ALPN (no h1 fallback)
16. `/ws-proxy/management` works when client connects via h2 ALPN
17. Bidirectional gRPC-Web/WebSocket frames flow over h2 stream

### End-to-end NetBird
18. `netbird up` → management sync → peer list → signal connect → tunnel established
19. Peer-to-peer traffic flows through WireGuard tunnel
20. No reconnection loops in logs (previously every ~60s)
