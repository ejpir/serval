# Native WebSocket Server Endpoint Design

Add **native WebSocket termination** to Serval so applications can serve WebSocket endpoints directly in Zig code, not only proxy them to upstreams.

This plan builds on `docs/plans/2026-03-09-websocket-design.md`, which implemented the first slice: **HTTP/1.1 WebSocket proxying/tunneling**.

## Goal

Support this topology:

```text
client ↔ serval-server ↔ Zig WebSocket handler
```

Today Serval supports:

```text
client ↔ serval-server ↔ serval-proxy ↔ upstream WebSocket server
```

The missing capability is native endpoint handling inside `serval-server`.

## Spec Review

Primary protocol specification:

- **RFC 6455** — The WebSocket Protocol
  - Section 4.1: Client requirements
  - Section 4.2.2: Server opening handshake
  - Section 5.2: Base framing
  - Section 5.3: Client masking
  - Section 5.4: Fragmentation
  - Section 5.5: Control frames
  - Section 7.1–7.4: Closing handshake and close codes

HTTP envelope:

- **RFC 9110 / RFC 9112** — HTTP/1.1 request parsing and upgrade semantics still apply before the protocol switch.

Deliberately **out of scope** for the first native slice:

- RFC 7692 permessage-deflate
- RFC 8441 WebSockets over HTTP/2 extended CONNECT
- WebTransport / HTTP/3

## What the spec requires Serval to do

### Opening handshake

For a valid server-side WebSocket accept path, Serval must:

- accept only `GET`
- require `Connection` to contain `Upgrade`
- require `Upgrade: websocket`
- require valid `Sec-WebSocket-Key`
- require `Sec-WebSocket-Version: 13`
- reject HTTP message-body framing on the upgrade request
- return `101 Switching Protocols`
- send `Upgrade: websocket`
- send `Connection: Upgrade`
- send `Sec-WebSocket-Accept`

Optional-but-important handshake behavior:

- may select **one** subprotocol from the client-offered `Sec-WebSocket-Protocol` list
- must not negotiate extensions it does not implement
- should fail closed on malformed upgrade attempts

### Data phase

After upgrade, Serval must enforce RFC 6455 framing invariants:

- client-to-server frames **must be masked**
- server-to-client frames **must not be masked**
- RSV1/RSV2/RSV3 must be zero unless an extension was negotiated
- control frames must be:
  - final (`FIN=1`)
  - payload length `<= 125`
  - processed even when interleaved inside fragmented messages
- continuation rules must be enforced
- unknown opcodes must fail the connection
- text messages and close reasons must be valid UTF-8
- close frames must use valid close codes

### Close behavior

Serval must:

- respond to a peer close with a close frame if it has not already sent one
- stop delivering application messages after close starts
- bound close wait time with an explicit timeout
- close the underlying connection if the peer does not complete the close handshake

## Architecture Placement

### `serval-websocket` — Layer 1 (Protocol)

Owns protocol mechanics only:

- frame header parse/encode
- masking/unmasking
- control frame validation
- close code validation
- UTF-8 validation helpers for text/close payloads
- subprotocol token parsing/validation helpers
- existing handshake helpers stay here

Non-responsibilities:

- no socket ownership
- no server session lifecycle
- no handler callbacks
- no accept loop

### `serval-server` — Layer 5 (Orchestration)

Owns native WebSocket termination:

- deciding whether a request is handled locally as WebSocket
- sending the `101` response
- handing the connection off from HTTP mode to WebSocket session mode
- session read/write loop
- handler API for receiving/sending messages
- timeout enforcement
- final logging and metrics

### `serval-proxy` — Layer 3 (Mechanics)

Unchanged responsibility:

- keeps proxy/tunnel support for upstream WebSocket servers
- remains the fallback path when a request is not handled locally

## Key Design Decision

Do **not** put WebSocket session types in `serval-core`.

`serval-core` owns shared vocabulary used across the whole stack. Native WebSocket serving needs connection ownership and HTTP-loop handoff, which belong in `serval-server`.

`serval-websocket` owns protocol primitives, not live sessions.

## Public API Proposal

The cleanest shape is a **server-specific optional hook pair**, not a new `serval-core.Action` variant.

Why this design:

- avoids pushing WebSocket session types into `serval-core`
- keeps existing HTTP handler API stable
- allows one handler to mix:
  - normal HTTP responses
  - proxied WebSocket upgrades
  - native WebSocket endpoints

### New server-side types

Planned exports from `serval-server` (and re-exported by `serval`):

```zig
pub const WebSocketRouteAction = union(enum) {
    decline,
    accept: WebSocketAccept,
    reject: types.RejectResponse,
};

pub const WebSocketAccept = struct {
    subprotocol: ?[]const u8 = null,
    extra_headers: []const u8 = "",
    max_message_size_bytes: u32 = config.WEBSOCKET_MAX_MESSAGE_SIZE_BYTES,
    idle_timeout_ns: u64 = config.WEBSOCKET_SESSION_IDLE_TIMEOUT_NS,
    auto_pong: bool = true,
};

pub const WebSocketMessageKind = enum {
    text,
    binary,
};

pub const WebSocketMessage = struct {
    kind: WebSocketMessageKind,
    payload: []const u8,
    fragmented: bool,
};
```

### New optional handler hooks

```zig
pub fn selectWebSocket(
    self: *Handler,
    ctx: *serval.Context,
    request: *const serval.Request,
) serval.WebSocketRouteAction

pub fn handleWebSocket(
    self: *Handler,
    ctx: *serval.Context,
    request: *const serval.Request,
    session: *serval.WebSocketSession,
) !void
```

Semantics:

- `selectWebSocket` is called only for requests that already passed RFC 6455 handshake validation
- `.decline` means: not a native endpoint; continue with the existing proxy/upstream path
- `.reject` means: send an HTTP rejection instead of upgrading
- `.accept` means: send `101` and enter native session handling
- if `selectWebSocket` exists, `handleWebSocket` must also exist

### Session API

First-slice public API should be **message-oriented**, not frame-oriented:

```zig
pub const WebSocketSession = struct {
    pub fn readMessage(self: *WebSocketSession, buf: []u8) !?WebSocketMessage;
    pub fn sendText(self: *WebSocketSession, payload: []const u8) !void;
    pub fn sendBinary(self: *WebSocketSession, payload: []const u8) !void;
    pub fn sendPing(self: *WebSocketSession, payload: []const u8) !void;
    pub fn close(self: *WebSocketSession, code: websocket.CloseCode, reason: []const u8) !void;
    pub fn subprotocol(self: *const WebSocketSession) ?[]const u8;
};
```

`readMessage()` behavior:

- reads one complete application message into caller-owned `buf`
- transparently reassembles fragmented data frames
- auto-handles ping/pong when `auto_pong=true`
- returns `null` when the peer has completed close
- fails closed on protocol violations and sends an appropriate close code where possible

Why message-oriented first:

- better app ergonomics for echo/chat/broadcast handlers
- keeps masking/continuation/control-frame complexity inside the library
- still zero-allocation because the caller provides the message buffer

## Example Intended Usage

```zig
const ChatHandler = struct {
    pub fn onRequest(
        self: *@This(),
        ctx: *serval.Context,
        req: *serval.Request,
        response_buf: []u8,
    ) serval.Action {
        _ = self;
        _ = ctx;
        _ = req;
        _ = response_buf;
        return .continue_request;
    }

    pub fn selectWebSocket(
        self: *@This(),
        ctx: *serval.Context,
        req: *const serval.Request,
    ) serval.WebSocketRouteAction {
        _ = self;
        _ = ctx;

        if (!std.mem.eql(u8, req.path, "/ws")) {
            return .decline;
        }

        return .{ .accept = .{
            .subprotocol = "chat",
        } };
    }

    pub fn handleWebSocket(
        self: *@This(),
        ctx: *serval.Context,
        req: *const serval.Request,
        session: *serval.WebSocketSession,
    ) !void {
        _ = self;
        _ = ctx;
        _ = req;

        var msg_buf: [4096]u8 = undefined;

        while (try session.readMessage(&msg_buf)) |msg| {
            switch (msg.kind) {
                .text => try session.sendText(msg.payload),
                .binary => try session.sendBinary(msg.payload),
            }
        }
    }
};
```

## Request Flow

### Native endpoint request

1. `serval-server` parses the HTTP/1.1 request
2. `onRequest` still runs first for auth / WAF / direct responses
3. if request looks like WebSocket, `serval-websocket.validateClientRequest()` runs
4. `selectWebSocket()` is called if the handler provides it
5. on `.accept`:
   - validate requested/selected subprotocol relationship
   - compute `Sec-WebSocket-Accept`
   - send `101 Switching Protocols`
   - stop the HTTP request loop
   - create `WebSocketSession`
   - call `handleWebSocket()`
6. when session ends:
   - close handshake completes or timeout fires
   - log final status with `101`
   - close client connection

### Declined request

If `selectWebSocket()` returns `.decline`, the request continues through the existing path:

- proxy/lb/router upstream selection
- existing WebSocket proxy path if the upstream speaks WebSocket
- or plain HTTP forwarding

This preserves the current proxy feature while adding native endpoints.

## File Plan

### New files in `serval-websocket`

| File | Responsibility |
|------|----------------|
| `serval-websocket/frame.zig` | Frame header parse/encode, opcodes, masking helpers |
| `serval-websocket/close.zig` | Close codes, close payload validation |
| `serval-websocket/subprotocol.zig` | Offered-subprotocol parsing and validation |

### New files in `serval-server`

| File | Responsibility |
|------|----------------|
| `serval-server/websocket/mod.zig` | Public server-side WebSocket exports |
| `serval-server/websocket/accept.zig` | `101` response formatting and accept handshake |
| `serval-server/websocket/session.zig` | `WebSocketSession` read/write API and state machine |
| `serval-server/websocket/io.zig` | TLS/plain connection read/write helpers for session loop |

### Modified files

| File | Change |
|------|--------|
| `build.zig` | Add new source files to module tests |
| `serval-websocket/mod.zig` | Export frame/close/subprotocol helpers |
| `serval-server/mod.zig` | Re-export native WebSocket server API |
| `serval-server/h1/server.zig` | Add native endpoint routing before proxy fallback |
| `serval/ARCHITECTURE.md` | Document native endpoint support placement |
| `serval/README.md` | Document native serving capability |
| `serval-server/README.md` | Document handler hooks and session API |
| `serval-websocket/README.md` | Expand scope to frame/close helpers |

## Protocol State Machine

### Session state

Minimal explicit state enum in `serval-server/websocket/session.zig`:

```zig
const SessionState = enum {
    open,
    close_sent,
    close_received,
    closed,
};
```

### Read path invariants

On every frame read, the session must validate:

- header fully parsed within explicit size bounds
- payload length does not exceed configured message limit
- masking key present for client frames
- control-frame invariants hold
- fragmentation state is legal

### Write path invariants

For every outbound frame:

- server frames are unmasked
- control payload length `<= 125`
- close reason UTF-8 is valid
- close code is valid for wire use

## Config Additions

Planned additions in `serval-core/config.zig`:

```zig
pub const WEBSOCKET_MAX_MESSAGE_SIZE_BYTES: u32 = 1024 * 1024;
pub const WEBSOCKET_MAX_FRAGMENTS_PER_MESSAGE: u32 = 1024;
pub const WEBSOCKET_SESSION_IDLE_TIMEOUT_NS: u64 = 60 * std.time.ns_per_s;
pub const WEBSOCKET_CLOSE_TIMEOUT_NS: u64 = 5 * std.time.ns_per_s;
pub const WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES: u32 = 125;
```

Why these exist:

- TigerStyle requires explicit bounds
- prevents memory abuse through huge fragmented messages
- prevents hanging forever in close-handshake wait

## Error Handling Policy

Fail closed with RFC-appropriate close codes where possible:

| Condition | Action |
|-----------|--------|
| invalid handshake request | HTTP error, no upgrade |
| unsupported version | HTTP `426` + `Sec-WebSocket-Version: 13` |
| unmasked client frame | close `1002` |
| unknown opcode | close `1002` |
| invalid RSV bit | close `1002` |
| fragmented control frame | close `1002` |
| control frame payload > 125 | close `1002` |
| invalid UTF-8 text payload | close `1007` |
| invalid close payload/code | close `1002` |
| message too large | close `1009` |
| internal handler error | close `1011` |
| idle timeout | close connection after bounded close attempt |

## Observability Plan

Initial behavior:

- log the handshake as HTTP `101`
- keep `duration_ns` equal to full WebSocket session lifetime
- keep `response_bytes` / `bytes_sent` / `bytes_received` as total wire bytes observed by the server

Follow-up work, not required for first slice:

- websocket-specific metrics (`messages_in`, `messages_out`, `close_code`)
- richer tracing spans around message reads/writes

## Testing Plan

### Unit tests — `serval-websocket`

1. frame header parse for 7-bit, 16-bit, and 64-bit lengths
2. mask/unmask round trip
3. reject unmasked client frame
4. reject invalid RSV bits
5. reject unknown opcodes
6. reject fragmented control frame
7. reject control payload > 125 bytes
8. close payload validation:
   - empty close payload
   - code only
   - code + UTF-8 reason
   - invalid 1-byte close payload
   - invalid close code
   - invalid UTF-8 reason
9. subprotocol selection validation:
   - chosen protocol offered by client
   - chosen protocol not offered

### Unit tests — `serval-server/websocket`

1. `101` response formatting
2. selected subprotocol included exactly once
3. session `readMessage()` reassembles fragmented text
4. control frame interleaving during fragmented message
5. auto-pong on ping
6. `sendText()` and `sendBinary()` encode correct headers
7. close handshake transitions:
   - peer first
   - server first
   - simultaneous close
8. timeout path exits bounded loop
9. message-too-large path sends `1009`

### Integration tests

1. native echo endpoint: text in → text out
2. native binary echo endpoint
3. fragmented client text message → single handler message
4. ping from client → pong from server
5. client close → graceful server close
6. server-initiated close
7. invalid unmasked frame → connection closed with protocol error
8. invalid UTF-8 text → close `1007`
9. subprotocol negotiation success
10. subprotocol negotiation rejection
11. native local endpoint on one path, proxied websocket on another path
12. TLS-terminated WebSocket endpoint
13. server does not resume HTTP parsing after local upgrade

## Phased Implementation

### Phase 2A — Minimum production-useful native serving

Deliver:

- handler hooks: `selectWebSocket`, `handleWebSocket`
- `101` handshake response generation
- message-oriented session API
- text + binary messages
- fragmentation reassembly
- ping/pong auto-handling
- close handshake
- explicit bounds and integration tests

Non-goals in 2A:

- extensions
- compression
- frame-level public API for applications
- websocket-specific metrics schema

### Phase 2B — Hardening and ergonomics

Deliver:

- subprotocol helper improvements
- richer close/error reporting to handlers
- websocket metrics / tracing fields
- stricter RFC response status behavior for handshake failures
- examples (`examples/websocket_echo.zig`)

### Phase 2C — Advanced protocol support

Future only:

- permessage-deflate
- HTTP/2 WebSockets (RFC 8441)
- sticky long-lived routing integrations if needed

## Rejected Designs

### Rejected: add `Action.websocket` to `serval-core`

Why rejected:

- leaks WebSocket-specific server semantics into the foundation layer
- forces session or accept types to live in `serval-core`
- makes the core Action union less general and more server-specific

### Rejected: put session lifecycle in `serval-websocket`

Why rejected:

- session lifecycle owns sockets and connection shutdown
- that is orchestration, not protocol
- would violate the current layering model

### Rejected: frame-oriented public API first

Why rejected:

- too low-level for the primary use case
- pushes fragmentation/control-frame handling burden onto application code
- increases likelihood of user-space protocol bugs

## Recommended Next Implementation Slice

Implement **Phase 2A** only.

That gives Serval a complete, production-useful native endpoint story for common workloads:

- chat
- command streams
- browser push channels
- bidirectional control channels
- app-local WebSocket APIs

without taking on compression or HTTP/2 complexity yet.
