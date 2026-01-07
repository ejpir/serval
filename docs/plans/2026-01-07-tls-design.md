# TLS Implementation Design

## Overview

Add TLS support to Serval with kTLS acceleration and BoringSSL for handshakes.

## Requirements

| Requirement | Decision |
|-------------|----------|
| Scope | Client termination + upstream origination |
| Priority | Performance (willing to accept complexity) |
| Async | Critical (non-blocking handshakes via io_uring) |
| kTLS | Preferred, with userspace fallback |
| Crypto library | BoringSSL (system-installed) |

## Architecture

### New Module: serval-tls (Layer 1 - Protocol)

```
serval-tls/
├── mod.zig          # Public exports
├── c.zig            # BoringSSL C bindings (@cImport)
├── context.zig      # SSL_CTX lifecycle (one per config)
├── session.zig      # SSL session per connection
├── handshake.zig    # Async handshake (poll + SSL_do_handshake loop)
├── stream.zig       # TlsStream unified interface
├── ktls.zig         # kTLS setup (setsockopt SO_TLS) - optional
└── ext.zig          # Extension functions (from Pingora ext.rs)
```

**Note:** No `bio.zig` — we use socket BIOs directly, not memory BIOs.

### Integration Points

| Module | Change |
|--------|--------|
| serval-core | Add `TlsConfig`, extend `Upstream.tls` field |
| serval-server | Wrap accepted sockets with `TlsStream` if cert configured |
| serval-proxy | Wrap upstream connections with `TlsStream` if `upstream.tls` |
| serval-pool | `Connection` holds `TlsStream` instead of raw `Io.net.Stream` |

Handlers remain unchanged - TLS is transparent at the strategy layer.

## Async Handshake Design

### Reference Implementations
- **secsock** (`~/repos/secsock/src/bearssl/`) — BearSSL vtable pattern with Tardy
- **Pingora** (`pingora-boringssl/src/boring_tokio.rs`) — BoringSSL async wrapper

### Approach: Socket BIO + Non-blocking fd (Pingora's way)

**Why not Memory BIO:** Memory BIOs are incompatible with proactor-style I/O (io_uring). We'd have to block waiting for completions anyway, defeating async benefits.

**Socket BIO approach:**
1. Set socket to non-blocking
2. `SSL_set_fd(ssl, fd)` — BoringSSL uses socket directly
3. `SSL_do_handshake()` returns `WANT_READ`/`WANT_WRITE`
4. Use io_uring to **poll** socket readiness (not do I/O)
5. When ready, call `SSL_do_handshake()` again
6. Repeat until handshake completes

BoringSSL does the actual I/O internally when we call it:

```
┌─────────────────────────────────────────────────────────┐
│                   TLS Handshake FSM                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. SSL_do_handshake() ──► returns SSL_ERROR_WANT_READ   │
│                                                          │
│  2. BIO_read(write_bio) ──► get encrypted bytes to send  │
│                                                          │
│  3. io_uring submit ──► send bytes to peer (async)       │
│                                                          │
│  4. io_uring complete ──► recv bytes from peer (async)   │
│                                                          │
│  5. BIO_write(read_bio) ──► feed encrypted bytes in      │
│                                                          │
│  6. Loop to step 1 until SSL_is_init_finished()          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Handshake State Machine

```zig
const HandshakeState = enum {
    start,
    want_read,      // Need to recv from peer
    want_write,     // Need to send to peer
    complete,
    failed,
};
```

Timeout: `handshake_timeout_ms` (default 10s). Fail connection if exceeded.

### Critical Initialization Order (from secsock learnings)

The order matters — getting this wrong causes subtle failures:

```zig
// 1. Create SSL_CTX (once at startup)
const ctx = SSL_CTX_new(TLS_method());
SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

// 2. Load certificates (server) or CA bundle (client)
SSL_CTX_use_certificate_chain_file(ctx, cert_path);
SSL_CTX_use_PrivateKey_file(ctx, key_path);
// or for client: SSL_CTX_load_verify_locations(ctx, ca_path)

// 3. Create SSL object per connection
const ssl = SSL_new(ctx);

// 4. Create memory BIOs (not socket BIOs - we do our own I/O)
const read_bio = BIO_new(BIO_s_mem());   // we write received data here
const write_bio = BIO_new(BIO_s_mem());  // SSL writes encrypted data here
SSL_set_bio(ssl, read_bio, write_bio);   // ownership transferred

// 5. Set SNI for client connections
SSL_set_tlsext_host_name(ssl, server_name);

// 6. Set connect state (client) or accept state (server)
SSL_set_connect_state(ssl);  // client
// or: SSL_set_accept_state(ssl);  // server

// 7. Run handshake loop (async via memory BIOs)
while (!SSL_is_init_finished(ssl)) {
    const ret = SSL_do_handshake(ssl);
    // handle SSL_ERROR_WANT_READ/WANT_WRITE
    // shuttle bytes between BIOs and io_uring
}

// 8. After handshake: attempt kTLS offload
// Extract keys, call setsockopt(SOL_TLS, ...)
```

**BearSSL → BoringSSL mapping:**

| BearSSL | BoringSSL |
|---------|-----------|
| `br_ssl_client_init_full()` | `SSL_CTX_new()` + `SSL_new()` |
| `br_x509_minimal_init_full()` | `SSL_CTX_load_verify_locations()` |
| `br_ssl_engine_set_buffer()` | `SSL_set_bio()` with memory BIOs |
| `br_ssl_client_reset(sni)` | `SSL_set_tlsext_host_name()` + `SSL_set_connect_state()` |
| `br_sslio_init(recv_cb, send_cb)` | Memory BIO + manual shuttle |
| `br_sslio_write("", 0) + flush` | `SSL_do_handshake()` loop |

## kTLS Transition

After handshake completes, attempt kTLS offload:

```
Handshake complete (SSL_is_init_finished)
           │
           ▼
┌──────────────────────────────────┐
│  Extract session keys from SSL   │
│  - cipher suite                  │
│  - encryption key + IV           │
│  - sequence number               │
└──────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────┐
│  setsockopt(SOL_TLS, TLS_TX)     │
│  setsockopt(SOL_TLS, TLS_RX)     │
└──────────────────────────────────┘
           │
           ├──► Success: Return raw fd, io_uring uses it directly
           │
           └──► Failure: Keep SSL object, use userspace encrypt/decrypt
```

### Supported kTLS Ciphers

- `TLS_CIPHER_AES_GCM_128` — most common
- `TLS_CIPHER_AES_GCM_256` — more secure
- `TLS_CIPHER_CHACHA20_POLY1305` — better on CPUs without AES-NI

### Fallback Detection

| Error | Action |
|-------|--------|
| `ENOPROTOOPT` | kTLS module not loaded, use userspace |
| `ENOENT` | Cipher not supported by kTLS, use userspace |
| Other | Fail connection (don't hide real errors) |

## TlsStream Interface

```zig
pub const TlsStream = struct {
    mode: Mode,

    const Mode = union(enum) {
        ktls: KtlsState,
        userspace: UserspaceState,
    };

    const KtlsState = struct {
        fd: std.posix.fd_t,   // Raw fd, io_uring works directly
    };

    const UserspaceState = struct {
        fd: std.posix.fd_t,   // Underlying socket
        ssl: *SSL,            // BoringSSL context
        read_bio: *BIO,       // Memory BIO for decrypted reads
        write_bio: *BIO,      // Memory BIO for encrypted writes
    };

    /// Async read - works with io_uring for both modes
    pub fn read(self: *TlsStream, io: *Io, buf: []u8) !usize;

    /// Async write - works with io_uring for both modes
    pub fn write(self: *TlsStream, io: *Io, data: []const u8) !usize;

    /// For splice() zero-copy - only valid in ktls mode
    pub fn getFd(self: *TlsStream) ?std.posix.fd_t;

    /// Graceful TLS shutdown (sends close_notify)
    pub fn close(self: *TlsStream, io: *Io) void;
};
```

### Zero-Copy Consideration

`splice()` only works with kTLS mode. In userspace mode, `getFd()` returns `null`, and serval-proxy falls back to buffered copy through BoringSSL.

## Configuration

### TlsConfig (serval-core)

```zig
pub const TlsConfig = struct {
    // Client termination (incoming connections)
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,

    // Upstream origination (outgoing connections)
    upstream_tls_enabled: bool = false,
    verify_upstream: bool = true,
    ca_path: ?[]const u8 = null,

    // Tuning
    handshake_timeout_ms: u32 = 10_000,
    session_cache_size: u32 = 1024,

    // kTLS
    prefer_ktls: bool = true,
};
```

### Per-Upstream TLS

```zig
pub const Upstream = struct {
    host: []const u8,
    port: u16,
    idx: u32,
    tls: bool = false,  // Enable TLS to this backend
};
```

## Error Types

```zig
pub const TlsError = error{
    HandshakeTimeout,
    HandshakeFailed,
    CertificateInvalid,
    CertificateExpired,
    HostnameMismatch,
    ProtocolError,
    KeyExtractionFailed,
    UnsupportedCipher,
};
```

## Build Integration

```zig
// build.zig
const tls_mod = b.addModule("serval-tls", .{
    .root_source_file = b.path("serval-tls/mod.zig"),
});
tls_mod.linkSystemLibrary("ssl");
tls_mod.linkSystemLibrary("crypto");
```

### Compile-Time Detection

```zig
pub const has_ktls = @hasDecl(std.os.linux, "TLS_TX");
```

## Testing Strategy

| Test | Method |
|------|--------|
| Handshake FSM | Unit test with mock BIOs, no real network |
| kTLS setup | Integration test, skip if module not loaded |
| Full TLS flow | Integration test against local test server |
| Certificate validation | Unit tests with test certs |
| Fallback path | Force userspace mode, verify it works |

### Build Targets

```bash
zig build test-tls          # Unit tests (no network)
zig build test-tls-integ    # Integration tests (requires certs)
```

## Pingora Patterns → Zig

### Error Mapping (from boring_tokio.rs)

```zig
// Pingora's cvt_ossl translated to Zig
fn mapSslError(err: c.SSL_get_error(...)) HandshakeResult {
    return switch (err) {
        c.SSL_ERROR_WANT_READ => .want_read,
        c.SSL_ERROR_WANT_WRITE => .want_write,
        c.SSL_ERROR_NONE => .complete,
        else => .failed,
    };
}
```

### Key BoringSSL Calls (from ext.rs)

```zig
// c.zig will expose these
extern fn SSL_CTX_new(method: *const SSL_METHOD) ?*SSL_CTX;
extern fn SSL_new(ctx: *SSL_CTX) ?*SSL;
extern fn SSL_set_fd(ssl: *SSL, fd: c_int) c_int;
extern fn SSL_set_connect_state(ssl: *SSL) void;
extern fn SSL_set_accept_state(ssl: *SSL) void;
extern fn SSL_do_handshake(ssl: *SSL) c_int;
extern fn SSL_get_error(ssl: *SSL, ret: c_int) c_int;
extern fn SSL_read(ssl: *SSL, buf: [*]u8, len: c_int) c_int;
extern fn SSL_write(ssl: *SSL, buf: [*]const u8, len: c_int) c_int;
extern fn SSL_shutdown(ssl: *SSL) c_int;
extern fn SSL_free(ssl: *SSL) void;
extern fn SSL_CTX_free(ctx: *SSL_CTX) void;

// Certificate loading
extern fn SSL_use_certificate(ssl: *SSL, cert: *X509) c_int;
extern fn SSL_use_PrivateKey(ssl: *SSL, key: *EVP_PKEY) c_int;
extern fn SSL_CTX_use_certificate_chain_file(ctx: *SSL_CTX, path: [*:0]const u8) c_int;
extern fn SSL_CTX_use_PrivateKey_file(ctx: *SSL_CTX, path: [*:0]const u8, type: c_int) c_int;
extern fn SSL_CTX_load_verify_locations(ctx: *SSL_CTX, ca_file: ?[*:0]const u8, ca_path: ?[*:0]const u8) c_int;

// SNI and verification
extern fn SSL_set_tlsext_host_name(ssl: *SSL, name: [*:0]const u8) c_int;
extern fn X509_VERIFY_PARAM_add1_host(param: *X509_VERIFY_PARAM, name: [*]const u8, len: usize) c_int;
extern fn SSL_set1_verify_cert_store(ssl: *SSL, store: *X509_STORE) c_int;

// Protocol versions
extern fn SSL_CTX_set_min_proto_version(ctx: *SSL_CTX, version: u16) c_int;
extern fn SSL_CTX_set_max_proto_version(ctx: *SSL_CTX, version: u16) c_int;
```

### Handshake Loop Pattern

```zig
pub fn doHandshake(self: *TlsSession, io: *Io) !void {
    while (true) {
        const ret = c.SSL_do_handshake(self.ssl);
        if (ret == 1) return; // Success

        const err = c.SSL_get_error(self.ssl, ret);
        switch (err) {
            c.SSL_ERROR_WANT_READ => {
                // Poll socket for readability via io_uring
                try io.pollIn(self.fd);
            },
            c.SSL_ERROR_WANT_WRITE => {
                // Poll socket for writability via io_uring
                try io.pollOut(self.fd);
            },
            else => return error.HandshakeFailed,
        }
    }
}
```

## Implementation Order

1. BoringSSL C bindings (`c.zig`) — @cImport + function declarations
2. SSL_CTX wrapper (`context.zig`) — one per config, shared across connections
3. SSL session wrapper (`session.zig`) — one per connection
4. Async handshake (`handshake.zig`) — poll + SSL_do_handshake loop
5. TlsStream interface (`stream.zig`) — read/write/close
6. Extension functions (`ext.zig`) — cert loading, SNI, verification
7. kTLS setup (`ktls.zig`) — optional optimization
8. Config types in serval-core
9. serval-server integration
10. serval-proxy integration
11. Tests

## Observability

`LogEntry` gets new field for TLS mode tracking:

```zig
tls_mode: enum { none, ktls, userspace }
```

## Prerequisites

- System-installed BoringSSL or OpenSSL 3.x
- Linux kernel with `tls` module for kTLS (`modprobe tls`)
- Kernel 6.14+ for full key rotation support (optional)

---

## POC Validation (experiments/tls-poc)

### What Works

| Component | Status | Notes |
|-----------|--------|-------|
| Manual bindings | ✅ Working | `ssl.zig` avoids @cImport macro issues |
| Socket BIO | ✅ Working | `SSL_set_fd()` simpler than Memory BIO |
| Server handshake | ✅ Working | `SSL_accept()` completes successfully |
| Client handshake | ✅ Working | `SSL_connect()` with SNI works |
| Certificate loading | ✅ Working | `SSL_CTX_use_certificate_chain_file()` |
| TLS I/O | ✅ Working | `SSL_read()` / `SSL_write()` functional |
| Error handling | ✅ Working | `ERR_get_error()` / `ERR_error_string_n()` |
| Build integration | ✅ Working | Static link `libssl.a` + `libcrypto.a` |

### Key Learnings

1. **Manual bindings > @cImport**: BoringSSL macros cause issues. Explicit `extern` declarations work better.
2. **Socket BIO simplicity**: Direct `SSL_set_fd()` avoids Memory BIO shuttle complexity.
3. **Blocking handshakes**: POC handshakes block. Need async wrapper for production.
4. **std.Io integration**: POC uses `std.Io.Threaded` — async will use `std.Io.Group`.

### POC → Production Gap Analysis

| Gap | POC State | Production Requirement |
|-----|-----------|------------------------|
| Async handshake | Blocking `SSL_accept()` | Non-blocking with io_uring poll |
| Error recovery | `continue` on error | Proper error propagation |
| Connection lifecycle | One connection then exit | Per-connection TlsSession struct |
| Resource cleanup | defer statements | Pool integration (reuse SSL_CTX) |
| kTLS offload | Not implemented | Optional post-handshake optimization |
| Config management | Hardcoded paths | TlsConfig from serval-core |
| Stream abstraction | Raw SSL calls | TlsStream interface |
| Memory allocation | GPA in main | Pass allocator to init functions |

## Async Handshake Implementation

### Problem: SSL_do_handshake() Blocks on I/O

BoringSSL's `SSL_accept()` / `SSL_connect()` internally call `read()` / `write()` on the socket BIO. With a blocking fd, this stalls the thread.

### Solution: Non-blocking fd + io_uring Poll

```zig
// 1. Set socket to non-blocking
const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
try posix.fcntl(fd, posix.F.SETFL, flags | posix.O.NONBLOCK);

// 2. Set fd in SSL
_ = c.SSL_set_fd(ssl, fd);

// 3. Handshake loop
while (true) {
    const ret = c.SSL_do_handshake(ssl);
    if (ret == 1) break; // Success

    const err = c.SSL_get_error(ssl, ret);
    switch (err) {
        c.SSL_ERROR_WANT_READ => {
            // Socket needs data from peer
            try io.pollIn(fd, timeout_ns);
        },
        c.SSL_ERROR_WANT_WRITE => {
            // Socket ready to send data to peer
            try io.pollOut(fd, timeout_ns);
        },
        c.SSL_ERROR_SYSCALL => {
            // Check errno
            return error.HandshakeSyscallError;
        },
        else => {
            c.printErrors();
            return error.HandshakeFailed;
        },
    }
}
```

**io_uring integration:**
- `io.pollIn()` → `IORING_OP_POLL_ADD` with `POLLIN`
- `io.pollOut()` → `IORING_OP_POLL_ADD` with `POLLOUT`
- Does NOT read/write — just waits for fd readiness
- BoringSSL does actual I/O when we call `SSL_do_handshake()` again

### Handshake Timeout

```zig
pub fn doHandshake(
    ssl: *SSL,
    fd: c_int,
    io: *Io,
    timeout_ns: u64,
) !void {
    const start = std.time.nanoTimestamp();

    while (true) {
        const elapsed_ns = std.time.nanoTimestamp() - start;
        if (elapsed_ns > timeout_ns) return error.HandshakeTimeout;

        const remaining_ns = timeout_ns - elapsed_ns;

        const ret = c.SSL_do_handshake(ssl);
        if (ret == 1) return; // Success

        const err = c.SSL_get_error(ssl, ret);
        switch (err) {
            c.SSL_ERROR_WANT_READ => {
                try io.pollIn(fd, remaining_ns);
            },
            c.SSL_ERROR_WANT_WRITE => {
                try io.pollOut(fd, remaining_ns);
            },
            else => return error.HandshakeFailed,
        }
    }
}
```

## TlsStream: Userspace-Only First

Defer kTLS to Phase 2. Initial implementation uses userspace crypto only.

```zig
pub const TlsStream = struct {
    fd: c_int,
    ssl: *SSL,
    allocator: Allocator,

    pub fn initServer(
        ctx: *SSL_CTX,
        fd: c_int,
        io: *Io,
        timeout_ns: u64,
        allocator: Allocator,
    ) !TlsStream {
        const ssl = c.SSL_new(ctx) orelse return error.SslNew;
        errdefer c.SSL_free(ssl);

        // Non-blocking
        const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
        try posix.fcntl(fd, posix.F.SETFL, flags | posix.O.NONBLOCK);

        if (c.SSL_set_fd(ssl, fd) != 1) return error.SslSetFd;
        c.SSL_set_accept_state(ssl);

        try doHandshake(ssl, fd, io, timeout_ns);

        return .{
            .fd = fd,
            .ssl = ssl,
            .allocator = allocator,
        };
    }

    pub fn initClient(
        ctx: *SSL_CTX,
        fd: c_int,
        io: *Io,
        sni: []const u8,
        timeout_ns: u64,
        allocator: Allocator,
    ) !TlsStream {
        const ssl = c.SSL_new(ctx) orelse return error.SslNew;
        errdefer c.SSL_free(ssl);

        // Non-blocking
        const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
        try posix.fcntl(fd, posix.F.SETFL, flags | posix.O.NONBLOCK);

        if (c.SSL_set_fd(ssl, fd) != 1) return error.SslSetFd;

        // SNI
        const sni_z = try allocator.dupeZ(u8, sni);
        defer allocator.free(sni_z);
        if (c.SSL_set_tlsext_host_name(ssl, sni_z) != 1) return error.SslSetSni;

        c.SSL_set_connect_state(ssl);

        try doHandshake(ssl, fd, io, timeout_ns);

        return .{
            .fd = fd,
            .ssl = ssl,
            .allocator = allocator,
        };
    }

    pub fn read(self: *TlsStream, io: *Io, buf: []u8, timeout_ns: u64) !usize {
        const start = std.time.nanoTimestamp();

        while (true) {
            const elapsed_ns = std.time.nanoTimestamp() - start;
            if (elapsed_ns > timeout_ns) return error.Timeout;

            const remaining_ns = timeout_ns - elapsed_ns;

            const ret = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
            if (ret > 0) return @intCast(ret);

            const err = c.SSL_get_error(self.ssl, ret);
            switch (err) {
                c.SSL_ERROR_WANT_READ => {
                    try io.pollIn(self.fd, remaining_ns);
                },
                c.SSL_ERROR_ZERO_RETURN => return 0, // Clean shutdown
                else => return error.SslRead,
            }
        }
    }

    pub fn write(self: *TlsStream, io: *Io, data: []const u8, timeout_ns: u64) !usize {
        const start = std.time.nanoTimestamp();
        var written: usize = 0;

        while (written < data.len) {
            const elapsed_ns = std.time.nanoTimestamp() - start;
            if (elapsed_ns > timeout_ns) return error.Timeout;

            const remaining_ns = timeout_ns - elapsed_ns;
            const chunk = data[written..];

            const ret = c.SSL_write(self.ssl, chunk.ptr, @intCast(chunk.len));
            if (ret > 0) {
                written += @intCast(ret);
                continue;
            }

            const err = c.SSL_get_error(self.ssl, ret);
            switch (err) {
                c.SSL_ERROR_WANT_WRITE => {
                    try io.pollOut(self.fd, remaining_ns);
                },
                else => return error.SslWrite,
            }
        }

        return written;
    }

    pub fn close(self: *TlsStream, io: *Io) void {
        // Graceful shutdown
        _ = c.SSL_shutdown(self.ssl);
        c.SSL_free(self.ssl);
        // Caller owns fd, don't close it here
    }
};
```

## Integration Steps

### 1. serval-tls Module Structure

```
serval-tls/
├── mod.zig          # pub const ssl = @import("ssl.zig");
│                    # pub const TlsStream = @import("stream.zig").TlsStream;
├── ssl.zig          # BoringSSL bindings (copy from POC)
├── stream.zig       # TlsStream implementation
└── README.md        # Module documentation
```

### 2. serval-core Changes

```zig
// config.zig
pub const TlsConfig = struct {
    // Server (client termination)
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,

    // Client (upstream origination)
    ca_path: ?[]const u8 = null,
    verify_upstream: bool = true,

    // Timeouts
    handshake_timeout_ns: u64 = 10 * std.time.ns_per_s,
    io_timeout_ns: u64 = 30 * std.time.ns_per_s,
};

// types.zig
pub const Upstream = struct {
    host: []const u8,
    port: u16,
    idx: u32,
    health: Health = .healthy,
    tls: bool = false,  // NEW: Enable TLS to this upstream
};
```

### 3. serval-server Integration

```zig
// serval-server/http1.zig - serve() function

pub fn serve(config: Config, handler: anytype, io: *Io) !void {
    // ...existing accept loop setup...

    // NEW: Initialize SSL_CTX if TLS configured
    const tls_ctx: ?*ssl.SSL_CTX = if (config.tls) |tls_cfg| blk: {
        ssl.init();
        const ctx = try ssl.createServerCtx();

        const cert_z = try allocator.dupeZ(u8, tls_cfg.cert_path.?);
        defer allocator.free(cert_z);
        const key_z = try allocator.dupeZ(u8, tls_cfg.key_path.?);
        defer allocator.free(key_z);

        if (ssl.SSL_CTX_use_certificate_chain_file(ctx, cert_z) != 1) {
            return error.LoadCertFailed;
        }
        if (ssl.SSL_CTX_use_PrivateKey_file(ctx, key_z, ssl.SSL_FILETYPE_PEM) != 1) {
            return error.LoadKeyFailed;
        }

        break :blk ctx;
    } else null;
    defer if (tls_ctx) |ctx| ssl.SSL_CTX_free(ctx);

    while (true) {
        const stream = try server.accept(io);

        // NEW: Wrap with TLS if configured
        const maybe_tls = if (tls_ctx) |ctx| blk: {
            const tls_stream = try TlsStream.initServer(
                ctx,
                @intCast(stream.socket.handle),
                io,
                config.tls.?.handshake_timeout_ns,
                allocator,
            );
            break :blk tls_stream;
        } else null;

        // Pass to handleConnection (signature changes)
        try handleConnection(stream, maybe_tls, handler, io, config);
    }
}
```

### 4. serval-proxy Integration

```zig
// serval-proxy/forwarder.zig - connectUpstream() function

pub fn connectUpstream(
    upstream: Upstream,
    io: *Io,
    config: Config,
) !Connection {
    const addr = std.Io.net.IpAddress{ .ip4 = .{
        .bytes = try resolveIp(upstream.host),
        .port = upstream.port,
    }};

    const stream = try addr.connect(io, .{ .mode = .stream });
    const fd: c_int = @intCast(stream.socket.handle);

    // NEW: Wrap with TLS if upstream requires it
    const maybe_tls = if (upstream.tls) blk: {
        const ctx = try getClientCtx(config); // Cache this globally
        const tls_stream = try TlsStream.initClient(
            ctx,
            fd,
            io,
            upstream.host,
            config.tls.?.handshake_timeout_ns,
            config.allocator,
        );
        break :blk tls_stream;
    } else null;

    return Connection{
        .stream = stream,
        .tls = maybe_tls,
        .upstream_idx = upstream.idx,
    };
}
```

## Testing Plan

### Unit Tests (serval-tls)

```bash
# Test bindings compile
zig build test-tls-bindings

# Test TlsStream with mock (no network)
zig build test-tls-stream
```

### Integration Tests

```bash
# Requires certs in /tmp/test-certs/
# Start test backend: python3 -m http.server 8080

# Test client termination
zig build test-tls-server

# Test upstream origination
zig build test-tls-client

# Full proxy flow (TLS → upstream TLS)
zig build test-tls-proxy
```

### TigerStyle Validation

Before any commit, run:

```bash
/tigerstyle
```

Check:
- S1: Preconditions (assert fd > 0, ssl != null)
- S2: Postconditions (assert handshake completed)
- S3: No unbounded loops (handshake has timeout)
- S4: Explicit error handling (no catch {})
- P1: Non-blocking I/O (io_uring poll, not blocking read)
- C1: Functions < 70 lines (split TlsStream.read if needed)
- C2: Units in names (timeout_ns, not timeout)

## Phase 1 Deliverables

- [ ] serval-tls module created
- [ ] ssl.zig bindings (from POC)
- [ ] TlsStream.initServer() (async handshake)
- [ ] TlsStream.initClient() (async handshake + SNI)
- [ ] TlsStream.read() (non-blocking)
- [ ] TlsStream.write() (non-blocking)
- [ ] TlsConfig in serval-core
- [ ] serval-server TLS termination
- [ ] serval-proxy upstream TLS
- [ ] Integration tests pass
- [ ] TigerStyle review complete

## Phase 2: kTLS Optimization (Future)

After Phase 1 is stable, add kTLS offload:

1. Extend TlsStream.Mode to union(ktls, userspace)
2. After handshake, try `setsockopt(SOL_TLS, ...)`
3. Extract keys via `SSL_export_keying_material()`
4. If successful, switch to ktls mode
5. In ktls mode, `read()`/`write()` go directly to fd (no SSL_*)
6. Metrics: track ktls success rate

## Open Questions

1. **Connection pooling:** Does serval-pool need TLS-aware state?
   - **Answer:** Yes. Pool key should include `(host, port, tls)`. Separate pools for TLS vs plain.

2. **Certificate reload:** How to reload certs without restart?
   - **Answer:** Defer to Phase 2. Create new SSL_CTX, atomic swap pointer, defer-free old one.

3. **ALPN negotiation:** Needed for HTTP/2 later?
   - **Answer:** Yes, but not in Phase 1. Add `SSL_CTX_set_alpn_protos()` when adding serval-h2.

4. **Session resumption:** Worth implementing?
   - **Answer:** Yes for performance. Use `SSL_CTX_sess_set_cache_size()`. Track via metrics.

5. **Certificate validation errors:** Return 502 or 503?
   - **Answer:** 502 Bad Gateway (upstream issue, not service unavailable).

## Success Metrics

| Metric | Target |
|--------|--------|
| Handshake latency (p50) | < 50ms |
| Handshake latency (p99) | < 200ms |
| Handshake failure rate | < 0.1% |
| CPU overhead (vs plain) | < 10% with kTLS |
| Memory per connection | < 32KB |
