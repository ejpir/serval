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
├── c.zig            # BoringSSL C bindings
├── bio.zig          # Custom memory BIO wrapper
├── handshake.zig    # Async TLS handshake state machine
├── ktls.zig         # kTLS setup (setsockopt SO_TLS)
├── stream.zig       # TlsStream unified interface
└── config.zig       # Cert loading, cipher config
```

### Integration Points

| Module | Change |
|--------|--------|
| serval-core | Add `TlsConfig`, extend `Upstream.tls` field |
| serval-server | Wrap accepted sockets with `TlsStream` if cert configured |
| serval-proxy | Wrap upstream connections with `TlsStream` if `upstream.tls` |
| serval-pool | `Connection` holds `TlsStream` instead of raw `Io.net.Stream` |

Handlers remain unchanged - TLS is transparent at the strategy layer.

## Async Handshake Design

Reference: secsock (`~/repos/secsock/src/bearssl/`) shows the vtable pattern and initialization order working with Tardy. Same pattern applies to BoringSSL with different API calls.

BoringSSL's `SSL_do_handshake()` is blocking by default. We use memory BIOs to make it async:

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

## Implementation Order

1. BoringSSL C bindings (`c.zig`)
2. Memory BIO wrapper (`bio.zig`)
3. Async handshake FSM (`handshake.zig`)
4. kTLS setup (`ktls.zig`)
5. `TlsStream` interface (`stream.zig`)
6. Config types in serval-core
7. serval-server integration
8. serval-proxy integration
9. serval-pool integration
10. Tests

## Observability

`LogEntry` gets new field for TLS mode tracking:

```zig
tls_mode: enum { none, ktls, userspace }
```

## Prerequisites

- System-installed BoringSSL or OpenSSL 3.x
- Linux kernel with `tls` module for kTLS (`modprobe tls`)
- Kernel 6.14+ for full key rotation support (optional)
