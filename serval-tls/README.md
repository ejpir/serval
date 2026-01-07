# serval-tls

TLS termination (client-side) and origination (upstream-side) using BoringSSL.

## Purpose

Provides TLS support for both incoming client connections (termination) and outgoing upstream connections (origination). Handles handshakes, encryption/decryption, and certificate validation. Phase 1 uses userspace crypto; kTLS kernel offload deferred to Phase 2.

## Layer

**Layer 1 - Protocol**

No business logic, only protocol implementation. Sits alongside serval-http and serval-net.

## Status

**Phase 1 - In Progress**

- Userspace-only TLS (no kTLS yet)
- Socket BIO approach (not Memory BIO)
- Non-blocking handshakes via io_uring poll
- Manual BoringSSL bindings (avoids @cImport macro issues)

## Exports

- `ssl` - BoringSSL bindings module
  - `SSL_CTX`, `SSL` opaque types
  - `init()`, `createClientCtx()`, `createServerCtx()`
  - Low-level BoringSSL function bindings
  - Error handling utilities

- `TlsStream` - Unified TLS stream interface (Task 3)
  - `initServer()` - Server-side TLS termination
  - `initClient()` - Client-side TLS origination
  - `read()` - Non-blocking TLS read
  - `write()` - Non-blocking TLS write
  - `close()` - Graceful TLS shutdown

## Dependencies

**External:**
- BoringSSL (system-installed libssl + libcrypto)
- Requires `link_libc = true` in build.zig

**Internal:**
- None (Layer 1 module - no serval dependencies)

## Features

### Phase 1 (Current)
- [x] Manual BoringSSL bindings (ssl.zig)
- [ ] TLS handshake (async via io_uring poll)
- [ ] Server certificate loading
- [ ] Client SNI support
- [ ] Upstream certificate verification
- [ ] Non-blocking read/write
- [ ] Graceful shutdown (close_notify)

### Phase 2 (Future)
- [ ] kTLS kernel offload
- [ ] Session resumption
- [ ] ALPN negotiation (for HTTP/2)
- [ ] Certificate reload without restart
- [ ] OCSP stapling

## Configuration

Configuration lives in serval-core (`TlsConfig`):

```zig
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
```

Per-upstream TLS flag in `Upstream` struct:

```zig
pub const Upstream = struct {
    host: []const u8,
    port: u16,
    idx: u32,
    tls: bool = false,  // Enable TLS to this backend
};
```

## Architecture Decisions

### Socket BIO (Not Memory BIO)

**Decision:** Use `SSL_set_fd()` with non-blocking socket, not Memory BIO.

**Rationale:**
- Memory BIOs incompatible with proactor-style I/O (io_uring)
- Socket BIO simpler - BoringSSL does I/O internally
- Poll readiness with io_uring, let SSL_do_handshake() do actual read/write
- Validated in POC (experiments/tls-poc/)

### Manual Bindings (Not @cImport)

**Decision:** Explicit `extern fn` declarations, not `@cImport("openssl/ssl.h")`.

**Rationale:**
- BoringSSL macros cause @cImport issues
- More control over exposed API surface
- Easier to maintain and understand
- POC confirmed this approach works

### Userspace First (kTLS Later)

**Decision:** Phase 1 uses userspace crypto; defer kTLS to Phase 2.

**Rationale:**
- Get working TLS support deployed faster
- kTLS optimization can be added transparently later
- TlsStream abstraction hides implementation (userspace vs kTLS)
- Avoid complexity of key extraction and kernel interaction initially

## Integration Points

| Module | Change |
|--------|--------|
| serval-core | Add `TlsConfig`, extend `Upstream.tls` field |
| serval-server | Wrap accepted sockets with `TlsStream` if cert configured |
| serval-proxy | Wrap upstream connections with `TlsStream` if `upstream.tls` |
| serval-pool | `Connection` holds `TlsStream` instead of raw fd |

Handlers remain unchanged - TLS is transparent at the strategy layer.

## Error Types

```zig
pub const TlsError = error{
    HandshakeTimeout,
    HandshakeFailed,
    CertificateInvalid,
    CertificateExpired,
    HostnameMismatch,
    ProtocolError,
    NoTlsMethod,
    SslCtxNew,
    SslNew,
    SslSetFd,
    SslSetSni,
    SslRead,
    SslWrite,
};
```

## Testing Strategy

### Unit Tests
```bash
zig build test-tls          # Test ssl.zig bindings
```

### Integration Tests
```bash
zig build test-tls-integ    # Requires test certs in /tmp/test-certs/
```

## TigerStyle Compliance

- **S1 (Preconditions):** Assert fd > 0, ssl != null in init functions
- **S2 (Postconditions):** Assert handshake completed after doHandshake()
- **S3 (Bounded loops):** Handshake timeout prevents infinite loops
- **S4 (Error handling):** All errors propagated explicitly, no catch {}
- **P1 (Non-blocking I/O):** io_uring poll for readiness, not blocking read
- **C1 (Function size):** All functions < 70 lines
- **C2 (Units in names):** timeout_ns, handshake_timeout_ns
- **C5 (Explicit types):** c_int, u64, no usize except slice indexing

## Implementation Status

| Component | Status | File | Task |
|-----------|--------|------|------|
| BoringSSL bindings | Complete | ssl.zig | Task 1 |
| TlsStream struct | Placeholder | stream.zig | Task 3 |
| Async handshake | Not started | stream.zig | Task 3 |
| Non-blocking I/O | Not started | stream.zig | Task 3 |
| Certificate loading | Not started | stream.zig | Task 3 |
| Config types | Not started | serval-core | Task 4 |

## Build Integration

Module linked in build.zig:
- Links libssl and libcrypto (system-installed)
- Requires `link_libc = true`
- No other dependencies

## Observability

LogEntry will track TLS mode:
```zig
tls_mode: enum { none, userspace, ktls }
```

## Prerequisites

- System-installed BoringSSL or OpenSSL 3.x
- Development headers (libssl-dev on Debian/Ubuntu)
- For Phase 2 kTLS: Linux kernel with `tls` module (`modprobe tls`)

## Design References

- **POC:** experiments/tls-poc/ (validated approach)
- **Design doc:** docs/plans/2026-01-07-tls-design.md
- **Pingora:** pingora-boringssl/src/ (async patterns)
- **secsock:** ~/repos/secsock/src/bearssl/ (BearSSL patterns applicable to BoringSSL)
