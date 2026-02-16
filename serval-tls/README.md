# serval-tls

TLS termination (client-side) and origination (upstream-side) using OpenSSL/BoringSSL.

## Purpose

Provides TLS support for both incoming client connections (termination) and outgoing upstream connections (origination). Handles handshakes, encryption/decryption, and certificate validation. Phase 1 uses userspace crypto; kTLS kernel offload deferred to Phase 2.

## Layer

**Layer 1 - Protocol**

No business logic, only protocol implementation. Sits alongside serval-http and serval-net.

## Status

**Phase 1 - Complete**
- Userspace TLS via OpenSSL/BoringSSL
- Socket BIO approach (not Memory BIO)
- Non-blocking handshakes via io_uring poll
- Manual SSL bindings (avoids @cImport macro issues)

**Phase 2 - Complete**
- kTLS kernel offload (OpenSSL native + BoringSSL manual)
- Automatic runtime detection and fallback to userspace (module missing/non-Linux/disabled)
- Zero-copy sendfile() support when kTLS active

## Exports

- `ssl` - OpenSSL/BoringSSL bindings module
  - `SSL_CTX`, `SSL` opaque types
  - `init()`, `createClientCtx()`, `createServerCtx()`
  - Low-level SSL function bindings
  - Error handling utilities

- `TLSStream` - Unified TLS stream interface
  - `initServer()` - Server-side TLS termination (accepts client connections)
  - `initClient()` - Client-side TLS origination (connects to HTTPS backends)
  - `read()` - TLS read (decrypts incoming data)
  - `write()` - TLS write (encrypts outgoing data)
  - `close()` - Graceful TLS shutdown (sends close_notify)
  - `isKtls()` - Check if kTLS kernel offload is active (zero overhead)
  - `queryKtlsStatus()` - Get detailed kTLS TX/RX status (for diagnostics)

- `ktls` - kTLS kernel offload module
  - `tryEnableKtls()` - Attempt kTLS setup after handshake (BoringSSL path)
  - `KtlsResult` - Result enum (ktls_enabled, userspace_fallback)
  - Linux kernel constants and crypto info structs

## Dependencies

**External:**
- OpenSSL 3.x or BoringSSL (system-installed libssl + libcrypto)
  - Provides TLS protocol implementation (handshakes, encryption, certificates)
  - serval-tls wraps these libraries with Zig-friendly bindings
- Requires `link_libc = true` in build.zig

**Internal:**
- None (Layer 1 module - no serval dependencies)

## Features

### Phase 1 (Complete)
- [x] Manual SSL bindings (ssl.zig)
- [x] TLS handshake (async via io_uring poll)
- [x] Server certificate loading
- [x] Client SNI support
- [x] Upstream certificate verification (optional via `verify_upstream`)
- [x] Non-blocking read/write
- [x] Graceful shutdown (close_notify)

### Phase 2 (Complete)
- [x] kTLS kernel offload (OpenSSL native via SSL_OP_ENABLE_KTLS)
- [x] kTLS manual key extraction (BoringSSL fallback path)
- [x] Automatic kTLS runtime detection and userspace fallback
- [x] HandshakeInfo.ktls_enabled status tracking
- [x] TLSStream.isKtls() / queryKtlsStatus() for runtime checks

### Phase 3 (Future)
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

### kTLS with Dual-Path Support

**Decision:** Support both OpenSSL native kTLS and manual BoringSSL key extraction.

**Rationale:**
- OpenSSL 3.x has native kTLS via `SSL_OP_ENABLE_KTLS` - handles key extraction internally
- BoringSSL requires manual key extraction via `SSL_export_keying_material`
- Automatic detection: try OpenSSL path first, fall back to manual if needed
- Transparent to users - TLSStream API unchanged, `isKtls()` for status

**kTLS Benefits:**
- Zero-copy sendfile() for encrypted data (kernel handles TLS records)
- Reduced context switches (crypto in kernel space)
- Hardware crypto offload on supported NICs

**Requirements (for kTLS offload mode):**
- Linux kernel with `tls` module (`modprobe tls`)
- OpenSSL 3.0+ for native kTLS
- Supported ciphers: AES-GCM-128, AES-GCM-256, CHACHA20-POLY1305

If any requirement is missing, TLS continues in userspace mode (no handshake failure).
For diagnostics/testing, set `SERVAL_DISABLE_KTLS=1` to force userspace mode.

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

| Component | Status | File |
|-----------|--------|------|
| SSL bindings | Complete | ssl.zig |
| TLSStream struct | Complete | stream.zig |
| Server TLS (termination) | Complete | stream.zig |
| Client TLS (origination) | Complete | stream.zig |
| Async handshake | Complete | stream.zig |
| Non-blocking I/O | Complete | stream.zig |
| Certificate loading | Complete | stream.zig |
| Certificate verification | Complete | ssl.zig |
| SNI support | Complete | stream.zig |
| Config types | Complete | serval-core |
| kTLS kernel offload | Complete | ktls.zig, stream.zig |
| kTLS OpenSSL native | Complete | stream.zig (SSL_OP_ENABLE_KTLS) |
| kTLS BoringSSL manual | Complete | ktls.zig (key extraction) |
| HandshakeInfo | Complete | handshake_info.zig |

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

- OpenSSL 3.x or BoringSSL (system-installed)
- Development headers (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on RHEL)
- For Phase 2 kTLS offload: Linux kernel with `tls` module (`modprobe tls`) (optional; userspace fallback is automatic)

## Design References

- **POC:** experiments/tls-poc/ (validated approach)
- **Design doc:** docs/plans/2026-01-07-tls-design.md
- **Pingora:** pingora-boringssl/src/ (async patterns)
- **secsock:** ~/repos/secsock/src/bearssl/ (BearSSL patterns applicable to BoringSSL)
