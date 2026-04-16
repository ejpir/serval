# serval-tls

TLS termination (client-side) and origination (upstream-side) using OpenSSL/BoringSSL.

## Purpose

Provides TLS support for both incoming client connections (termination) and outgoing upstream connections (origination). Handles handshakes, encryption/decryption, and certificate validation. kTLS enablement is negotiated through OpenSSL/BoringSSL BIO support when available at runtime.

## Layer

**Layer 1 - Protocol**

No business logic, only protocol implementation. Sits alongside serval-http and serval-net.

## Status

**Phase 1 - Complete**
- Userspace TLS via OpenSSL/BoringSSL
- Socket BIO approach (not Memory BIO)
- Bounded non-blocking handshakes via fd readiness waits
- Manual SSL bindings (avoids @cImport macro issues)

**Phase 2 - Complete**
- kTLS kernel offload via OpenSSL/BoringSSL BIO path (`SSL_OP_ENABLE_KTLS`)
- Automatic runtime detection and fallback to userspace (module missing/non-Linux/disabled)
- Zero-copy sendfile() support when kTLS active

## Exports

- `ssl` - OpenSSL/BoringSSL bindings module
  - `SSL_CTX`, `SSL` opaque types
  - `init()`, `createClientCtx()`, `createServerCtx()`, `createServerCtxFromPemFiles()`
  - Low-level SSL function bindings
  - Error handling utilities
  - `SSL_pending()` binding for userspace TLS buffered-read inspection
  - Installs process-wide `SIGPIPE` ignore before OpenSSL socket-BIO use on Linux

- `TLSStream` - Unified TLS stream interface
  - `initServer()` / `initClient()` - Server/client TLS setup with default handshake + I/O timeouts from `serval-core.config.TlsConfig`
  - `initServerWithTimeouts()` / `initClientWithTimeouts()` - Server/client TLS setup with explicit handshake + I/O timeouts
  - `readStep()` - Single non-blocking TLS read step (`bytes` / `closed` / `need_read` / `need_write`)
  - `read()` - Non-blocking TLS read primitive (legacy compatibility mapping for `error.WantRead` / `error.WantWrite`)
  - `readBounded()` / `readWithTimeout()` - TLS read with stored or explicit timeout enforcement (internally step-driven)
  - `writeStep()` - Single non-blocking TLS write step (`bytes` / `closed` / `need_read` / `need_write`)
  - `write()` - Non-blocking TLS write primitive (legacy compatibility mapping for `error.WantRead` / `error.WantWrite`)
  - `writeBounded()` / `writeWithTimeout()` - TLS write with stored or explicit timeout enforcement (internally step-driven)
  - `close()` - Quiet TLS shutdown for deterministic teardown without peer-close `SIGPIPE`
  - `isKtls()` - Check if kTLS kernel offload is active (zero overhead)
  - `queryKtlsStatus()` - Get detailed kTLS TX/RX status (for diagnostics)

- `ReloadableServerCtx` - Bounded SSL_CTX generation manager
  - `init(initial_ctx)` - Start generation 1 from loaded SSL_CTX
  - `acquire()/release()` - Handshake-time lease management
  - `activate(new_ctx)` - Atomically switch active generation
  - `activateFromPemFiles(cert_path, key_path)` - Build + activate new generation from PEM paths

- `ktls` - kTLS kernel offload module
  - Runtime capability checks and Linux kTLS constants
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
- [x] TLS handshake with bounded readiness waits and explicit timeout enforcement
- [x] Server certificate loading
- [x] Client SNI support
- [x] Upstream certificate verification (optional via `verify_upstream`)
- [x] Non-blocking step primitives (`readStep`/`writeStep`) plus bounded timeout-enforcing wrappers
- [x] Compatibility `read`/`write` APIs preserving explicit `WantRead` vs `WantWrite`
  signaling for existing callers
- [x] Graceful shutdown (close_notify)
- [x] Read-side diagnostics for `close_notify`, peer resets, and TLS protocol failures

### Phase 2 (Complete)
- [x] kTLS kernel offload via OpenSSL/BoringSSL BIO enablement
- [x] Automatic kTLS runtime detection and userspace fallback
- [x] HandshakeInfo.ktls_enabled status tracking
- [x] TLSStream.isKtls() / queryKtlsStatus() for runtime checks

### Phase 3 (In Progress)
- [ ] Session resumption
- [x] ALPN negotiation (for HTTP/2)
- [~] Certificate reload groundwork (`ReloadableServerCtx` generation/refcount manager)
- [~] Certificate activation API skeleton (`createServerCtxFromPemFiles` + `activateFromPemFiles`)
- [ ] Certificate file watcher / control-plane trigger
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

### kTLS via OpenSSL/BIO

**Decision:** Enable `SSL_OP_ENABLE_KTLS` before handshake and keep TLS I/O on the SSL/BIO path, with explicit runtime checks and userspace fallback.

**Rationale:**
- Runtime checks gate kTLS setup (platform, module presence, optional env disable)
- Deterministic fallback: if BIO kTLS is unavailable, TLS stays in userspace without handshake failure
- Transparent to users - TLSStream API unchanged, `isKtls()` for status

**kTLS Benefits:**
- Zero-copy sendfile() for encrypted data (kernel handles TLS records)
- Reduced context switches (crypto in kernel space)
- Hardware crypto offload on supported NICs

**Requirements (for kTLS offload mode):**
- Linux kernel with `tls` module (`modprobe tls`)
- OpenSSL/BoringSSL build with kTLS BIO support
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
    WouldBlock,
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
| kTLS BIO enablement | Complete | stream.zig |
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
