# Component Usage Rules

Use Serval components consistently. Avoid raw alternatives unless you are working inside the lowest-level abstraction itself.

## HTTP clients

Always use `serval-client`:

- `Client.init(allocator, dns_resolver, client_ctx, verify_tls)`
- `client.connect(upstream, io)`
- `client.sendRequest(conn, request, path)`
- `client.readResponseHeaders(conn, header_buf)`

Do not use raw `posix.socket()` for HTTP client behavior.

## HTTP servers

Always use `serval-server`:

- `Server(Handler, Pool, Metrics, Tracer)` or `MinimalServer(Handler)`
- Implement handler contracts (`selectUpstream`, hooks)
- Use `DirectResponse` for short-circuit responses

Do not reimplement accept/bind/listen with raw socket calls in higher layers.

## Constants and timing

Always use `serval-core`:

- `serval-core.config` for timeouts, limits, sizes, default ports
- `serval-core.time` for monotonic/realtime and elapsed calculations

Avoid local duplicate constants for values that already exist in core config.

## Shared types

Always use `serval-core.types` for common contracts:

- `Request`, `Response`, `Method`, `Version`
- `Upstream`, `Action`, `DirectResponse`, `RejectResponse`
- `HeaderMap`, `ConnectionInfo`

Do not redefine shared protocol/application types locally.

## DNS and sockets

- Use `serval-net.DnsResolver` for DNS (cache + concurrency safety)
- Use `serval-socket.Socket` for unified TCP/TLS read/write behavior

## TLS

Always use `serval-tls` wrappers:

- `ssl.createServerCtx()` for server termination
- `ssl.createClientCtx()` for upstream origination
- `TLSStream` for userspace TLS I/O
- `ktls` where supported with userspace fallback

Do not call raw OpenSSL/BoringSSL APIs directly in modules above TLS abstraction boundaries.
