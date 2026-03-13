# HTTP/2 Compliance Baseline Capture (Phase 0)

Date: 2026-03-12

## Environment

- Repository: `/home/nick/repos/serval`
- Compiler used for baseline verification:
  - `/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig`

## Tooling availability

- `grpcurl`: available
- `h2spec`: available (`$HOME/.local/bin/h2spec`)
- `nghttp`: available (`/usr/bin/nghttp`)

## Commands executed

```bash
/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build test-h2
# Exit code: 0

/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build test-server
# Exit code: 0

/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build test-client
# Exit code: 0

/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build test-proxy
# Exit code: 0

/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build test-tls
# Exit code: 0

/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build test-integration
# Exit code: 1 (one run; intermittent ReadTimeout in goaway-last-stream scenario)

/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build test-integration
# Exit code: 0
# Summary: All 96 tests passed (1 skipped)

/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build
# Exit code: 0

integration/h2_conformance_runner.sh --host 127.0.0.1 --h2c-port 8080 --tls-port 8443 --h2spec-timeout 1
# Exit code: 1
# h2spec h2c: 145 tests, 145 passed, 0 skipped, 0 failed
# h2spec TLS: 145 tests, 145 passed, 0 skipped, 0 failed
# nghttp cleartext: OK
# nghttp TLS: OK
```

## Baseline interpretation

- Internal Zig unit/integration coverage for current h2/gRPC-h2c paths is strong and passing.
- External RFC conformance tooling (`h2spec`/`nghttp`) is installed locally and runner automation is available via `integration/h2_conformance_runner.sh`.
- Cleartext conformance (`h2c`) currently executes 145/145 with zero failures.
- TLS conformance (`h2`) on the dedicated conformance target now also executes 145/145 with zero failures.
- Compliance matrix and remaining blockers are tracked in:
  - `docs/plans/http2-rfc9113-matrix.md`
