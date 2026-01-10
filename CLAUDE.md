<project>
  <name>zzz-fix</name>
  <description>HTTP server framework for Zig — backends, proxies, load balancers, API gateways, sidecars</description>
  <style>TigerStyle</style>
</project>

<quality-standards>
  <CRITICAL priority="HIGHEST">
    This is PRODUCTION-GRADE code. We are building infrastructure software that must operate with space shuttle-level reliability.
  </CRITICAL>

  <principles>
    <principle name="production-quality">
      We are NOT building prototypes or POCs anymore. Every line of code must be production-ready.
      Code that goes into serval-* modules will be used in real systems handling real traffic.
    </principle>

    <principle name="space-shuttle-testing">
      Testing must be exhaustive and thorough like NASA's space shuttle software development:
      - Test all code paths (happy path, error paths, edge cases)
      - Test boundary conditions (zero, max, overflow)
      - Test resource exhaustion (OOM, fd limits, timeouts)
      - Test concurrent access (race conditions, deadlocks)
      - Test failure recovery (crash recovery, rollback, cleanup)
      - Integration tests for all major features
      - Stress tests to validate performance claims
    </principle>

    <principle name="follow-specs">
      Strictly follow specifications:
      - RFC compliance (HTTP/1.1, TLS, etc.)
      - Architecture layer rules (no sideways dependencies)
      - TigerStyle rules (ALL rules, NO exceptions)
      - API contracts (function signatures, error handling)
      - Performance requirements (latency targets, memory bounds)
    </principle>

    <principle name="mandatory-tigerstyle">
      ALWAYS run /tigerstyle validation:
      - Before writing new code (to understand requirements)
      - During implementation (to validate approach)
      - After writing code (to verify compliance)
      - Before committing (final check)

      TigerStyle is NOT optional. It is a requirement for ALL code.
      Check EVERY rule (S1-S7, P1-P4, C1-C5, Y1-Y6) individually.
    </principle>

    <principle name="verify-all-decisions">
      Validate architectural and implementation decisions:
      - Use /tigerstyle to check if design follows TigerStyle principles
      - Reference RFC specs for protocol decisions
      - Check layer architecture rules for module placement
      - Verify against implementation plans in docs/plans/
      - Cross-reference with existing code patterns in codebase
    </principle>

    <principle name="no-shortcuts">
      NO SHORTCUTS. NO "TODO" comments. NO "will fix later."
      - Every function has proper error handling
      - Every resource has cleanup (defer, errdefer)
      - Every assumption has an assertion
      - Every timeout has a bound
      - Every loop has an exit condition
      - Every allocation has a corresponding free
    </principle>
  </principles>

  <development-process>
    <step order="1">
      Read and understand specs (RFCs, plans, TigerStyle docs)
    </step>
    <step order="2">
      Design implementation (validate with /tigerstyle)
    </step>
    <step order="3">
      Write code with inline assertions and error handling
    </step>
    <step order="4">
      Run /tigerstyle validation on code
    </step>
    <step order="5">
      Write comprehensive tests (unit, integration, edge cases)
    </step>
    <step order="6">
      Run all tests and verify they pass
    </step>
    <step order="7">
      Update documentation (README.md, ARCHITECTURE.md)
    </step>
    <step order="8">
      Final /tigerstyle check before commit
    </step>
  </development-process>

  <testing-requirements>
    <requirement category="unit-tests">
      Every function with logic must have unit tests:
      - Test success cases with valid inputs
      - Test all error paths with invalid inputs
      - Test boundary conditions (0, 1, max, max+1)
      - Test resource cleanup (defer, errdefer)
    </requirement>

    <requirement category="integration-tests">
      Every module must have integration tests:
      - Test module initialization and cleanup
      - Test integration with dependencies
      - Test concurrency (if applicable)
      - Test resource limits (memory, fds, timeouts)
    </requirement>

    <requirement category="property-tests">
      For parsers and state machines:
      - Fuzz testing with random inputs
      - Property-based testing (invariants hold)
      - State transition coverage
    </requirement>

    <requirement category="performance-tests">
      For performance-critical code:
      - Benchmark against targets (p50, p99 latency)
      - Stress test under load
      - Memory usage profiling
      - CPU profiling to identify bottlenecks
    </requirement>
  </testing-requirements>

  <code-quality-checklist>
    <check>✓ All TigerStyle rules pass (/tigerstyle validation)</check>
    <check>✓ All tests pass (unit, integration)</check>
    <check>✓ No memory leaks (valgrind or similar)</check>
    <check>✓ No undefined behavior (ubsan)</check>
    <check>✓ All error paths tested</check>
    <check>✓ All resources properly cleaned up</check>
    <check>✓ Documentation updated</check>
    <check>✓ Specs followed (RFCs, plans)</check>
    <check>✓ Architecture rules followed (layers, deps)</check>
    <check>✓ Performance targets met (if applicable)</check>
  </code-quality-checklist>

  <rejection-criteria>
    <CRITICAL>Reject code that has ANY of these:</CRITICAL>
    <reject>Missing error handling (catch {}, unchecked errors)</reject>
    <reject>Unbounded loops (no timeout, no max iterations)</reject>
    <reject>Resource leaks (missing defer, missing free)</reject>
    <reject>Missing assertions (no precondition/postcondition checks)</reject>
    <reject>TigerStyle violations (any rule S1-S7, P1-P4, C1-C5, Y1-Y6)</reject>
    <reject>Missing tests (no test coverage for new code)</reject>
    <reject>Spec violations (RFC non-compliance, layer violations)</reject>
    <reject>TODO comments (finish it now, not later)</reject>
    <reject>Magic numbers (use named constants with units)</reject>
    <reject>Implicit behavior (make all defaults explicit)</reject>
  </rejection-criteria>

  <completion-gate>
    <CRITICAL>BEFORE saying "ready to commit", "done", or "all tests pass", you MUST output this verification block:</CRITICAL>

    <required-output>
      ## Completion Verification

      ### Files Changed
      [List EVERY modified file from git status]

      ### Each File Reviewed
      | File | TigerStyle | Tests | Docs |
      |------|-----------|-------|------|
      | path/to/file.zig | ✓ S1-S7, P1-P4, C1-C5, Y1-Y6 checked | ✓ or N/A | ✓ or N/A |

      ### Verification Commands Run
      ```
      zig build              # Exit code: 0
      zig build test         # Exit code: 0
      ```

      ### Checklist
      - [ ] All TigerStyle rules checked (not delegated to subagent without verification)
      - [ ] All modified files listed and reviewed
      - [ ] Tests pass (with actual output shown)
      - [ ] README.md updated for affected modules
      - [ ] No usize where bounded type would work
      - [ ] No catch {}
      - [ ] Assertions in every function (~2 per function)
    </required-output>

    <forbidden>
      DO NOT use phrases like "ready to commit", "done", "all set", "looks good"
      without FIRST outputting the verification block above.

      DO NOT trust subagent reviews without spot-checking their findings yourself.

      DO NOT declare completion after fixing an issue - re-verify the ENTIRE changeset.
    </forbidden>
  </completion-gate>

  <examples>
    <bad-example>
      // BAD: Missing timeout, no assertions, catch {}
      fn do_handshake(ssl: *SSL) !void {
          while (true) {
              _ = c.SSL_do_handshake(ssl) catch {};
          }
      }
    </bad-example>

    <good-example>
      // GOOD: Bounded loop, assertions, explicit error handling, timeout
      fn do_handshake(
          ssl: *SSL,
          fd: c_int,
          io: *Io,
          timeout_ns: i64,
      ) !void {
          assert(ssl != null); // S1: precondition
          assert(fd > 0); // S1: precondition
          assert(timeout_ns > 0); // S1: precondition

          const start_ns: i64 = std.time.nanoTimestamp();
          var iteration: u32 = 0;
          const max_iterations: u32 = 1000; // S3: bounded loop

          while (iteration < max_iterations) { // S3: explicit bound
              iteration += 1;

              const now_ns: i64 = std.time.nanoTimestamp();
              const elapsed_ns: i64 = now_ns - start_ns;
              assert(elapsed_ns >= 0); // S1: monotonic clock invariant
              if (elapsed_ns > timeout_ns) return error.HandshakeTimeout;

              const remaining_ns: i64 = timeout_ns - elapsed_ns;

              const ret = c.SSL_do_handshake(ssl);
              if (ret == 1) {
                  assert(c.SSL_is_init_finished(ssl)); // S2: postcondition
                  return; // Success
              }

              const err = c.SSL_get_error(ssl, ret);
              switch (err) { // S4: explicit error handling
                  c.SSL_ERROR_WANT_READ => try io.pollIn(fd, remaining_ns),
                  c.SSL_ERROR_WANT_WRITE => try io.pollOut(fd, remaining_ns),
                  else => return error.HandshakeFailed,
              }
          }

          return error.HandshakeMaxIterations; // S3: bounded loop exit
      }
    </good-example>
  </examples>
</quality-standards>

<compiler>
  <path>/usr/local/zig-x86_64-linux-0.16.0-dev.1912+0cbaaa5eb/zig</path>
</compiler>

<commands>
  <build>zig build</build>
  <test>zig build test</test>
  <test-lb>zig build test-lb</test-lb>
  <test-router>zig build test-router</test-router>
  <test-health>zig build test-health</test-health>
  <run-lb-example>zig build run-lb-example</run-lb-example>
  <run-router-example>zig build run-router-example</run-router-example>
</commands>

<architecture>
  <module name="serval" path="serval/">Main HTTP/1.1 server library (imports all modules)</module>
  <module name="serval-core" path="serval-core/">Foundation: types, config, errors, context, log</module>
  <module name="serval-http" path="serval-http/">HTTP/1.1 parser</module>
  <module name="serval-net" path="serval-net/">Socket abstraction (plain TCP + TLS unified interface)</module>
  <module name="serval-tls" path="serval-tls/">TLS termination/origination with kTLS kernel offload</module>
  <module name="serval-pool" path="serval-pool/">Connection pooling</module>
  <module name="serval-proxy" path="serval-proxy/">Upstream forwarding (splice zero-copy)</module>
  <module name="serval-metrics" path="serval-metrics/">Metrics interfaces</module>
  <module name="serval-tracing" path="serval-tracing/">Distributed tracing interfaces</module>
  <module name="serval-otel" path="serval-otel/">OpenTelemetry implementation (OTLP/JSON export)</module>
  <module name="serval-health" path="serval-health/">Health tracking (atomic bitmap, thresholds)</module>
  <module name="serval-prober" path="serval-prober/">Background health probing (HTTP/HTTPS)</module>
  <module name="serval-client" path="serval-client/">HTTP/1.1 client (DNS, TCP, TLS, request/response)</module>
  <module name="serval-lb" path="serval-lb/">Load balancer handler (round-robin)</module>
  <module name="serval-router" path="serval-router/">Content-based routing with per-pool load balancing</module>
  <module name="serval-gateway" path="serval-gateway/">Gateway API types and translator (library for gateway controllers)</module>
  <module name="serval-server" path="serval-server/">HTTP server with connection handling and hooks</module>
  <module name="serval-cli" path="serval-cli/">CLI argument parsing utilities</module>

  <design-points>
    <point>Concurrent connection handling via Io.Group.concurrent (io_uring batch submission)</point>
    <point>Handler hooks: onRequest, onResponse, onError, onLog, onConnectionOpen, onConnectionClose</point>
    <point>All timing in nanoseconds with _ns suffix</point>
  </design-points>

  <layers description="Modules organized by abstraction level - higher layers depend on lower, never sideways">
    <layer level="0" name="foundation">
      <module>serval-core</module>
      <responsibility>Types, config, errors, context - shared vocabulary</responsibility>
    </layer>
    <layer level="1" name="protocol">
      <module>serval-http</module>
      <module>serval-net</module>
      <module>serval-tls</module>
      <module status="future">serval-h2</module>
      <responsibility>Protocol parsing, socket utilities - no business logic</responsibility>
      <notes>
        serval-http: HTTP/1.1 request/response parsing (implemented)
        serval-net: Unified Socket abstraction for plain TCP and TLS (implemented)
        serval-tls: TLS termination and origination with kTLS kernel offload (implemented)
        serval-h2: HTTP/2 framing, HPACK, stream multiplexing - shares types with serval-http (future)
      </notes>
    </layer>
    <layer level="2" name="infrastructure">
      <module>serval-pool</module>
      <module>serval-metrics</module>
      <module>serval-tracing</module>
      <module>serval-otel</module>
      <module>serval-health</module>
      <module>serval-prober</module>
      <module>serval-client</module>
      <module status="future">serval-cache</module>
      <module status="future">serval-waf</module>
      <module status="future">serval-ratelimit</module>
      <responsibility>Reusable infrastructure - generic, handler-agnostic</responsibility>
      <notes>
        serval-pool: Fixed-size connection pooling with idle/age eviction (implemented)
        serval-metrics: Request metrics with noop and Prometheus implementations (implemented)
        serval-tracing: Interface for distributed tracing (implemented)
        serval-otel: OpenTelemetry with OTLP/JSON export and batching (implemented)
        serval-health: Threshold-based health tracking with atomic bitmap (implemented)
        serval-prober: Background HTTP/HTTPS health probing using serval-client (implemented)
        serval-client: HTTP/1.1 client for upstream connections (implemented)
        serval-cache: Cache storage and lookup (keys, TTL, eviction) - policy via handler hooks (future)
        serval-waf: Rule engine for threat detection (SQLi, XSS, etc.) - blocking via handler hooks (future)
        serval-ratelimit: Token bucket / sliding window rate limiting - keyed by IP, path, header (future)
      </notes>
    </layer>
    <layer level="3" name="mechanics">
      <module>serval-proxy</module>
      <responsibility>HOW to forward - network I/O, connection mgmt, timing</responsibility>
      <notes>
        serval-proxy: Async upstream forwarding with splice zero-copy, delegates to serval-client for HTTP (implemented)
      </notes>
    </layer>
    <layer level="4" name="strategy">
      <module>serval-lb</module>
      <module>serval-router</module>
      <module>serval-gateway</module>
      <module status="future">serval-forward</module>
      <responsibility>WHERE/WHICH to forward - routing decisions, upstream selection, gateway config</responsibility>
      <notes>
        serval-lb: Health-aware round-robin with background probing (implemented)
        serval-router: Content-based routing with host/path matching, path rewriting, per-pool LB (implemented)
        serval-gateway: Gateway API types (Gateway, HTTPRoute) and translator to serval-router config (implemented)
        serval-forward: Simple forwarding handler (future)
      </notes>
    </layer>
    <layer level="5" name="orchestration">
      <module>serval-server</module>
      <module>serval</module>
      <module>serval-cli</module>
      <responsibility>Composition - wires layers together, accept loop</responsibility>
      <notes>
        serval-server: HTTP/1.1 server with keep-alive, handler hooks, metrics, tracing (implemented)
        serval: Umbrella module re-exporting all modules (implemented)
        serval-cli: CLI argument parsing utilities (implemented)
      </notes>
    </layer>
  </layers>

  <abstraction-rules>
    <rule name="no-sideways-deps">
      Modules at the same layer MUST NOT depend on each other.
      serval-lb and serval-proxy are independent; they share only serval-core types.
    </rule>
    <rule name="strategy-vs-mechanics">
      "Where to send" (strategy) is separate from "how to send" (mechanics).
      New routing algorithms → layer 4. New forwarding features → layer 3.
    </rule>
    <rule name="handler-interface">
      Strategy modules implement selectUpstream(ctx, request) → Upstream.
      The Upstream type is the contract between strategy and mechanics.
    </rule>
    <rule name="extension-points">
      <point trigger="new upstream selection algorithm">Add handler in layer 4 (like serval-lb)</point>
      <point trigger="new forwarding capability">Extend serval-proxy in layer 3</point>
      <point trigger="new protocol support">Add module in layer 1</point>
      <point trigger="new shared utility">Add to serval-core or create layer 1/2 module</point>
      <point trigger="new cross-cutting concern">Add infrastructure module in layer 2</point>
      <point trigger="response caching">
        Storage/eviction → serval-cache (layer 2).
        Cache key generation → handler hook onRequest.
        Cache-Control parsing → serval-http (layer 1).
        Short-circuit response → handler returns cached response before selectUpstream.
      </point>
      <point trigger="distributed tracing / OpenTelemetry" status="implemented">
        Span interface → serval-tracing (layer 2, implemented).
        OTLP export → serval-otel (layer 2, implemented with JSON/HTTP and batching).
        Span creation → handler hooks (onRequest creates span, onResponse closes).
        Context propagation → serval-core Context struct carries trace_id, span_id.
        W3C traceparent header → serval-http or serval-proxy injects/extracts (future).
      </point>
      <point trigger="TLS / HTTPS support" status="implemented">
        TLS primitives → serval-tls (layer 1, implemented): handshake, cert loading, kTLS kernel offload.
        Socket abstraction → serval-net (layer 1, implemented): unified Socket tagged union for TCP/TLS.
        Client termination → serval-server wraps accepted socket with TLS (implemented).
        Upstream origination → serval-proxy wraps upstream socket with TLS (implemented).
        Config → serval-core: cert_path, key_path, upstream_tls_enabled, verify_upstream.
        kTLS offload → automatic detection with userspace fallback (implemented).
        Zero-copy → splice() works with kTLS-capable sockets (implemented).
      </point>
      <point trigger="HTTP/2 support">
        Framing/HPACK → serval-h2 (layer 1): frame parsing, header compression, stream state.
        Shared types → serval-core: Request/Response work for both HTTP/1.1 and HTTP/2.
        Stream multiplexing → serval-h2: maps N streams to 1 connection.
        Connection handling → serval-server: detect h2 via ALPN or upgrade, dispatch to h2 handler.
        Upstream h2 → serval-proxy: optional h2 to backends (h2c or h2 over TLS).
        Priority/flow control → serval-h2: internal concern, not exposed to handlers.
        Handlers unchanged → selectUpstream sees Request, unaware of underlying protocol.
      </point>
      <point trigger="protocol negotiation (h2 + TLS)">
        ALPN in TLS handshake → serval-tls returns negotiated protocol (h2, http/1.1).
        Dispatch → serval-server checks ALPN result, routes to serval-h2 or serval-http.
        Fallback → if no ALPN, default to HTTP/1.1.
        h2c (cleartext h2) → serval-http detects "PRI * HTTP/2.0" preface, hands off to serval-h2.
      </point>
      <point trigger="content-based routing / API gateway" status="implemented">
        Route matching → serval-router (layer 4, implemented): path prefix, exact, host matching.
        Per-pool LB → serval-router composes LbHandler internally for each backend pool (implemented).
        Route config → compile-time routes (implemented), runtime mutable (future).
        Fallback route → required default route (implemented, TigerStyle: explicit default).
        Path rewriting → strip prefix before forwarding (implemented), replace prefix (future).
        Additional matchers → headers, query params, method, regex (future).
        Rate limiting → serval-ratelimit (layer 2) + handler hook (future).
        Auth routing → route to auth service, or reject if auth header missing (future).
      </point>
      <point trigger="WAF / Web Application Firewall">
        Rule engine → serval-waf (layer 2): pattern matching, rule evaluation, threat scoring.
        Rule sets → serval-waf: OWASP CRS-style rules (SQLi, XSS, path traversal, etc.).
        Request inspection → handler hook onRequest: check headers, path, query, body.
        Response inspection → handler hook onResponse: check for data leaks, errors.
        Blocking decision → onRequest returns block response (403) before selectUpstream.
        Logging → onLog receives WAF decision (allow/block/flag) with matched rules.
        Mode → config: enforce (block) vs detect-only (log but forward).
        IP reputation → serval-waf or separate module: blocklists, geo-blocking.
        Body parsing → serval-waf: form data, JSON, multipart inspection (bounded, no full buffering).
      </point>
      <point trigger="health checks" status="implemented">
        State tracking → serval-health (layer 2, implemented): atomic bitmap + threshold counters.
        Design → Pingora-inspired: boolean health with consecutive thresholds (no circuit breaker states).
        Passive checks → handler calls tracker.recordSuccess/recordFailure on request completion (implemented).
        Active probes → serval-prober (layer 2, implemented): background thread HTTP/HTTPS GET probes against unhealthy backends.
        TLS support → serval-prober detects upstream.tls flag and performs TLS handshake with SNI before HTTP probe (implemented).
        Integration → selectUpstream uses tracker.findNthHealthy() to skip unhealthy backends (implemented in serval-lb).
        Config → DEFAULT_UNHEALTHY_THRESHOLD (3), DEFAULT_HEALTHY_THRESHOLD (2), DEFAULT_PROBE_INTERVAL_MS (5000), DEFAULT_HEALTH_PATH ("/").
      </point>
      <point trigger="rate limiting">
        Algorithm → serval-ratelimit (layer 2): token bucket, sliding window, or fixed window.
        Key extraction → by IP, path, header value, API key, or combination.
        Limits config → requests_per_second, burst_size, window_duration_ms.
        Integration → handler hook onRequest: check limit, return 429 if exceeded.
        Headers → add X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After to response.
        Shared state → for distributed deployments, external store (Redis) or approximate local.
        Graceful degradation → if rate limit store unavailable, allow (fail open) or block (fail closed).
      </point>
    </rule>
    <rule name="type-ownership">
      Types live in the lowest layer that needs them.
      Upstream, Request, Context → serval-core (layer 0).
      ForwardResult, ForwardError → serval-proxy (layer 3, not shared).
    </rule>
  </abstraction-rules>
</architecture>

<component-usage>
  <CRITICAL>Use serval-* components consistently - avoid raw implementations</CRITICAL>

  <rule name="http-clients">
    Always use serval-client for HTTP client operations:
    - Use Client.init(allocator, dns_resolver, client_ctx, verify_tls)
    - Use client.connect(upstream, io) → ConnectResult
    - Use client.sendRequest(conn, request, path)
    - Use client.readResponseHeaders(conn, header_buf)
    - NEVER use raw posix.socket() for HTTP client connections
  </rule>

  <rule name="http-servers">
    Always use serval-server for HTTP server operations:
    - Use Server(Handler, Pool, Metrics, Tracer) or MinimalServer(Handler)
    - Implement Handler interface (selectUpstream, onRequest hooks)
    - Use DirectResponse for immediate responses without forwarding
    - NEVER use raw posix.socket(), posix.bind(), posix.listen(), posix.accept()
  </rule>

  <rule name="constants">
    Always use serval-core.config for constants:
    - Timeouts: CLIENT_CONNECT_TIMEOUT_NS, CLIENT_READ_TIMEOUT_NS, etc.
    - Buffer sizes: MAX_HEADER_SIZE_BYTES, DIRECT_RESPONSE_BUFFER_SIZE_BYTES, etc.
    - Limits: MAX_RETRIES, MAX_UPSTREAMS, etc.
    - Ports: DEFAULT_ADMIN_PORT
    - NEVER define local constants for values that exist in serval-core.config
  </rule>

  <rule name="timing">
    Always use serval-core.time for timing utilities:
    - Use time.monotonicNanos() for elapsed time measurements
    - Use time.realtimeNanos() for wall clock timestamps
    - Use time.elapsedNanos(start, end) for duration calculations
    - NEVER use std.time directly when serval-core.time provides the utility
  </rule>

  <rule name="types">
    Always use serval-core.types for common types:
    - Request, Response, Method, Version
    - Upstream, Action, DirectResponse, RejectResponse
    - HeaderMap, ConnectionInfo
    - NEVER redefine types that exist in serval-core
  </rule>

  <rule name="dns">
    Always use serval-net.DnsResolver for DNS:
    - Provides caching and async resolution
    - Thread-safe for concurrent access
    - NEVER use std.net.getAddressList directly
  </rule>

  <rule name="sockets">
    Always use serval-net.Socket for socket operations:
    - Unified abstraction for plain TCP and TLS
    - Consistent read/write interface
    - NEVER mix raw posix sockets with serval-net.Socket
  </rule>

  <rule name="tls">
    Always use serval-tls for TLS operations:
    - Use ssl.createServerCtx() for server TLS termination (accepts client connections)
    - Use ssl.createClientCtx() for client TLS origination (connects to HTTPS upstreams)
    - Use TLSStream for userspace TLS encryption/decryption
    - Use ktls for kernel TLS offload (automatic fallback to userspace if unsupported)
    - Set SSL_CTX_set_verify() for certificate verification control
    - Caller owns SSL_CTX lifetime (create once, free on shutdown)
    - NEVER use raw OpenSSL/BoringSSL calls directly - use serval-tls wrappers
  </rule>

  <examples>
    <bad-example>
      // BAD: Raw socket for HTTP client
      const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
      posix.connect(sock, &addr);
      posix.write(sock, "GET / HTTP/1.1\r\n...");
    </bad-example>
    <good-example>
      // GOOD: serval-client for HTTP client
      var client = Client.init(allocator, &dns_resolver, null, false);
      var result = try client.connect(upstream, io);
      try client.sendRequest(&result.conn, &request, null);
    </good-example>
    <bad-example>
      // BAD: Local timeout constant
      const MY_TIMEOUT_NS: u64 = 5_000_000_000;
    </bad-example>
    <good-example>
      // GOOD: Use serval-core.config
      const timeout_ns = serval_core.config.CLIENT_CONNECT_TIMEOUT_NS;
    </good-example>
  </examples>
</component-usage>

<code-placement>
  <IMPORTANT>Before writing code, decide WHERE it belongs using this framework</IMPORTANT>

  <decision-tree>
    <question id="1">Is this a bug fix or small enhancement to existing behavior?</question>
    <answer if="yes">Modify the existing file. Do not create new abstractions.</answer>
    <answer if="no">Continue to question 2.</answer>

    <question id="2">Does this functionality belong to an existing module's responsibility?</question>
    <answer if="yes">
      <sub-question>Is the existing file under 300 lines and cohesive?</sub-question>
      <sub-answer if="yes">Add to the existing file.</sub-answer>
      <sub-answer if="no">Create a new file within the same module (serval-X/).</sub-answer>
    </answer>
    <answer if="no">Continue to question 3.</answer>

    <question id="3">Is this a new cross-cutting concern or infrastructure capability?</question>
    <answer if="yes">Create a new module at layer 2 (serval-newmodule/).</answer>
    <answer if="no">Continue to question 4.</answer>

    <question id="4">Is this a new routing/selection algorithm?</question>
    <answer if="yes">Create a new handler module at layer 4.</answer>
    <answer if="no">Ask: which layer owns this responsibility? Place there.</answer>
  </decision-tree>

  <guidelines>
    <guideline name="prefer-existing">
      Default to modifying existing files. New abstractions have costs:
      - More files to navigate
      - More imports to manage
      - More documentation to maintain
      Only create new files when cohesion demands it.
    </guideline>

    <guideline name="one-responsibility">
      Each file should have ONE clear responsibility. Signs you need a new file:
      - File exceeds ~300 lines
      - Two distinct "sections" with different concerns
      - You're adding unrelated imports
      - The filename no longer describes all contents
    </guideline>

    <guideline name="new-module-criteria">
      Create a new serval-X/ module ONLY when ALL of these apply:
      - Functionality is reusable across multiple handlers/contexts
      - Has its own lifecycle (init, deinit) or state
      - Would require 2+ files if kept in existing module
      - Fits cleanly into the layer architecture (doesn't create sideways deps)
    </guideline>

    <guideline name="file-in-module">
      Create a new file within an existing module when:
      - Related to module's responsibility but distinct sub-concern
      - Existing file would exceed 300 lines
      - Logical separation aids readability (e.g., types.zig, parser.zig, encoder.zig)
    </guideline>

    <guideline name="avoid-premature-abstraction">
      TigerStyle: Do not abstract until you have 3+ concrete uses.
      - First implementation: inline in the file that needs it
      - Second use: still inline, note the duplication
      - Third use: extract to shared location
    </guideline>
  </guidelines>

  <examples>
    <example trigger="Add timeout configuration">
      → config.zig in serval-core (existing config home)
    </example>
    <example trigger="Add new error type">
      → errors.zig in serval-core (existing errors home)
    </example>
    <example trigger="Add HTTP header parsing helper">
      → parser.zig in serval-http (existing parser, if small)
      → headers.zig in serval-http (new file, if parser.zig is large)
    </example>
    <example trigger="Add circuit breaker">
      → New serval-health/ module (cross-cutting, has state, layer 2)
    </example>
    <example trigger="Add weighted round-robin">
      → handler.zig in serval-lb (extends existing LB logic)
    </example>
    <example trigger="Add request body streaming">
      → forwarder.zig in serval-proxy (extends existing forwarding)
    </example>
  </examples>
</code-placement>

<tigerstyle priority-order="Safety > Performance > Developer Experience">
  <references>
    <url>https://tigerstyle.dev/</url>
    <url>https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md</url>
  </references>

  <rules category="safety">
    <rule>~2 assertions per function (preconditions, postconditions)</rule>
    <rule>No recursion, all loops bounded</rule>
    <rule>Explicit types (u32, u64 - avoid usize except for slice indexing)</rule>
    <rule>No runtime allocation after init</rule>
    <rule>No catch {} - handle all errors explicitly</rule>
  </rules>

  <rules category="performance">
    <rule>Optimize slowest first: network > disk > memory > CPU</rule>
    <rule>Zero-copy where possible (splice, slices)</rule>
    <rule>Batch operations</rule>
  </rules>

  <rules category="style">
    <rule>Functions under 70 lines</rule>
    <rule>snake_case for functions, variables, files</rule>
    <rule>Units in names: timeout_ms, size_bytes, duration_ns</rule>
    <rule>Comments explain "why" not "what"</rule>
  </rules>
</tigerstyle>

<workflow>
  <IMPORTANT>Follow these steps IN ORDER after making code changes</IMPORTANT>

  <step order="1">Write idiomatic Zig code</step>
  <step order="2">Run /tigerstyle code review</step>
  <step order="3">Update README.md files in serval-*/ folders for any modified modules</step>
  <step order="4">Verify serval/ARCHITECTURE.md is still accurate</step>
  <step order="5">Build and test</step>
</workflow>

<documentation>
  <IMPORTANT>When modifying serval modules, verify these docs are current</IMPORTANT>

  <doc path="ROADMAP.md">Development phases, priorities, deliverables checklist</doc>
  <doc path="plans/">Detailed implementation plans for major features</doc>
  <doc path="serval/ARCHITECTURE.md">Module structure, request flow, interfaces</doc>
  <doc path="serval-*/README.md">Per-module purpose, exports, implementation status</doc>
</documentation>

<code-review>
  <skill>/tigerstyle</skill>
  <usage>Use for reviewing code changes before committing</usage>
  <CRITICAL>You MUST check EVERY rule (S1-S7, P1-P4, C1-C5, Y1-Y6) - NO EXCEPTIONS</CRITICAL>
  <CRITICAL>Do NOT skip rules. Do NOT summarize. Check each rule individually and report status.</CRITICAL>
</code-review>
