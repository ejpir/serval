<project>
  <name>zzz-fix</name>
  <description>HTTP server framework for Zig — backends, proxies, load balancers, API gateways, sidecars</description>
  <style>TigerStyle</style>
</project>

<compiler>
  <path>/usr/local/zig-x86_64-linux-0.16.0-dev.1859+212968c57/zig</path>
</compiler>

<commands>
  <build>zig build</build>
  <test-serval>zig build test-serval</test-serval>
  <test-lb>zig build test-lb</test-lb>
  <run-example>zig build run-lb-example</run-example>
</commands>

<architecture>
  <module name="serval" path="lib/serval/">Main HTTP/1.1 server library (imports all modules)</module>
  <module name="serval-core" path="lib/serval-core/">Foundation: types, config, errors, context, log</module>
  <module name="serval-http" path="lib/serval-http/">HTTP/1.1 parser</module>
  <module name="serval-pool" path="lib/serval-pool/">Connection pooling</module>
  <module name="serval-proxy" path="lib/serval-proxy/">Upstream forwarding (splice zero-copy)</module>
  <module name="serval-metrics" path="lib/serval-metrics/">Metrics interfaces</module>
  <module name="serval-tracing" path="lib/serval-tracing/">Distributed tracing interfaces</module>
  <module name="serval-lb" path="lib/serval-lb/">Load balancer handler (round-robin)</module>

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
      <module status="future">serval-tls</module>
      <module status="future">serval-h2</module>
      <responsibility>Protocol parsing, socket utilities - no business logic</responsibility>
      <notes>
        serval-http: HTTP/1.1 request/response parsing
        serval-tls: TLS termination (client-side) and origination (upstream-side), ALPN
        serval-h2: HTTP/2 framing, HPACK, stream multiplexing - shares types with serval-http
      </notes>
    </layer>
    <layer level="2" name="infrastructure">
      <module>serval-pool</module>
      <module>serval-metrics</module>
      <module>serval-tracing</module>
      <module status="future">serval-cache</module>
      <module status="future">serval-otel</module>
      <module status="future">serval-waf</module>
      <module status="future">serval-ratelimit</module>
      <module status="future">serval-health</module>
      <responsibility>Reusable infrastructure - generic, handler-agnostic</responsibility>
      <notes>
        serval-tracing: Interface for distributed tracing (span creation, context propagation)
        serval-otel: OpenTelemetry implementation of serval-tracing interface (OTLP export)
        serval-cache: Cache storage and lookup (keys, TTL, eviction) - policy via handler hooks
        serval-waf: Rule engine for threat detection (SQLi, XSS, etc.) - blocking via handler hooks
        serval-ratelimit: Token bucket / sliding window rate limiting - keyed by IP, path, header
        serval-health: Health checks (active probes), circuit breaker state machine, backend status
      </notes>
    </layer>
    <layer level="3" name="mechanics">
      <module>serval-proxy</module>
      <responsibility>HOW to forward - network I/O, connection mgmt, timing</responsibility>
    </layer>
    <layer level="4" name="strategy">
      <module>serval-lb</module>
      <module>serval-forward (future)</module>
      <module>serval-router (future)</module>
      <responsibility>WHERE/WHICH to forward - routing decisions, upstream selection</responsibility>
    </layer>
    <layer level="5" name="orchestration">
      <module>serval-server</module>
      <module>serval</module>
      <responsibility>Composition - wires layers together, accept loop</responsibility>
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
      <point trigger="distributed tracing / OpenTelemetry">
        Span interface → serval-tracing (layer 2, already exists).
        OTLP export → serval-otel (layer 2, implements serval-tracing).
        Span creation → handler hooks (onRequest creates span, onResponse closes).
        Context propagation → serval-core Context struct carries trace_id, span_id.
        W3C traceparent header → serval-http or serval-proxy injects/extracts.
      </point>
      <point trigger="TLS / HTTPS support">
        TLS primitives → serval-tls (layer 1): handshake, cert loading, ALPN negotiation.
        Client termination → serval-server wraps accepted socket with TLS.
        Upstream origination → serval-proxy wraps upstream socket with TLS.
        Config → serval-core: cert_path, key_path, upstream_tls_enabled, verify_upstream.
        Connection pooling → serval-pool: separate pools for TLS vs plain connections.
        Stream abstraction → both serval-http and serval-tls implement same read/write interface.
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
      <point trigger="content-based routing / API gateway">
        Route matching → serval-router (layer 4): path prefix, regex, headers, host, method.
        Per-pool LB → serval-router composes serval-lb internally for each backend pool.
        Route config → runtime config or serval-core: route table definition.
        Fallback route → required (TigerStyle: no implicit behavior, explicit default).
        Path rewriting → serval-router: strip prefix, add prefix before forwarding.
        Rate limiting → serval-router or separate serval-ratelimit (layer 2) + handler hook.
        Auth routing → route to auth service, or reject if auth header missing.
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
      <point trigger="health checks">
        Active probes → serval-health (layer 2): periodic HTTP/TCP checks to backends.
        Probe config → interval_ms, timeout_ms, unhealthy_threshold, healthy_threshold.
        Health state → serval-health maintains per-upstream status (healthy, unhealthy, unknown).
        Integration → handlers (layer 4) query health before selection, skip unhealthy.
        Passive checks → onResponse/onError update health based on real traffic (5xx = unhealthy).
        Background task → serval-health runs probe loop independently of request handling.
        Startup → backends start as unknown, become healthy after first successful probe.
      </point>
      <point trigger="circuit breaker">
        State machine → serval-health (layer 2): closed → open → half-open → closed.
        Closed → normal operation, track error rate per upstream.
        Open → reject requests to upstream immediately (fail fast), return 503.
        Half-open → after timeout, allow limited probe requests to test recovery.
        Thresholds → config: error_rate_percent, window_size_ms, open_duration_ms, probe_count.
        Integration → selectUpstream checks circuit state, skips open circuits.
        Error tracking → onError/onResponse with 5xx increments failure counter.
        Success tracking → onResponse with 2xx/3xx resets failure counter, closes circuit.
        Metrics → circuit state changes emit events for serval-metrics/logging.
        Separate from health → circuit breaker is reactive (based on traffic), health checks are proactive.
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
      <sub-answer if="no">Create a new file within the same module (lib/serval-X/).</sub-answer>
    </answer>
    <answer if="no">Continue to question 3.</answer>

    <question id="3">Is this a new cross-cutting concern or infrastructure capability?</question>
    <answer if="yes">Create a new module at layer 2 (lib/serval-newmodule/).</answer>
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
      Create a new lib/serval-X/ module ONLY when ALL of these apply:
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
      → New lib/serval-health/ module (cross-cutting, has state, layer 2)
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
  <step order="3">Update README.md files in lib/ folders for any modified modules</step>
  <step order="4">Verify lib/serval/ARCHITECTURE.md is still accurate</step>
  <step order="5">Build and test</step>
</workflow>

<documentation>
  <IMPORTANT>When modifying serval modules, verify these docs are current</IMPORTANT>

  <doc path="ROADMAP.md">Development phases, priorities, deliverables checklist</doc>
  <doc path="plans/">Detailed implementation plans for major features</doc>
  <doc path="lib/serval/ARCHITECTURE.md">Module structure, request flow, interfaces</doc>
  <doc path="lib/*/README.md">Per-module purpose, exports, implementation status</doc>
</documentation>

<code-review>
  <skill>/tigerstyle</skill>
  <usage>Use for reviewing code changes before committing</usage>
</code-review>
