# serval-reverseproxy

`serval-reverseproxy` provides the reverse-proxy runtime foundation for Serval's plugin platform.

Scope in this slice:
- Canonical IR runtime types (`ir.zig`)
- Deterministic IR validation diagnostics (stage + object + reason)
- Deterministic chain ordering and composition (`ordering.zig`, `composition.zig`)
- Header-phase policy execution contract (`policy.zig`)
- Runtime-loaded filter binding/dispatch (`filter_runtime.zig`)
- Request streaming execution with bounded backpressure (`stream_request.zig`)
- Response streaming execution + framing planner (`stream_response.zig`)
- Failure classification + protocol-correct terminal actions (`failure.zig`)
- Guard-window monitoring + rollback/safe-mode triggers (`guard_window.zig`)
- Declarative DSL parser + semantic validation (`dsl.zig`)
- DSL/schema equivalence harness (`equivalence.zig`)
- Generation-based orchestrator lifecycle (`orchestrator.zig`)
- Atomic active-generation swap and bounded drain/retire handling
- Rollback and safe-mode transition hooks

## Layer Ownership

- **Layer 5 (Orchestration)** ownership for reverse-proxy apply lifecycle.
- **Not** responsible for route strategy decisions (router/lb layer).
- **Not** responsible for stream forwarding mechanics (serval-proxy layer).

## Public API

```zig
const reverseproxy = @import("serval-reverseproxy");

var runtime = try reverseproxy.load(.{ .config_file = "examples/reverseproxy/basic.dsl" });
defer runtime.deinit();

try runtime.run(.{ .port = 8080 }); // optional override; omit to use DSL listener port
```

Starter DSL config:
- `examples/reverseproxy/basic.dsl`
- `examples/reverseproxy/netbird.dsl` (NetBird route matrix replacement)
- TLS providers example: `examples/reverseproxy/tls_providers.dsl`

Route/listener binding:
- Routes may declare `listener=<listener-id>` for explicit listener scoping.
- If omitted, runtime defaults route binding to the first declared listener.

Core DSL object roles:
- `listener`: inbound bind target (IP:port) for receiving traffic.
- `pool`: upstream target set (in this slice, one upstream spec per pool).
- `plugin`: a policy/filter capability with fail policy and metadata.
- `chain`: ordered policy execution pipeline referencing one or more plugins.
- `route`: request matcher (listener/host/path) that selects pool + chain.

`chain` in practice:
- A chain is the policy pipeline attached to a route.
- Route matching decides *where* to send traffic (`pool`), and chain decides *what policy logic* runs for that traffic (`plugin` entries).

## Failure Policy Semantics (`fail_open` vs `fail_closed`)

Policy values:
- `fail_closed`: on plugin failure, do not bypass policy logic; fail the request/stream.
- `fail_open`: on plugin failure, allow sticky bypass only when safe; otherwise fail the request/stream.

Terminal behavior is protocol-aware:
- Pre-header plugin/upstream failures: send explicit error response.
- Mid-stream HTTP/1.1 failures: close the connection.
- Mid-stream HTTP/2 or h2c failures: reset the active stream.

`fail_open` sticky bypass safety:
- Allowed before response headers are sent.
- Not allowed once response body/headers are in-flight.

Implementation source of truth:
- Canonical policy type: `serval-reverseproxy/ir.zig` (`FailurePolicy`)
- Runtime decision logic: `serval-reverseproxy/failure.zig` (`classifyFailure`)

Current DSL caveat:
- DSL currently requires `plugin ... fail_policy=...` syntax.
- Chain entries are currently emitted with `fail_closed` in parser wiring.
- So `fail_policy` is validated in DSL today, but chain runtime behavior is currently fail-closed unless parser wiring is extended.

Runtime component selection (binary mode):
- `config.component.pool=simple|none`
- `config.component.metrics=noop|prometheus`
- `config.component.tracing=noop|otel`
- when tracing is `otel`, set `config.component.tracing.otel.endpoint=<http(s)://collector:4318/v1/traces>`
- optional OTEL metadata keys:
  - `config.component.tracing.otel.service_name`
  - `config.component.tracing.otel.service_version`
  - `config.component.tracing.otel.scope_name`
  - `config.component.tracing.otel.scope_version`

Alternate statement form is also supported:
- `component pool simple`
- `component metrics prometheus`
- `component tracing noop`

TLS listener providers:
- `tls.provider=static` with `tls.static.cert_path` + `tls.static.key_path`
- `tls.provider=selfsigned` with `tls.selfsigned.state_dir` + `tls.selfsigned.domain`
- `tls.provider=acme` with `tls.acme.directory_url`, `tls.acme.contact_email`, `tls.acme.state_dir`, `tls.acme.domain`

ACME provider bootstrap behavior:
- If no ACME-issued certificate exists in `<state_dir>/cert/current/`, reverseproxy first generates a listener-scoped self-signed bootstrap certificate.
- Reverseproxy starts TLS using that bootstrap certificate.
- ACME renewer then requests and hot-activates a CA-issued certificate via `reloadServerTlsFromPemFiles()`.

Key exports:
- `load`
- `Runtime`
- `CanonicalIr`
- `validateCanonicalIr`
- `RuntimeSnapshot`
- `Orchestrator`
- `ApplyStage`
- `OrchestratorEvent`

## Testing

- Full reverseproxy module tests: `zig build test-reverseproxy`
- Cross-component reverseproxy integration tests: `zig build test-reverseproxy-integration`

## Operator Runbook (foundation slice)

1. **Dry-run** candidate via IR/DSL validation and equivalence checks.
2. **Apply** via orchestrator (`build -> admit -> activate`).
3. **Monitor** during guard window (`GuardWindowMonitor`) against threshold profile.
4. **Rollback** automatically on critical breach, or manually to last-known-good.
5. **Safe mode** is entered if rollback cannot be completed.

## Alerting / SLO guardrails

Track at minimum:
- policy reject and fail-closed counts
- backpressure timeout counts
- drain timeout force-retire counts
- rollback/safe-mode transition events

Threshold profile definitions:
- `serval-reverseproxy/threshold-profiles.json`
- `serval-reverseproxy/threshold-profiles.md`

These files must remain in parity.

## Notes

- Validation is deterministic by input order.
- Validation does not mutate candidate IR.
- Activation keeps prior generation in draining state until explicit retire path.
