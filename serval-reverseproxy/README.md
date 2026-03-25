# serval-reverseproxy

`serval-reverseproxy` provides the reverse-proxy runtime foundation for Serval's plugin platform.

Scope in this slice:
- Canonical IR runtime types (`ir.zig`)
- Deterministic IR validation diagnostics (stage + object + reason)
- Deterministic chain ordering and composition (`ordering.zig`, `composition.zig`)
- Header-phase policy execution contract (`policy.zig`)
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

Route/listener binding:
- Routes may declare `listener=<listener-id>` for explicit listener scoping.
- If omitted, runtime defaults route binding to the first declared listener.

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
