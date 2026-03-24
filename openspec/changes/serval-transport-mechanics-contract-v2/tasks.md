## 1. Define and document unified h1/h2 seam contract

- [ ] 1.1 Add contract section to architecture docs with explicit ownership split.
- [ ] 1.2 Add contract flow diagram to `serval/ARCHITECTURE.md` and module READMEs.
- [ ] 1.3 Confirm no layer ownership changes are implied.

## 2. Encapsulate h2 bridge mechanics in `serval-proxy`

- [ ] 2.1 Add/complete proxy-owned action polling API (`poll_next_action` equivalent) with bounded fairness.
- [ ] 2.2 Remove server direct access to bridge binding-table internals.
- [ ] 2.3 Keep explicit mapped action model (headers/data/trailers/reset/close).
- [ ] 2.4 Preserve GOAWAY/session-generation behavior and existing semantics.

## 3. Align generic h2 forwarding ownership with h1 forwarder model

- [ ] 3.1 Identify forwarding mechanics currently implemented in server frontend that belong in proxy.
- [ ] 3.2 Move/adapterize mechanics into proxy-owned helpers while keeping server as orchestration.
- [ ] 3.3 Keep request-class policy explicit in server adapter layer.

## 4. TigerStyle + Zig-idiomatic seam verification

- [ ] 4.1 Assertions/invariants present in seam-facing non-trivial functions.
- [ ] 4.2 All loops/scans bounded with explicit caps/timeouts.
- [ ] 4.3 No `catch {}` in touched code paths.
- [ ] 4.4 Explicit integer widths used where practical for ids/counters.
- [ ] 4.5 Lifecycle cleanup verified for background readers/tasks.

## 5. Tests and conformance gates

- [ ] 5.1 Add tests that fail if server depends on bridge internals.
- [ ] 5.2 Keep h1/h2 parity tests green for routing, body forwarding, reset/close paths.
- [ ] 5.3 Keep gRPC/non-gRPC mixed-stream completion behavior coverage green.
- [ ] 5.4 Run architecture conformance scripts for layers/exports/hooks/reuse.
- [ ] 5.5 Run verification commands and record results (`zig build`, `zig build test`, targeted h2/grpc integration suites).

## 6. Documentation consistency

- [ ] 6.1 Update `docs/architecture/h2-bridge.md` boundary language to match contract.
- [ ] 6.2 Update `serval-server/README.md` and `serval-proxy/README.md` API ownership notes.
- [ ] 6.3 Ensure root architecture text does not overclaim generic h2 behavior.
