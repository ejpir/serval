# HTTP/2 RFC 9113 Compliance Matrix (Serval)

Last updated: 2026-03-12

This matrix tracks **actual implementation status** versus RFC 9113 requirements.

Status legend:
- ✅ implemented and covered by tests
- ⚠ partial / bounded subset only
- ❌ missing (or currently non-compliant)

Related execution plan:
- `docs/plans/2026-03-13-generic-tls-h2-wiring-plan.md`

## Supported profile (current)

Serval currently has strong coverage for:
- cleartext prior-knowledge HTTP/2 (`h2c`) for terminated runtime tests
- cleartext `Upgrade: h2c`
- gRPC-oriented stream-aware bridge behavior for `.h2c` and `.h2` upstreams
- local cleartext and TLS conformance execution (`h2spec`) now green at 145/145 each (0 skipped)

Mixed-offer frontend policy remains conservative (`http/1.1` preferred when client offers both `http/1.1` and `h2`) until broader mixed-traffic rollout hardening is complete.

---

## RFC 9113 Matrix

| RFC 9113 area | Requirement | Status | Evidence | Gap / blocker |
|---|---|---:|---|---|
| §3.2 Starting HTTP/2 for `https` | ALPN negotiation + immediate HTTP/2 behavior on negotiated `h2` | ⚠ | TLS ALPN `h2` now dispatches to terminated h2 runtime; dedicated TLS conformance target passes `h2spec` 145/145 | Mixed-offer policy remains conservative (`http/1.1` preferred) pending broader rollout hardening |
| §3.3 Starting HTTP/2 for `http` | Prior knowledge preface handling | ✅ | `serval-h2/preface.zig`; `serval-server/h2/server.zig` + integration terminated-h2 tests | — |
| §3.2/§3.3 | `Upgrade: h2c` validation and switch | ✅ | `serval-h2/upgrade.zig`; main-server upgrade dispatch tests in `integration/tests.zig` | — |
| §4.1 Frame format | 9-byte header parse/build, reserved bit checks | ✅ | `serval-h2/frame.zig` | — |
| §4.1 Unknown frame types | Unknown frame types MUST be ignored | ✅ | `serval-h2/frame.zig` maps unknown frame types to `.extension`; client/server runtimes ignore `.extension` frames | — |
| §4.2 Frame size | Enforce max frame size and per-frame fixed sizes | ✅ | Global max enforced in frame/control parsers; terminated server response DATA is peer-max aware; outbound HEADERS/trailers now emit bounded HEADERS+CONTINUATION fragments (client request path and terminated server response path) | — |
| §4.3 Header compression | HPACK decode, bounded dynamic table, Huffman | ✅ | `serval-h2/hpack.zig` tests cover dynamic table + Huffman + fuzz corpus | — |
| §5.1 Streams | Stream id rules, parity, monotonicity | ✅ | `serval-h2/stream.zig` | — |
| §5.1/§5.2 Stream lifecycle | open/half-closed/closed and transition enforcement | ✅ | `serval-h2/stream.zig`, `serval-server/h2/connection.zig` | — |
| §5.2 Multiplexing | Concurrent streams on one connection | ✅ | integration tests for interleaved streams and churn (`integration/tests.zig`) | — |
| §5.2 Stream errors | RST_STREAM propagation and fail-closed behavior | ✅ | `serval-server/h2/runtime.zig`; proxy bridge reset tests | — |
| §5.3 Priority | PRIORITY frame parsing/handling | ⚠ | PRIORITY accepted and ignored safely (`serval-server/h2/runtime.zig`) | Prioritization semantics intentionally not implemented |
| §5.4 Error handling | GOAWAY/RST_STREAM protocol mapping | ⚠ | Runtime/server maps protocol vs flow-control errors | Mapping coverage needs h2spec confirmation across all edge cases |
| §5.5 Extensibility | Extension frame tolerance | ✅ | Unknown extension frame types are tolerated and ignored in receive paths | — |
| §6.1 DATA | stream-id != 0, flow-control accounting, END_STREAM | ✅ | `serval-server/h2/runtime.zig`; flow-control tests | — |
| §6.2 HEADERS + CONTINUATION | Sequencing, bounded reassembly | ✅ | `serval-server/h2/runtime.zig`; continuation tests | — |
| §6.3 PRIORITY | Frame length/stream-id validity | ✅ | `serval-server/h2/runtime.zig` | — |
| §6.4 RST_STREAM | Frame parse/build + state updates | ✅ | `serval-h2/control.zig`; runtime handling | — |
| §6.5 SETTINGS | parse/validate/apply + ACK rules | ✅ | `serval-h2/settings.zig`; runtime ACK flow | — |
| §6.6 PUSH_PROMISE | Proper handling/rejection | ⚠ | Explicit unsupported path (`UnsupportedPushPromise`) | Policy is fail-closed, but h2spec verification pending |
| §6.7 PING | ACK behavior and opaque payload | ✅ | `serval-h2/control.zig`; runtime send_ping_ack tests | — |
| §6.8 GOAWAY | parse/build + last_stream_id behavior | ✅ | control parser + bridge tests for `last_stream_id` behavior | — |
| §6.9 WINDOW_UPDATE | parse/build + overflow/zero increment checks | ✅ | `serval-h2/control.zig`; `flow_control.zig` | — |
| §8.1.2 Request pseudo-headers | Required pseudo-headers and request validity | ✅ | `serval-h2/request.zig` enforces pseudo-header ordering, duplicate rejection, mandatory pseudo fields, and CONNECT-specific constraints | — |
| §8.1.2.2 Connection-specific fields | Connection-specific fields forbidden in h2 | ✅ | `serval-h2/request.zig` rejects connection-specific headers in generic h2 request decode path; `upgrade.zig` strips/rejects and now lowercases forwarded regular headers | — |
| §8.1.2.3 TE | `te` restricted to `trailers` | ✅ | `serval-h2/request.zig` enforces trailers-only `te`; strict checks also present in upgrade/gRPC validation paths | — |
| §8.1.2 Malformed request handling | Deterministic protocol errors on malformed headers | ✅ | Runtime + parser tightening verified by h2spec on cleartext and TLS conformance targets (145/145 each) | — |

---

## Current Critical Blockers

### B1 — Unknown frame type handling
- Resolved in current slice: unknown frame types are now mapped to `.extension` and ignored by runtime receive paths.

### B2 — ALPN `h2` + TLS frontend dispatch hardening
- Implemented: when ALPN negotiates `h2` and handler provides terminated-h2 hooks, frontend now dispatches directly into the terminated h2 runtime over TLS.
- Conformance evidence: dedicated TLS target now passes `h2spec` 145/145 (0 skipped, 0 failed).
- Safety mitigation remains active for mixed offers: ALPN callback still prefers `http/1.1` over `h2` when both are offered.
- Remaining scope is rollout/policy hardening for mixed-client traffic profiles.

### B3 — Request pseudo-header validation
- Resolved in current slice: ordering/duplicate/mandatory pseudo-header and CONNECT rules are enforced in generic h2 request decode.

### B4 — Connection-specific header enforcement on generic h2 request decode path
- Resolved in current slice: generic decode now rejects connection-specific headers; upgrade translation path remains strict and lowercases forwarded regular header names.

### B5 — Peer-advertised max frame size handling
- Resolved in current slice: outbound request HEADERS and terminated-runtime response HEADERS/trailers emit bounded HEADERS+CONTINUATION fragments; response DATA chunking is peer-max aware.

### B6 — External protocol conformance automation
- Implemented: `integration/h2_conformance_runner.sh` for h2spec/nghttp execution and `integration/h2_conformance_ci.sh` for server orchestration + gate execution.
- CI wiring complete in `.github/workflows/ci.yml`: installs `h2spec` + `nghttp2-client`, then runs `integration/h2_conformance_ci.sh`.
- Local and CI-oriented gate now exercise both cleartext and TLS conformance targets.

---

## Immediate next compliance actions

1. Keep mixed-offer ALPN rollout conservative until mixed-traffic hardening criteria are complete.
2. Keep h2spec/nghttp conformance gate required for protocol-affecting h2 changes.
3. Expand CI evidence artifacts (logs/JUnit) for faster triage when conformance regressions occur.
