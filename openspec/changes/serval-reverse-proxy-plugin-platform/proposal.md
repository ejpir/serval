## Why

Serval already has strong composition primitives (`Handler` hooks, `Router` for virtual hosts/path, `ShieldedHandler` wrapper pattern), but a Caddy-class reverse proxy platform needs a first-class plugin story for:

- virtual hosts + route-level policy composition
- WAF/filter/caching style plug-in behavior
- **streaming-only body transforms** (no full-body buffering)
- deterministic ordering, admission control, and safe operations

Today, hooks are excellent for inspection and reject/short-circuit policy, but not a complete transform pipeline contract for production-grade request/response body mutation across h1/h2.

## What Changes

This change introduces a unified plugin platform design and requirements for Serval:

1. **Plugin composition model** for reverse proxy features (vhosts, WAF, filters, cache taps)
2. **Streaming transform mechanics contract** for request/response body transformation
3. **Filter SDK boundary** so user Zig code can interact only with approved hook surfaces
4. **Manifest + admission system** with deterministic ordering and strict hard caps
5. **Operator safety model** for dry-run admission, atomic apply, observability, and rollback
6. **Config DSL (v2-now)** that compiles into the same canonical schema/IR and admission pipeline

## Scope

In scope:
- Design + requirements for chain composition and transform lifecycle
- h1/h2 semantic parity requirements for streaming transforms
- failure model (`fail_open`/`fail_closed`, sticky bypass behavior)
- hard resource limits and admission gates
- route/global chain merge rules and mandatory plugin policy
- config DSL frontend and compiler requirements targeting canonical IR

Out of scope (explicitly deferred):
- dynamic runtime ABI plugin loading
- websocket/CONNECT payload transforms
- automatic decompress/recompress body pipelines
- advanced DSL language features (macros/functions/conditionals)

## Impact

- Establishes the architecture for a Caddy-like extensible reverse proxy in Serval
- Preserves Serval layer boundaries (strategy vs mechanics)
- Enables user-authored Zig filters without exposing unsafe internals
- Standardizes config inputs through one canonical IR and one admission engine
- Reduces operational risk via strict admission and atomic rollout rules
