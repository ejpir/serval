# Testing and Verification Standard

Serval changes require exhaustive verification, including error paths and failure recovery.

## Unit tests

For each function with logic:

- Success cases
- Error cases
- Boundary values (0, 1, max, max+1 where meaningful)
- Resource cleanup behavior

## Integration tests

Per module:

- Init/deinit lifecycle
- Integration with dependencies
- Concurrency behavior (if applicable)
- Resource limit behavior (timeouts, memory/fd constraints)

## Property/fuzz tests

Required for parsers/state machines where practical:

- Fuzz random malformed/valid inputs
- Assert invariants hold
- Cover key state transitions

## Performance/stress tests

For performance-sensitive code:

- Benchmark relevant percentiles (e.g., p50/p99)
- Stress under sustained load
- Profile memory/CPU where needed

## Verification checklist

- TigerStyle constraints re-checked
- Architecture/layer constraints preserved
- Module README updated if behavior changed
- `serval/ARCHITECTURE.md` still accurate
- Command results captured with exit codes

## Command baseline

```bash
zig build
zig build test
```
