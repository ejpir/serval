# Session Context

## User Prompts

### Prompt 1

• Findings (ordered by severity)

  1. High: acquire() can return dead/stale sockets without liveness check

  - serval-pool/pool.zig:214 returns pooled connections after age/idle checks only.
  - serval-pool/pool.zig:108 has isUnusable() (poll-based stale detection) but it is never used in SimplePool.acquire.
  - Impact: recently half-closed/reset upstream sockets can be reused, causing avoidable request failures/retries.

  2. High: checked-out accounting is not semantically correct for “c...

### Prompt 2

[Request interrupted by user]

### Prompt 3

cont

### Prompt 4

[Request interrupted by user]

### Prompt 5

just verify and let me know what the plan is

### Prompt 6

verify:

• Verified. The plan is strong, but I’d adjust 4 points before implementation:

  1. Finding 1 needs metric/order + lock discipline

  - Do liveness check before final hit/miss metric emission.
  - If unusable: close outside lock, but decrement checked_out_counts under lock.
  - Emit .acquire_evicted and then .acquire_miss (since caller got no connection).

  2. Finding 2 is correct, but update docs semantics

  - from_pool is a good fix.
  - Also update README wording: checked_out ...

### Prompt 7

[Request interrupted by user]

