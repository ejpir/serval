# Threshold Profiles

The following guard-window profiles must remain in parity with `threshold-profiles.json`.

## strict
- `guard_window_ns`: `30000000000`
- `max_error_rate_milli`: `10`
- `max_fail_closed_count`: `5`

## balanced
- `guard_window_ns`: `60000000000`
- `max_error_rate_milli`: `25`
- `max_fail_closed_count`: `20`

## lenient
- `guard_window_ns`: `120000000000`
- `max_error_rate_milli`: `50`
- `max_fail_closed_count`: `100`
