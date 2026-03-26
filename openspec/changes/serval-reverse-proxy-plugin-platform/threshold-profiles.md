# Rollout Threshold Profiles (Initial Defaults)

This document defines initial guard-window and auto-rollback thresholds for plugin-chain activation in `serval-reverse-proxy`.

These are starter defaults intended for early production hardening and should be tuned with real traffic baselines.

---

## 1) Guard Window Defaults

- **Canary guard window:** 5 minutes
- **Production guard window:** 10 minutes
- Evaluation buckets:
  - 30-second rolling window (fast spike detection)
  - 60-second rolling window (sustained regression detection)

---

## 2) Auto-Rollback Thresholds

| Signal | Canary Trigger | Production Trigger | Notes |
|---|---:|---:|---|
| HTTP 5xx rate | `>2x baseline` **and** `>1.5%` absolute for 60s | `>1.5x baseline` **and** `>1.0%` absolute for 60s | Require relative + absolute to avoid low-volume false positives |
| `chain_abort_rate` | `>0.2%` requests for 30s | `>0.1%` requests for 30s | Direct plugin pipeline health signal |
| `fail_closed_rate` | `>0.5%` for 30s | `>0.25%` for 30s | Detect over-strict filter behavior |
| Backpressure timeouts | `>=5/min` | `>=2/min` | Indicates downstream/transform pressure |
| Expansion budget violations | `>=10/min` | `>=3/min` | Common transform misconfiguration signal |
| CPU budget violations | `>=20/min` | `>=5/min` | Hot-path plugin cost regression signal |
| p99 latency regression | `>35%` over baseline for 5 min | `>20%` over baseline for 5 min | Sustained impact guard |
| h2 reset anomaly | `>2x baseline` and `>0.5%` streams | `>1.5x baseline` and `>0.3%` streams | Mid-stream termination signal |

---

## 3) Immediate Hard-Stop Rollback Triggers

Any one of the following triggers immediate rollback without waiting for guard-window aggregation:

1. Runtime invariant violation / panic / critical internal fault
2. Listener health drops below minimum serving threshold after activation
3. Mandatory baseline security chain is missing after activation (should be impossible under admission)

---

## 4) Safe-Mode Escalation (Rollback Failure)

Enter safe mode if:

- a rollback attempt fails once, **or**
- two rollback attempts fail within 2 minutes

Safe mode behavior:

1. Freeze new applies
2. Disable optional plugin chains where policy allows
3. Preserve mandatory baseline security controls
4. Emit critical diagnostics and page on-call

---

## 5) Baseline Computation Defaults

Use prior stable generation metrics:

- Baseline window: previous 30 minutes
- Aggregation: median (robust to spikes)
- Exclude rollout windows from baseline calculation
- Require minimum traffic floor before auto actions (recommended: 200 req/min)

If traffic floor is not met, degrade to conservative manual approval or widened windows.

---

## 6) Tuning Guidance

- Start with production profile in strict environments.
- Tighten thresholds only after at least 1–2 weeks of stable telemetry.
- Re-evaluate thresholds per route class (API, static, streaming-heavy workloads).
- Keep threshold changes versioned and reviewed alongside rollout policy updates.
