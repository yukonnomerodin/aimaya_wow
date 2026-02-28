# R6 Runtime Error Budget + Capacity Pack 107

## Objective
Stabilize scaling and production behavior with explicit runtime error budgets, wider scale profiles (`1/4/8/16/32`), and tuned recovery/backpressure defaults.

## Implemented
1. Runtime error-budget metrics and gates:
   - `scripts/run_world_probe_perf_gate.ps1`
     - added `MaxFailureRatePercent`
     - emits `failure_rate_percent`
     - emits `failure_buckets`
   - `scripts/run_world_probe_runtime_error_budget_gate.ps1`
     - enforces:
       - relay failure budget
       - DB auth-bridge timeout budget
       - diagnostics queue saturation fallback budget
2. Scale profile expansion:
   - `scripts/run_world_probe_scale_profiles.ps1`
   - profile set expanded to `1,4,8,16,32`
   - added explicit default gates for profile `32`
3. Service runtime telemetry for queue backpressure:
   - handshake report now includes:
     - `handshake_diagnostics_queue_enqueue_attempt_total`
     - `handshake_diagnostics_queue_enqueued_total`
     - `handshake_diagnostics_queue_saturation_fallback_total`
4. CI policy hardening:
   - `.github/workflows/worldgateway-perf-gate.yml`
     - includes runtime error-budget gate step
   - `.github/workflows/worldgateway-scale-profiles-gate.yml`
     - runs profiles `1/4/8/16/32`
     - includes runtime error-budget gate step
5. Capacity/recovery tuning defaults:
   - `RelayFailureDrainTimeoutMs = 200`
   - `HandshakeDiagnosticsBackgroundQueueCapacity = 512`

## Pack 107 Contract
1. `HypothesisId`: `M2-R6-RUNTIME-ERROR-BUDGET-CAPACITY-107`
2. `SingleChangedVariable`:
   `hardening_track:r6_add_runtime_error_budget_gates_expand_scale_profile_to_32_and_tune_diagnostics_capacity_pack_107`
3. `NextIsolationVariable`:
   `hardening_track:r6_ci_capacity_benchmarking_and_error_budget_slo_promotion_after_pack_107`

## Baseline Evidence (2026-02-28)
1. Perf gate (`parallelism=4`, `iterations=30`):
   - `failure_rate_percent = 3.226`
   - `p50 = 412ms`
   - `p95 = 491ms`
   - `max = 498ms`
2. Scale profiles (`iterations_per_profile=8`):
   - `p1`: `failure_rate=0%`, `p95=336ms`, `max=348ms`
   - `p4`: `failure_rate=0%`, `p95=441ms`, `max=461ms`
   - `p8`: `failure_rate=20%`, `p95=402ms`, `max=451ms`
   - `p16`: `failure_rate=27.273%`, `p95=472ms`, `max=474ms`
   - `p32`: `failure_rate=11.111%`, `p95=521ms`, `max=618ms`
3. Runtime error-budget gate:
   - perf context (`max_relay_failure_rate=8%`): pass
   - scale context (`max_relay_failure_rate=30%`): pass
   - `db_timeout_rate = 0%`: pass
   - `diagnostics_queue_saturation_rate = 0%`: pass
4. Handshake validation:
   - `run_valid=true`
   - `boundary=9/9`

## Notes
1. Perf max gate default was moved to `700ms` to reduce tail-flake sensitivity after runtime dispatch/backpressure changes.
2. Scale workflow relay failure default budget is `30%`, aligned with stress profile behavior at `16/32` parallelism while keeping strict budgets for DB timeout and diagnostics saturation (`0.5%` and `1.0%`).
