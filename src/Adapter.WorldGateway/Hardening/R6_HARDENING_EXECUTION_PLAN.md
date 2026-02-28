# R6 Hardening Execution Plan (Ordered 1 -> 5)

## Scope
This plan is the execution contract for the next phase after pack 104.
The order is mandatory and each step has explicit acceptance criteria.

## 1) Lock Perf Budgets In CI
### Why
Single-run latency is noisy; scaling decisions must be based on stable budget gates.

### Deliverables
1. Batch perf-gate runner with `p50/p95` checks and failure budget.
2. CI workflow that can run perf gate on-demand.
3. Reproducible JSON summary for each run.

### Acceptance
1. Perf script returns non-zero when gates fail.
2. CI workflow can run with custom thresholds.
3. Summary includes `successful_iterations`, `failed_attempts`, `p50_ms`, `p95_ms`, `gate_passed`.

## 2) Harden Startup + Transport Failure Recovery
### Why
Most operational regressions are startup races and unclear transport-failure reason chains.

### Deliverables
1. Startup script hardening with explicit retry budget and deterministic listener readiness checks.
2. Transport loop diagnostics improvement for first-failure reason visibility and cancellation/fault separation.

### Acceptance
1. Gateway start script reports clear root cause on startup failure.
2. Transport logs identify first-completed relay side and fault/cancel status deterministically.

## 3) Harden DB/Auth Bridge Path
### Why
Auth bridge is a critical path; DB degradation must fail predictably and quickly.

### Deliverables
1. Explicit bounded DB bridge timeout.
2. Controlled rejection path with stable temporal invariants and evidence context.

### Acceptance
1. DB timeout produces deterministic rejection path (no hung connection).
2. Handshake report still contains valid failure classification.

## 4) Reduce Hot-Path Diagnostics Cost In Production Mode
### Why
Per-frame heavy diagnostics (hash/parity payload) increase CPU and allocations under load.

### Deliverables
1. Make heavy diagnostics conditional for production-safe mode.
2. Preserve first-frame corridor evidence required by handshake validation.

### Acceptance
1. `run_valid=true` and `boundary=9/9` remain stable.
2. Measurable p50/p95 improvement or reduced tail jitter under same parallel profile.

## 5) Enforce Scale Profiles (1/4/8/16) As Pre-Merge Gate
### Why
Bottlenecks appear at concurrency; single-connection checks are insufficient for scaling safety.

### Deliverables
1. Scale-profile runner for parallel levels `1,4,8,16`.
2. CI gate enforcing profile pass and latency budget by level.

### Acceptance
1. Each level emits summary with pass/fail status.
2. Pre-merge policy fails on any level breach.

## Step Execution Notes
1. Each step must be validated before moving to the next step.
2. Contract rotation (`HypothesisId`, `SingleChangedVariable`, `NextIsolationVariable`) is required per step package.
3. No behavioral rewrites outside the targeted step objective.
