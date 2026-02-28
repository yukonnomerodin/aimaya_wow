# R6 Perf Budget Baseline (2026-02-28)

Calibration was executed with:
1. runs: `5`
2. iterations per run: `20`
3. parallelism: `4`
4. allow failures: `4`
5. hypothesis: `M2-R5-PERF-GATE-HOTPATH-PARALLEL-104`

Observed maxima:
1. max observed `p50`: `403 ms`
2. max observed `p95`: `481 ms`
3. max observed `max`: `532 ms`

Applied safety multipliers:
1. `p50 x 1.20`
2. `p95 x 1.20`
3. `max x 1.15`

Recommended gates:
1. `p50 <= 500 ms` (calculated 484, rounded up)
2. `p95 <= 600 ms` (calculated 578, rounded up)
3. `max <= 620 ms` (calculated 612, rounded up)

These values are used as default inputs in `.github/workflows/worldgateway-perf-gate.yml`.
