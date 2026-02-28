# R6 Service Boundary + Recovery Pack 106

## Scope (Steps 1-4)
1. Service-boundary contract metadata + relay recovery policy wiring.
2. Contract tests for ACK gate, deferred flush, and DB/auth bridge boundaries.
3. Heavy handshake diagnostics dispatch via optional background channel mode.
4. PR SLO policy hardening: perf gate and scale gate both execute on pull requests.

## Implemented
1. Added WorldProxy config contract fields:
   - `ServiceBoundaryContractVersion`
   - `RelayFailureRecoveryPolicy`
   - `RelayFailureDrainTimeoutMs`
   - `HandshakeDiagnosticsDispatchMode`
   - `HandshakeDiagnosticsBackgroundQueueCapacity`
2. Added typed parsers/enums for recovery and diagnostics dispatch modes.
3. Added relay fault recovery policy application in transport loop with invariant evidence:
   - `relay_failure_recovery_policy_applied`
4. Added handshake report contract metadata fields:
   - `service_boundary_contract_version`
   - `relay_failure_recovery_policy`
   - `relay_failure_drain_timeout_ms`
   - `db_auth_bridge_timeout_ms`
   - `handshake_diagnostics_dispatch_mode`
5. Added asynchronous handshake report writer path:
   - bounded background channel
   - graceful drain on service shutdown
   - synchronous fallback when queue is saturated
6. Added/extended integration assertions for boundary contract:
   - ACK/deferred/db invariant presence
   - service-boundary/recovery metadata presence
7. Updated PR workflows:
   - `worldgateway-perf-gate.yml` now runs on `pull_request`
   - `worldgateway-scale-profiles-gate.yml` now uses robust event-input fallbacks on `pull_request` and `workflow_dispatch`

## Expected Outcome
1. Better operational scaling safety: service boundaries and recovery behavior are explicit in both startup telemetry and handshake artifacts.
2. Lower relay-path blocking risk from report I/O in production-mode runs.
3. Stronger merge guardrails: latency/scale SLO regressions fail PR checks automatically.
