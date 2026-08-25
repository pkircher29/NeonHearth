# M6 Network Doctor service contracts

Locked 2026-08-24 so the Doctor UI and the service wiring can build in
parallel. The wire shapes ARE the `lattice-doctor` public types (all serde
snake_case + ToSchema): `DiagnosticReport`, `CheckResult`, `Measurement`,
`Diagnosis`, `RepairPlan`, `RepairReport`, `Verification`, `RollbackOutcome`,
`RepairEvent`. The service adds only thin envelopes below; it never reshapes
the domain types.

## Routes (bearer-authenticated, loopback, like every route)

- `POST /api/v1/doctor/run` — runs one bounded diagnostic pass through the
  service's probe transport. Response:
  `{ run_id, started_at, report: DiagnosticReport,
     findings: [{ diagnosis: Diagnosis, plan: RepairPlan }] }`.
  Concurrent runs are refused with 409 (one diagnostic at a time).
- `GET /api/v1/doctor/report` — the latest completed run (same envelope), or
  204 when none has run.
- `POST /api/v1/doctor/approvals` — body `{ diagnosis_kind }`. Mints an
  approval for exactly one approval-required repair from the latest run:
  `{ approval_id, expires_at }` (10-minute expiry, single-use). 404 when the
  latest run has no such approval-required plan.
- `POST /api/v1/doctor/repair` — body `{ diagnosis_kind, approval_id? }`.
  Executes the plan from the LATEST run only: safe-automatic plans need no
  approval id; approval-required plans require a live, unused, matching
  approval id (403 otherwise); guided/observation plans are never executable
  (400). Response: `{ repair: RepairReport }` including verification
  before/after values and the rollback outcome. Every execution appends to
  the audit log (category `doctor_action`).

## UI obligations (checklist N5)

The Doctor view shows, per finding: the diagnosis with its evidence
measurements (values + units) and confidence, the impact statement, the
repair class with its approval state, an in-flight progress state, the
verification verdict with before/after values, and the rollback result when
one happened. Approval-required repairs get a two-step flow (request approval
→ confirm execute). Guided plans render their steps as instructions with no
execute button. Nothing in the UI may present an unverified repair as
successful.
