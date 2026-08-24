# M6/M7 software progress — evidence record

Recorded 2026-08-24, branch `claude/neonhearth-m5-home-twin`, Windows 11
development workstation. This record covers the M6 and M7 items completed in
this branch beyond the M5 evidence (`m5-evidence.md`). Items requiring real
hardware, clean machines, or long soaks are explicitly NOT claimed.

## Full-repository gates (this exact revision)

- `cargo fmt --all -- --check` — clean.
- `cargo deny check` — `advisories ok, bans ok, licenses ok, sources ok`
  (includes the new `argon2` dependency).
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo test --workspace` — exit 0, **99 suites, 824 tests passed, 0
  failed** (includes fixing three camera media tests that hardcoded Unix
  fixture paths and failed on the Windows release target, `75485a4`).
- apps/desktop: `npm test -- --run` — **177 passed**; `npm run check` —
  0 errors / 0 warnings; `npm run build` — success;
  `npx playwright test --config=e2e/playwright.config.ts` — **7 passed**.
- Environment quirks required on this machine (recorded in
  `docs/build/supply-chain.md`): prepend `C:\msys64\mingw64\bin` to PATH and
  `RUSTFLAGS=-L C:\Windows\System32\Npcap` for binaries linking capture.

## M6 — completed (fixture-proven)

- **N1–N4** `lattice-doctor` (`9afc552`): diagnostic dependency DAG with
  bounded, budgeted probes; typed diagnoses with evidence and confidence;
  repair classification where approval-required repairs are unconstructable
  without an approval token; snapshot→apply→verify→rollback executor with
  automatic rollback on regression, mid-apply failure, and unverifiable
  outcomes. 46 tests.
- **N5 + wiring** (`982cfeb`, `26e0792`): Doctor routes per the locked
  contract (single run at a time, minted single-use 10-minute approvals,
  guided plans never executable, every action audited or refused) and the
  Doctor view rendering evidence, confidence, impact, approval flow,
  progress, before/after verification, and rollback results honestly. The
  service probe transport answers only collector health and reports all
  network probes unsupported; the repair transport returns typed errors —
  nothing pretends success. 14 + 10 tests.
- **T1–T4** (`8e1fcb9`): Tailscale Serve to loopback with no funnel
  operation in the control trait and typed refusal when Funnel is detected;
  unconditional forwarded-identity header stripping; device-bound phone
  sessions (one-time secret, Argon2id PIN step-up with 5-minute grace,
  rate-limited lockout persisted across restarts); per-session command-id
  dedup returning stored results on replay. 18 tests.
- **I1–I2** (`8e1fcb9`): hash-stored scoped integration tokens valid only
  under the read-only versioned surface; rejected on 25 privileged routes
  including vault, doctor, drafts, and the owner WS. MQTT: pending, not
  built. 11 tests.
- **M6 gate — NOT claimed**: "away-from-home phone access works over the
  tailnet" requires a real tailnet and phone; the Doctor half (diagnosis +
  verified repair/rollback) is fixture-proven. The `SystemTailscaleControl`
  CLI path is parser-tested only.

## M7 — completed vs pending

- **RLS2** (`6beeb8b`): append-only SHA-256 hash-chained audit log with
  SQL-trigger-enforced immutability and anchor-based oldest-side retention;
  tamper detection tested at exact break indexes. 8 tests.
- **RLS3** (`6beeb8b`): integrity/foreign-key checks, atomic VACUUM INTO
  backups with verify-before-restore (restore consumes the pool handle),
  retention jobs, report-only disk pressure. 9 tests.
- **RLS6** (`2871804`): cargo-deny (clean, with 20 triaged RustSec ignores
  documented as open defects — notably wasmtime 27 sandbox-escape advisories
  whose fix is a semver-major bump), license allowlist, CI workflow,
  CycloneDX SBOM tooling. Reproducibility honestly unverified.
- **RLS13 — largely present, not checked**: the owner docs set
  (`docs/owner/`, `2742ff3`) covers getting started, identity, guard, home
  twin, cameras/security, privacy, troubleshooting with per-page pending
  footers; backup/restore has no owner-usable flow yet, so the item stays
  open.
- **RLS4/RLS5 — scaffolded, not complete** (`47aea65`): WiX MSI definition,
  configure script handling the empirical Npcap load-time-import reality,
  hardened systemd unit + nfpm packaging; `stage.ps1` verified end-to-end
  here including a smoke test of the staged binary (loopback-only listen,
  401 unauthenticated, healthy /api/v1/health). No MSI/deb/rpm has been
  built (no WiX/.NET SDK or nfpm on this machine) and no clean-machine
  install has occurred.
- **RLS1, RLS7–RLS12, RLS14, M7 gate — open**: vault rotation tests,
  artifact signing, performance budgets, chaos/recovery exercises, real W6
  and camera hardware acceptance, the 72-hour soak, and the acceptance
  matrix all require environments or time this workstation session cannot
  honestly provide.

## Also fixed on the Windows release target

- `271404c` — camera end-to-end canonicalized-path assertion and RTSP-proxy
  Linux-only imports (clippy) — the service suite and clippy now run fully
  green on Windows.

## Guard decision controls (M3 follow-through)

`dff6a2d` closed a gap found by the docs audit: the policy-action endpoint
existed but GuardView was read-only. Owner Approve/Reject/Quarantine/Extend
controls now mirror the domain rules (protections, one-use extension, undo
availability) with two-step confirms; success is applied only by the live
event stream. 11 tests.
