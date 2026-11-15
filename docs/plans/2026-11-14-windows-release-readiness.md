# Windows release readiness

Paul approved the shipping assessment with "fix it all". Scope: repair the
identified dependency, delivery, first-run, capability and acceptance gaps.
Preserve existing WIP branches, customer state and published artifacts.

1. Restore dependency checks (root): review and update affected Rust/npm
   dependencies in `Cargo.toml`, `Cargo.lock`, `apps/desktop/package*.json`.
   Prefer compatible security patches; document any required upstream backport.
   Run advisory checks, compile and regression tests. Risk: medium/high for DB
   bindings; migration bytes must stay unchanged.
2. Correct first-run/data-source states (dashboard agent): `App.svelte`,
   `PulseView.svelte` and related components/tests. Reproduce contradictory
   pairing copy first, then expose actual source coverage and an actionable next
   step. Add browser coverage. Risk: medium; never label household totals as
   per-device traffic.
3. Reconcile Windows delivery (packaging agent): `packaging/**`,
   `scripts/package-home-hub.py`, release workflow and installer docs. Remove
   obsolete Npcap startup gating; produce the native launcher/collector/MQTT
   candidate from one source commit with pinned inputs and manifests. Preserve
   legacy state and prevent parallel runtimes. Root owns any required launcher
   compatibility checks. Risk: high; no installed-service modifications without
   an isolated acceptance environment.
4. Add reproducible acceptance/soak tooling (acceptance agent): bounded isolated
   test state, loopback listeners, no active household scans or physical controls,
   secure credentials and persistent truthful result reports. Inventory available
   clean VM and signing capabilities without exporting credentials. Risk: medium.
5. Integrate and verify (root): review diffs, run fmt/clippy, Rust workspace,
   web unit/type/build/browser checks and dependency gates; build a frozen native
   candidate, exercise the safe customer workflow, verify hashes and retain exact
   evidence. Start an actual isolated soak only from a verified candidate and
   report pending elapsed time honestly. Risk: medium.

Definition of done: concrete fixes and reproducible candidate exist with fresh
verification. A signed/general-release or clean-machine/hardware/72-hour claim
requires actual evidence; unavailable credentials/machines or elapsed time remain
explicit gates, not fabricated completion. No paid signing purchase or public
release is implied. Existing authorization permits implementation and reviewable
PRs; prepare everything before any final publishing decision.
