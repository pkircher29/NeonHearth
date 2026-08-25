# M3 live UI, policy, and W6 evidence

Recorded: 2026-08-23

This record supports the simulated M3 gate. It does not claim that a production
Acer Predator W6 transport has been discovered or enabled.

## Delivered behavior

- The responsive Pulse, Devices, Guard, Cameras, Home, Doctor, and Settings
  navigation is available on desktop and phone layouts.
- Pulse renders animated throughput, protocol mix, top-device, coverage, and
  event views. Bandwidth intensity uses blue, cyan, gold, and pink tiers while
  policy/risk remains separately labelled.
- Guard consumes typed live policy events, preserves lifecycle state through
  resync, exposes pending delivery truth, and remounts a changed policy card so
  its lifecycle animation runs without navigation.
- Reduced-motion and mobile navigation paths have automated coverage.
- Policy deadlines are anchored to the immutable first service run and device
  first-seen time. The baseline cohort, 48-hour unknown deadline, seven-day
  automatic-identification confirmation window, danger quarantine, and
  protected-device self-lockout rules are durable and tested.
- Pending policy decisions persist the exact event. Snapshots prefer the newest
  exact pending decision over an older acknowledged one; upgraded legacy rows
  without an exact event fail closed as manual-required with no claimed undo.
- Verified Quarantine and PermanentBan decisions derive effective `blocked`
  presence. Discovery cannot overwrite that state; only a verified release can.

## W6 fixture evidence

The injectable W6 adapter has a trusted exact fingerprint and capability
profile, bounded session renewal, pre-mutation state checkpointing, exact
read-back verification, capacity reporting, and durable restore state.

The simulated mappings are:

| Policy action | Advertised W6 capability | Success condition |
|---|---|---|
| Quarantine | `deny_internet` | Exact post-mutation read-back |
| Permanent ban | `persistent_filter` | Exact entry/read-back within the 32-entry capacity |

Crash recovery covers mutation-before-publication and
publication-before-database-acknowledgement for both actions. Tests prove one
physical apply, causal marker recovery, exact old-decision publication, and no
duplicate apply. Immediate owner approval during that window performs one
verified restore, records the unblock, and clears durable retry state. Manual,
failed, or indeterminate outcomes remain visibly blocked and retryable rather
than being reported as successful.

## Verification

Fresh M3 gates at commit `d767da3`:

- `cargo fmt --all -- --check`
- `cargo test --workspace --all-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Desktop Vitest: 49 tests passed.
- Guard Playwright: 2 browser tests passed.
- Svelte check: 0 errors and 0 warnings.
- Production desktop build passed.
- Independent W6 spec review: PASS.
- Independent policy/store/UI spec review: PASS.

Live browser evidence:

- [Desktop Guard lifecycle](../../output/playwright/neonhearth-guard-live-desktop.png)
- [Phone Guard lifecycle](../../output/playwright/neonhearth-guard-live-mobile.png)

## Honest hardware boundary

W1, the sanitized owner-authorized W6 traffic capture, is still pending. No
production Acer endpoint, protocol, credential, or capability was guessed, and
no real W6 mutation was performed. The main runtime therefore remains on the
manual-required actuator. Real W6 enablement requires an owner-configured,
sanitized compatibility fixture followed by protected-device-safe read-back and
capacity acceptance.

The separate M2 real-device departure/rejoin observation also remains pending;
the running native Windows collector is healthy, but cache manipulation is not
accepted as physical departure evidence.
