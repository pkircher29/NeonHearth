# Guard and policy

## The approval model in one look

```text
first seen
   |
   +-- in the first-run 48-hour baseline ------> exempt from age deadlines
   |
   +-- high-confidence danger ----------------> quarantine requested now
   |
   +-- automatically identified (>= 0.85,
   |     two independent families) -----------> confirm within 7 days of first seen
   |
   +-- still unknown ---------------------------> quarantine due 48 hours after first seen

you approve  -> visible, no deadline
you reject   -> permanent ban requested
you quarantine -> quarantine requested
deadline passes -> quarantine requested until you decide
```

All deadlines are anchored to the device's immutable first-seen time and the
immutable first service run. A device being offline does not pause its
countdown; an expired rule simply applies when it returns.

## Baseline exemption

Devices first seen during the 48 hours after the service's very first start
are baseline-exempt: no age-based deadline ever fires for them. They stay
fully visible for naming and approval. Exemption does **not** protect a
device that shows high-confidence dangerous behavior — danger outranks
baseline.

## The unknown-device 48 hours

A post-baseline device that NeonHearth cannot automatically identify gets 48
hours from first sight. The Guard view shows the deadline, and warnings
appear at 24 hours, 6 hours, and 1 hour before it. If the deadline passes
without your decision, a quarantine is requested — not a ban; approving the
device later releases it.

## The 7-day confirmation window

If NeonHearth automatically identifies a device (vendor and class at 0.85+
confidence from two independent evidence families), the deadline extends to
7 days from first seen. Identification buys time; it never authorizes the
device. Only your approval does that.

## Your decisions

- **Approve** — the device is welcome; deadlines stop. Approving a device
  that is currently blocked also schedules a verified release, with retry if
  the router cannot confirm immediately.
- **Reject** — a permanent ban is requested.
- **Quarantine** — you can quarantine any device manually at any time.
- **Extend once** — one owner-authorized absolute extension of a deadline is
  supported; the store enforces that it is single-use.

Danger overrides Pending *and* Approved: a high-confidence danger signal
(0.90+ with concrete evidence) requests immediate quarantine even for a
device you previously approved.

## Protected devices

The router, the collector machine, the paired administrator phone, and any
device you designate as a safety device are protected from automated
enforcement. When policy would otherwise quarantine one of them — even for
danger — it instead raises **owner attention** and takes no automatic
action. NeonHearth will not saw off the branch you are both sitting on.

## What enforcement actually does

Enforcement is reported with four honest statuses: *not requested*,
*verified*, *manual required*, and *failed*. A device is shown as blocked
**only after read-back verification at the router** — never on hope.

On the supported Acer Predator Connect W6 mapping:

- **Quarantine** maps to the router's **Internet block** (`deny_internet`):
  the device loses internet access at the router. It can still associate
  with your Wi-Fi and may still reach LAN neighbors. This is *not* a Wi-Fi
  kick or deauthentication, and NeonHearth never describes it as one.
- **Permanent ban** maps to the router's **persistent MAC filter**
  (`persistent_filter`), which is limited to 32 entries. NeonHearth checks
  capacity before claiming a ban and refuses to claim one it could not
  install.

**Current build:** the W6 connector is fully verified against fixtures, but
it is intentionally not enabled in the live service until an
owner-authorized, sanitized capture of the real router interface exists. In
this build every enforcement request therefore resolves to **manual
required**: the Guard card shows exactly that, keeps the device's state
truthful, and the action stays retryable. Nothing is ever displayed as
blocked without router verification.

## Undo

Each Guard card shows whether owner undo is available. Before mutating the
router, the connector checkpoints the previous state; a verified undo
restores it. If the service crashes mid-action, recovery applies the action
exactly once, publishes the true old decision, and never double-applies. An
approval given during that window performs one verified restore and records
the unblock. Ambiguous outcomes stay visibly blocked and retryable rather
than being reported as success.

## Not yet available

- Live W6 router enforcement (fixture-verified only; awaiting the
  owner-authorized compatibility capture). Until then all actions are
  manual-required.
- Wi-Fi kick / association ban. The W6's documented interface does not
  verify these capabilities, so NeonHearth will not offer or claim them.
- In-app buttons for approve / reject / extend / quarantine. The decisions
  exist as authenticated service API actions and Guard displays their full
  lifecycle, but the click-to-decide controls are not wired into the app
  yet.
- Owner-configurable deadline lengths and danger thresholds (current values
  are fixed: 48 h / 7 d / 0.85 / 0.90).
