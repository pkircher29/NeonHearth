# M6 remote access and integrations contracts

Locked 2026-08-24 for the Tailscale (T1–T4) and integrations (I1–I2) lanes.

## Tailscale private phone access (T1–T4)

- **Detection + Serve (T1)**: the service detects a running Tailscale daemon
  via the local socket/CLI (injected `TailscaleControl` trait; fake for
  tests) and configures **Serve** (private HTTPS inside the tailnet) to the
  loopback listener. The service never binds any non-loopback socket itself.
- **Funnel refusal (T2)**: any configuration path that would enable Funnel
  (public exposure) is refused with a typed error — there is no override
  flag. Requests carrying forwarded-identity headers (`Tailscale-User-*`,
  `X-Forwarded-*`) are stripped/ignored unless the peer is the loopback
  Serve proxy; identity from headers is NEVER used for authorization —
  bearer/session auth only.
- **Phone sessions (T3)**: pairing mints a device-bound session (opaque id +
  secret hash, device label, created/expires timestamps; default expiry 30
  days, sliding). High-impact actions (policy actions, doctor repairs,
  audit-module approval, plan-affecting writes) require step-up: a 6-digit
  PIN set at pairing (Argon2id-hashed) re-entered per high-impact action
  with a short grace window (5 min). Failed step-up attempts are rate
  limited and audited.
- **No replay (T4)**: command-carrying requests over a phone session include
  a client-generated `command_id` (uuid); the service keeps a bounded
  per-session dedup window and returns the original result for a replayed
  id instead of re-executing. WebSocket reconnects resume the event stream
  by sequence (existing snapshot/resume protocol) and never re-deliver
  commands.

## Integrations (I1–I2)

- **Scoped read-only events (I1)**: `POST /api/v1/integrations/tokens`
  (owner, bearer) mints a named integration token with an explicit scope
  set from {`devices:read`, `presence:read`, `bandwidth:read`,
  `policy:read`}; tokens are hash-stored, listable, revocable. A versioned
  read-only surface (`/api/v1/integrations/v1/...` GET endpoints + an SSE
  or long-poll event feed of the same envelopes) accepts ONLY integration
  tokens and serves ONLY data within scope. MQTT is out of scope for this
  release and recorded as pending.
- **Hard exclusions (I2)**: integration tokens can never reach router
  credentials, vault handles, audit-module execution, doctor repairs,
  drafts, or any mutating route — enforced by a distinct auth layer that
  rejects integration tokens outside `/api/v1/integrations/`, with tests
  proving each excluded surface refuses them.

Every minting/revocation and step-up failure is appended to the audit log
(category `approval` for pairings/tokens).
