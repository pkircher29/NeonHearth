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
  durable per-session record (SQLite, `phone_command_replays`) and returns the
  original result for a replayed id instead of re-executing. The record is
  claimed before the handler runs, bound to the method, URI and body, and
  survives restart. Concurrent in-flight duplicates wait for the original
  result. A changed payload, or a claim whose handler never finished
  (crash, timeout, disconnect), returns 409; clients must refresh state before
  deciding whether to issue a new command. Reservations remain for the session
  lifetime: only the stored response bodies of the oldest settled commands are
  evicted, never the id. WebSocket reconnects resume the event stream
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

## Hardening amendments (security review)

- **PIN budget is reserved, not charged after the fact.** A step-up attempt
  reserves one of the five per-window attempts in a single atomic statement
  *before* the PIN is evaluated; a request that cannot reserve is refused
  (429) unevaluated, and a correct PIN never overrides a lock. PIN hashing and
  verification run on the blocking pool behind a two-permit gate.
- **Commands run at most once.** A mutating phone request writes a durable
  claim keyed `(session, command_id)` and bound to `(method, target, body)`
  before the handler runs, and completes it with the response afterwards. The
  claim survives a restart; a duplicate gets the stored response (any status,
  including 5xx), an id reused for a different request gets 409, and a claim
  whose handler never finished (crash, timeout, disconnect) gets 409 "outcome
  unknown" instead of a second execution.
- **Sessions are bounded.** Sliding expiry never passes an absolute 180-day
  age; revoked or expired sessions are never touched back to life, and the
  store exposes `purge_dead_phone_sessions` for the maintenance task.
- **Sockets follow their principal.** An event ticket records the principal it
  was issued to (quota: 8 outstanding per principal, 64 overall). A phone
  socket closes immediately when its session is revoked (broadcast) and
  re-validates against storage every 30 s as a backstop. Sockets are capped
  (32), pinged, closed when idle (60 s), limited in lifetime (1 h, clients
  resume by sequence), bounded in write time (10 s) and in client message size
  (1 KiB).
- **Host allowlist.** `Host` must be a loopback name on the bound port (plus
  the Vite dev/preview ports), or the daemon-reported tailnet name; anything
  else is 403 even with a matching `Origin` (DNS rebinding). Requests bearing
  the `Tailscale-Funnel-Request` header are refused (header name unverified
  against live Funnel traffic).
- **Audit attribution.** Remote-access audit rows record `actor = phone` with
  the session id for phone-initiated actions.
- **Owner token.** `POST /api/v1/service/token/rotate` (owner only) replaces
  the token; the new value is persisted to `<state>/owner-token`, which wins
  over `LATTICE_SERVICE_TOKEN` at the next start. The environment variable is
  removed from the process at startup so children never inherit it.
