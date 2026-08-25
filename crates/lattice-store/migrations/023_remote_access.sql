-- M6 remote access (T3) and integrations (I1): phone pairing sessions and
-- scoped read-only integration tokens.
--
-- Secrets are never stored: phone_sessions.secret_hash and
-- integration_tokens.token_hash hold SHA-256 hex digests of high-entropy
-- random secrets, and phone_sessions.pin_hash holds an Argon2id PHC string
-- for the low-entropy 6-digit step-up PIN. Step-up grace and PIN rate-limit
-- state live on the session row so lockouts survive a service restart.

CREATE TABLE phone_sessions (
    id TEXT PRIMARY KEY NOT NULL CHECK(length(id) = 36),
    secret_hash TEXT NOT NULL
        CHECK(length(secret_hash) = 64)
        CHECK(lower(secret_hash) = secret_hash)
        CHECK(secret_hash NOT GLOB '*[^0-9a-f]*'),
    device_label TEXT NOT NULL CHECK(length(device_label) BETWEEN 1 AND 128),
    pin_hash TEXT NOT NULL CHECK(length(pin_hash) BETWEEN 1 AND 512),
    created_at TEXT NOT NULL CHECK(length(created_at) BETWEEN 20 AND 40),
    expires_at TEXT NOT NULL CHECK(length(expires_at) BETWEEN 20 AND 40),
    last_used_at TEXT CHECK(last_used_at IS NULL OR length(last_used_at) BETWEEN 20 AND 40),
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
    stepup_expires_at TEXT
        CHECK(stepup_expires_at IS NULL OR length(stepup_expires_at) BETWEEN 20 AND 40),
    pin_failed_count INTEGER NOT NULL DEFAULT 0 CHECK(pin_failed_count >= 0),
    pin_window_started_at TEXT
        CHECK(pin_window_started_at IS NULL OR length(pin_window_started_at) BETWEEN 20 AND 40),
    pin_locked_until TEXT
        CHECK(pin_locked_until IS NULL OR length(pin_locked_until) BETWEEN 20 AND 40)
);

CREATE TABLE integration_tokens (
    id TEXT PRIMARY KEY NOT NULL CHECK(length(id) = 36),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    token_hash TEXT NOT NULL UNIQUE
        CHECK(length(token_hash) = 64)
        CHECK(lower(token_hash) = token_hash)
        CHECK(token_hash NOT GLOB '*[^0-9a-f]*'),
    scopes TEXT NOT NULL CHECK(json_valid(scopes) AND json_type(scopes) = 'array'),
    created_at TEXT NOT NULL CHECK(length(created_at) BETWEEN 20 AND 40),
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1))
);

UPDATE install_state SET schema_version = 23 WHERE singleton = 1 AND schema_version < 23;
