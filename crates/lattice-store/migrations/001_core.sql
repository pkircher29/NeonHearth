PRAGMA foreign_keys = ON;

CREATE TABLE install_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    install_id TEXT NOT NULL,
    first_run_at TEXT NOT NULL,
    schema_version INTEGER NOT NULL
);

CREATE TABLE event_sequence (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0)
);

INSERT INTO event_sequence (singleton, last_sequence) VALUES (1, 0);

CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    owner_name TEXT,
    type TEXT,
    owner_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (owner_confirmed IN (0, 1))
);

CREATE TABLE evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT REFERENCES devices(device_id) ON DELETE CASCADE,
    family TEXT NOT NULL,
    source TEXT NOT NULL,
    fact_key TEXT NOT NULL,
    fact_value TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    observed_at TEXT NOT NULL,
    expires_at TEXT,
    owner_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (owner_confirmed IN (0, 1))
);

CREATE INDEX evidence_device_time_idx ON evidence (device_id, observed_at DESC);

CREATE TABLE audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
