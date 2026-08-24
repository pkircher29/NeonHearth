PRAGMA foreign_keys = ON;

CREATE TABLE device_policy (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    baseline_exempt INTEGER NOT NULL CHECK (baseline_exempt IN (0, 1)),
    identification_json TEXT NOT NULL,
    owner_decision_json TEXT NOT NULL,
    risk_json TEXT NOT NULL,
    protection_json TEXT NOT NULL,
    extension_until TEXT,
    extension_used INTEGER NOT NULL DEFAULT 0 CHECK (extension_used IN (0, 1)),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    enrolled_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX device_policy_deadline_idx ON device_policy (extension_until, baseline_exempt);

UPDATE install_state SET schema_version=6 WHERE singleton=1 AND schema_version<6;
