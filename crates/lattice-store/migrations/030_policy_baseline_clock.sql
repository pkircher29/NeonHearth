-- Auditable baseline resets and a clock heartbeat for the plausibility gate.
CREATE TABLE policy_baseline_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    changed_at TEXT NOT NULL,
    previous_baseline TEXT,
    new_baseline TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512)
);
CREATE TABLE policy_clock_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    last_heartbeat_at TEXT NOT NULL,
    suspect_reason TEXT
);
UPDATE install_state SET schema_version=30 WHERE singleton=1 AND schema_version<30;
