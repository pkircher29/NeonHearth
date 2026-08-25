CREATE TABLE policy_actuation_journal (
    device_id TEXT PRIMARY KEY REFERENCES device_policy(device_id) ON DELETE CASCADE,
    policy_version INTEGER NOT NULL,
    action_json TEXT NOT NULL,
    reserved_at TEXT NOT NULL
);

CREATE INDEX policy_actuation_journal_action_idx
    ON policy_actuation_journal(device_id, policy_version, action_json);

UPDATE install_state SET schema_version=13 WHERE singleton=1 AND schema_version<13;
