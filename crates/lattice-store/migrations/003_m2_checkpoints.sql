PRAGMA foreign_keys = ON;
CREATE TABLE state_checkpoints (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), format_version INTEGER NOT NULL,
 checkpoint_bytes BLOB NOT NULL, source_fingerprint TEXT NOT NULL,
 commit_sequence INTEGER NOT NULL CHECK(commit_sequence>0), written_at TEXT NOT NULL,
 sha256 BLOB NOT NULL CHECK(length(sha256)=32)
);
CREATE TABLE presence_transitions (
 transition_id INTEGER PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
 from_state TEXT NOT NULL, to_state TEXT NOT NULL, occurred_at TEXT NOT NULL, reason TEXT NOT NULL,
 trigger_source TEXT NOT NULL, trigger_kind TEXT NOT NULL, evidence_observed_at TEXT NOT NULL,
 evidence_valid_until TEXT, trigger_arrival_at TEXT NOT NULL, correction_of INTEGER REFERENCES presence_transitions(transition_id),
 UNIQUE(device_id, transition_id)
);
CREATE INDEX presence_transitions_device_time_idx ON presence_transitions(device_id, occurred_at DESC);
CREATE TABLE discovery_commits (
 input_hash BLOB PRIMARY KEY CHECK(length(input_hash)=32), source TEXT NOT NULL,
 committed_at TEXT NOT NULL, result_summary BLOB NOT NULL,
 commit_digest BLOB NOT NULL CHECK(length(commit_digest)=32)
);
CREATE INDEX discovery_commits_time_idx ON discovery_commits(committed_at DESC);
CREATE UNIQUE INDEX evidence_semantic_identity_idx ON evidence
 (device_id, family, source, fact_key, fact_value, confidence, observed_at,
  COALESCE(expires_at, ''), owner_confirmed);
UPDATE install_state SET schema_version=3 WHERE singleton=1 AND schema_version<3;
