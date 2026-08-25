PRAGMA foreign_keys = ON;
CREATE INDEX presence_transitions_snapshot_idx ON presence_transitions (device_id, occurred_at DESC, transition_id DESC);
CREATE INDEX evidence_snapshot_idx ON evidence (device_id, confidence DESC, observed_at DESC, evidence_id DESC);
UPDATE install_state SET schema_version=5 WHERE singleton=1 AND schema_version<5;
