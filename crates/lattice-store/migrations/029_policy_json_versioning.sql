-- Review fixes: version the *_json blobs, freeze enrollment first_seen_at.
--
-- json_schema_version: 1 = rows written before this migration, 2 = current
-- writers. Readers accept <= 2 and report (not fail on) anything newer.
-- first_seen_at: the device's first-seen time at enrollment. Deadlines were
-- computed from the live devices.first_seen_at, which later commits can move
-- earlier (MIN upsert), silently shortening a deadline; baseline_exempt was
-- already frozen at enrollment.
ALTER TABLE device_policy ADD COLUMN json_schema_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE device_policy ADD COLUMN first_seen_at TEXT;
ALTER TABLE policy_outbox ADD COLUMN json_schema_version INTEGER NOT NULL DEFAULT 1;
UPDATE device_policy SET first_seen_at=(SELECT d.first_seen_at FROM devices d WHERE d.device_id=device_policy.device_id);
UPDATE install_state SET schema_version=29 WHERE singleton=1 AND schema_version<29;
