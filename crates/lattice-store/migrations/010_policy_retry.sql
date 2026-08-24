ALTER TABLE device_policy ADD COLUMN enforcement_retry_at TEXT;
UPDATE install_state SET schema_version=10 WHERE singleton=1 AND schema_version<10;
