ALTER TABLE device_policy ADD COLUMN decision_fingerprint TEXT;

UPDATE install_state SET schema_version=7 WHERE singleton=1 AND schema_version<7;
