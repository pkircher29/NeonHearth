ALTER TABLE device_policy ADD COLUMN published_decision_json TEXT;
UPDATE install_state SET schema_version=9 WHERE singleton=1 AND schema_version<9;
