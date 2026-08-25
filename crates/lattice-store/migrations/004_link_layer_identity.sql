PRAGMA foreign_keys = ON;
CREATE INDEX evidence_link_layer_identity_idx
 ON evidence (family, source, fact_key, fact_value, device_id);
UPDATE install_state SET schema_version=4 WHERE singleton=1 AND schema_version<4;
