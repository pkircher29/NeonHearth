CREATE TABLE policy_outbox (
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (device_id, fingerprint)
);

UPDATE install_state SET schema_version=8 WHERE singleton=1 AND schema_version<8;
