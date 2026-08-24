CREATE TABLE cameras (
    camera_id TEXT PRIMARY KEY NOT NULL
        CHECK(length(camera_id) = 36)
        CHECK(substr(camera_id, 9, 1) = '-' AND substr(camera_id, 14, 1) = '-' AND substr(camera_id, 19, 1) = '-' AND substr(camera_id, 24, 1) = '-')
        CHECK(lower(camera_id) = camera_id),
    classification TEXT NOT NULL CHECK(classification IN ('camera', 'possible_camera', 'unknown')),
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    health TEXT NOT NULL CHECK(health IN ('healthy', 'degraded', 'unknown')),
    observed_at TEXT NOT NULL CHECK(length(observed_at) BETWEEN 20 AND 40)
);

CREATE TABLE camera_evidence (
    camera_id TEXT NOT NULL REFERENCES cameras(camera_id) ON DELETE CASCADE,
    family TEXT NOT NULL CHECK(family IN ('onvif', 'ws_discovery', 'rtsp', 'upnp', 'http', 'tls', 'service', 'behavior')),
    source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 128),
    fact TEXT NOT NULL CHECK(length(fact) BETWEEN 1 AND 256),
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    observed_at TEXT NOT NULL CHECK(length(observed_at) BETWEEN 20 AND 40),
    expires_at TEXT CHECK(length(expires_at) BETWEEN 20 AND 40),
    CHECK(expires_at IS NULL OR expires_at > observed_at),
    PRIMARY KEY(camera_id, family, source, fact, observed_at)
);

CREATE TABLE camera_inventory (
    camera_id TEXT PRIMARY KEY NOT NULL REFERENCES cameras(camera_id) ON DELETE CASCADE,
    manufacturer TEXT CHECK(length(manufacturer) BETWEEN 1 AND 128 AND manufacturer NOT LIKE '%://%' AND instr(manufacturer, '@') = 0),
    model TEXT CHECK(length(model) BETWEEN 1 AND 128 AND model NOT LIKE '%://%' AND instr(model, '@') = 0),
    firmware TEXT CHECK(length(firmware) BETWEEN 1 AND 128 AND firmware NOT LIKE '%://%' AND instr(firmware, '@') = 0),
    serial TEXT CHECK(length(serial) BETWEEN 1 AND 128 AND serial NOT LIKE '%://%' AND instr(serial, '@') = 0),
    health TEXT NOT NULL CHECK(health IN ('healthy', 'degraded'))
);

CREATE TABLE camera_capabilities (
    camera_id TEXT NOT NULL REFERENCES cameras(camera_id) ON DELETE CASCADE,
    capability TEXT NOT NULL CHECK(length(capability) BETWEEN 1 AND 128 AND capability NOT LIKE '%://%' AND instr(capability, '@') = 0),
    PRIMARY KEY(camera_id, capability)
);

CREATE TABLE camera_stream_refs (
    camera_id TEXT NOT NULL REFERENCES cameras(camera_id) ON DELETE CASCADE,
    stream_id TEXT PRIMARY KEY NOT NULL
        CHECK(length(stream_id) = 36)
        CHECK(substr(stream_id, 9, 1) = '-' AND substr(stream_id, 14, 1) = '-' AND substr(stream_id, 19, 1) = '-' AND substr(stream_id, 24, 1) = '-')
        CHECK(lower(stream_id) = stream_id),
    source_ref TEXT NOT NULL CHECK(length(source_ref) BETWEEN 1 AND 128 AND source_ref NOT GLOB '*[^A-Za-z0-9_-]*'),
    UNIQUE(camera_id, source_ref)
);

CREATE INDEX camera_evidence_camera_observed_idx
    ON camera_evidence(camera_id, observed_at DESC, family, source, fact);
CREATE INDEX camera_evidence_expiry_idx
    ON camera_evidence(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX camera_capabilities_camera_idx ON camera_capabilities(camera_id, capability);
CREATE INDEX camera_stream_refs_camera_idx ON camera_stream_refs(camera_id, stream_id);

UPDATE install_state SET schema_version = 17 WHERE singleton = 1 AND schema_version < 17;
