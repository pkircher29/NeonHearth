CREATE TABLE cameras (
    camera_id TEXT PRIMARY KEY NOT NULL CHECK(length(camera_id) = 36),
    classification TEXT NOT NULL CHECK(classification IN ('camera','possible_camera','unknown')),
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    health TEXT NOT NULL CHECK(length(health) BETWEEN 1 AND 32),
    observed_at TEXT NOT NULL
);
CREATE TABLE camera_evidence (
    camera_id TEXT NOT NULL REFERENCES cameras(camera_id) ON DELETE CASCADE,
    family TEXT NOT NULL CHECK(length(family) BETWEEN 1 AND 32),
    fact TEXT NOT NULL CHECK(length(fact) BETWEEN 1 AND 128),
    observed_at TEXT NOT NULL,
    PRIMARY KEY(camera_id, family, fact)
);
CREATE TABLE camera_inventory (
    camera_id TEXT PRIMARY KEY NOT NULL REFERENCES cameras(camera_id) ON DELETE CASCADE,
    manufacturer TEXT CHECK(length(manufacturer) <= 128),
    model TEXT CHECK(length(model) <= 128),
    firmware TEXT CHECK(length(firmware) <= 128),
    serial TEXT CHECK(length(serial) <= 128)
);
CREATE TABLE camera_capabilities (
    camera_id TEXT NOT NULL REFERENCES cameras(camera_id) ON DELETE CASCADE,
    capability TEXT NOT NULL CHECK(length(capability) BETWEEN 1 AND 64),
    PRIMARY KEY(camera_id, capability)
);
CREATE TABLE camera_stream_refs (
    camera_id TEXT NOT NULL REFERENCES cameras(camera_id) ON DELETE CASCADE,
    stream_id TEXT PRIMARY KEY NOT NULL CHECK(length(stream_id) = 36),
    source_ref TEXT NOT NULL CHECK(length(source_ref) BETWEEN 1 AND 128),
    UNIQUE(camera_id, source_ref)
);
CREATE INDEX camera_evidence_camera_observed_idx ON camera_evidence(camera_id, observed_at DESC);
CREATE INDEX camera_stream_refs_camera_idx ON camera_stream_refs(camera_id);
UPDATE install_state SET schema_version=17 WHERE singleton=1 AND schema_version<17;
