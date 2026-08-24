CREATE TABLE home_plans (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
    home_id TEXT NOT NULL
        CHECK(length(home_id) = 36)
        CHECK(substr(home_id, 9, 1) = '-' AND substr(home_id, 14, 1) = '-' AND substr(home_id, 19, 1) = '-' AND substr(home_id, 24, 1) = '-')
        CHECK(lower(home_id) = home_id),
    version INTEGER NOT NULL CHECK(version >= 1),
    plan TEXT NOT NULL CHECK(json_valid(plan) AND length(plan) <= 1048576),
    saved_at TEXT NOT NULL CHECK(length(saved_at) BETWEEN 20 AND 40)
);

CREATE TABLE home_plan_history (
    home_id TEXT NOT NULL
        CHECK(length(home_id) = 36)
        CHECK(substr(home_id, 9, 1) = '-' AND substr(home_id, 14, 1) = '-' AND substr(home_id, 19, 1) = '-' AND substr(home_id, 24, 1) = '-')
        CHECK(lower(home_id) = home_id),
    version INTEGER NOT NULL CHECK(version >= 1),
    plan TEXT NOT NULL CHECK(json_valid(plan) AND length(plan) <= 1048576),
    saved_at TEXT NOT NULL CHECK(length(saved_at) BETWEEN 20 AND 40),
    PRIMARY KEY(home_id, version)
);

CREATE TABLE home_drafts (
    home_id TEXT PRIMARY KEY NOT NULL
        CHECK(length(home_id) = 36)
        CHECK(substr(home_id, 9, 1) = '-' AND substr(home_id, 14, 1) = '-' AND substr(home_id, 19, 1) = '-' AND substr(home_id, 24, 1) = '-')
        CHECK(lower(home_id) = home_id),
    draft TEXT NOT NULL CHECK(length(draft) <= 524288),
    updated_at TEXT NOT NULL CHECK(length(updated_at) BETWEEN 20 AND 40)
);

CREATE TABLE owner_placements (
    device_id TEXT PRIMARY KEY NOT NULL
        CHECK(length(device_id) = 36)
        CHECK(substr(device_id, 9, 1) = '-' AND substr(device_id, 14, 1) = '-' AND substr(device_id, 19, 1) = '-' AND substr(device_id, 24, 1) = '-')
        CHECK(lower(device_id) = device_id),
    placement_id TEXT NOT NULL
        CHECK(length(placement_id) = 36)
        CHECK(substr(placement_id, 9, 1) = '-' AND substr(placement_id, 14, 1) = '-' AND substr(placement_id, 19, 1) = '-' AND substr(placement_id, 24, 1) = '-')
        CHECK(lower(placement_id) = placement_id),
    floor_id TEXT NOT NULL
        CHECK(length(floor_id) = 36)
        CHECK(substr(floor_id, 9, 1) = '-' AND substr(floor_id, 14, 1) = '-' AND substr(floor_id, 19, 1) = '-' AND substr(floor_id, 24, 1) = '-')
        CHECK(lower(floor_id) = floor_id),
    x REAL NOT NULL CHECK(x >= -1000.0 AND x <= 1000.0),
    y REAL NOT NULL CHECK(y >= -1000.0 AND y <= 1000.0),
    height_m REAL CHECK(height_m IS NULL OR (height_m >= 0.0 AND height_m <= 6.0)),
    mounting TEXT CHECK(mounting IS NULL OR mounting IN ('wall', 'ceiling', 'floor', 'shelf'))
);

CREATE TABLE location_estimates (
    device_id TEXT PRIMARY KEY NOT NULL
        CHECK(length(device_id) = 36)
        CHECK(substr(device_id, 9, 1) = '-' AND substr(device_id, 14, 1) = '-' AND substr(device_id, 19, 1) = '-' AND substr(device_id, 24, 1) = '-')
        CHECK(lower(device_id) = device_id),
    floor_id TEXT
        CHECK(floor_id IS NULL OR (
            length(floor_id) = 36
            AND substr(floor_id, 9, 1) = '-' AND substr(floor_id, 14, 1) = '-' AND substr(floor_id, 19, 1) = '-' AND substr(floor_id, 24, 1) = '-'
            AND lower(floor_id) = floor_id)),
    room_id TEXT
        CHECK(room_id IS NULL OR (
            length(room_id) = 36
            AND substr(room_id, 9, 1) = '-' AND substr(room_id, 14, 1) = '-' AND substr(room_id, 19, 1) = '-' AND substr(room_id, 24, 1) = '-'
            AND lower(room_id) = room_id)),
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    evidence TEXT NOT NULL CHECK(json_valid(evidence) AND json_type(evidence) = 'array' AND length(evidence) <= 8192),
    estimated_at TEXT NOT NULL CHECK(length(estimated_at) BETWEEN 20 AND 40)
);

CREATE INDEX home_plan_history_version_idx ON home_plan_history(version DESC);

UPDATE install_state SET schema_version = 21 WHERE singleton = 1 AND schema_version < 21;
