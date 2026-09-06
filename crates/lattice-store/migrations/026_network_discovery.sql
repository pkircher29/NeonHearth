-- Last bounded scan and capture import, separate from trusted identity and control.
CREATE TABLE network_discovery_snapshots (
    kind TEXT PRIMARY KEY CHECK(kind IN ('scan', 'capture')),
    payload TEXT NOT NULL CHECK(length(payload) <= 8388608),
    updated_at TEXT NOT NULL
);
