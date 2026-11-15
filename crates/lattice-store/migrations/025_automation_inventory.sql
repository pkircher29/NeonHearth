-- Keep automation availability separate from evidence of LAN presence.
CREATE TABLE automation_inventory (
    source TEXT NOT NULL,
    upstream_id TEXT NOT NULL,
    device_id TEXT NOT NULL UNIQUE,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    metadata TEXT NOT NULL,
    PRIMARY KEY(source, upstream_id)
);
CREATE TABLE automation_commands (
    command_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
