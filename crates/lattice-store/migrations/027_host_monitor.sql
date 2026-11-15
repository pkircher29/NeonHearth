-- Host measurements are separate from observations of other LAN devices.
CREATE TABLE host_apps (
    app_id TEXT PRIMARY KEY CHECK(length(app_id) BETWEEN 1 AND 80),
    name TEXT NOT NULL CHECK(length(name) <= 512),
    executable TEXT CHECK(length(executable) <= 4096),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    sent_bytes INTEGER NOT NULL DEFAULT 0 CHECK(sent_bytes >= 0),
    received_bytes INTEGER NOT NULL DEFAULT 0 CHECK(received_bytes >= 0)
);
CREATE TABLE host_samples (
    id INTEGER PRIMARY KEY,
    observed_at TEXT NOT NULL,
    scope TEXT NOT NULL CHECK(scope IN ('host','app')),
    subject TEXT NOT NULL CHECK(length(subject) <= 80),
    interval_ms INTEGER NOT NULL CHECK(interval_ms > 0),
    sent_bytes INTEGER NOT NULL CHECK(sent_bytes >= 0),
    received_bytes INTEGER NOT NULL CHECK(received_bytes >= 0),
    coverage TEXT NOT NULL
);
CREATE INDEX host_samples_time ON host_samples(observed_at);
CREATE INDEX host_samples_subject_time ON host_samples(scope,subject,observed_at);
CREATE UNIQUE INDEX host_samples_bucket ON host_samples(observed_at,scope,subject);
CREATE TABLE host_connections (
    connection_id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES host_apps(app_id),
    protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp')),
    local_address TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_address TEXT,
    remote_port INTEGER,
    state TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE INDEX host_connections_recent ON host_connections(last_seen_at);
CREATE TABLE host_alerts (
    id INTEGER PRIMARY KEY,
    observed_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    app_id TEXT,
    detail TEXT NOT NULL CHECK(length(detail) <= 2048),
    acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1))
);
CREATE TABLE host_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    record_history INTEGER NOT NULL DEFAULT 1 CHECK(record_history IN (0,1)),
    snooze_until TEXT,
    retention_days INTEGER NOT NULL DEFAULT 30 CHECK(retention_days BETWEEN 1 AND 365),
    monthly_budget_bytes INTEGER CHECK(monthly_budget_bytes > 0)
);
INSERT INTO host_settings(id) VALUES(1);
CREATE TABLE host_firewall_rules (
    app_id TEXT NOT NULL REFERENCES host_apps(app_id),
    direction TEXT NOT NULL CHECK(direction IN ('inbound','outbound')),
    blocked INTEGER NOT NULL CHECK(blocked IN (0,1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(app_id,direction)
);
