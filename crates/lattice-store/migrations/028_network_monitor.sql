-- Router measurements stay separate from this computer's counters.
CREATE TABLE network_monitor_state (
    kind TEXT PRIMARY KEY CHECK(kind IN ('settings','discovery')),
    payload TEXT NOT NULL CHECK(length(payload) <= 2097152)
);
CREATE TABLE network_router_samples (
    at INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    download REAL NOT NULL CHECK(download >= 0),
    upload REAL NOT NULL CHECK(upload >= 0)
);
CREATE TABLE network_presence (
    interface INTEGER NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    missed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(interface,mac)
);
CREATE TABLE network_presence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    interface INTEGER NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('discovered','responding_again','not_responding'))
);
