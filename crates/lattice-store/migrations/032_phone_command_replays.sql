-- Durable replay records for phone commands (contract T4: no replay).
--
-- Each mutating phone request carries a client command id. The service writes
-- an in-flight row (executed = 0, status = 0) BEFORE running the handler and
-- completes it with the response afterwards. A restart, a crash or a cancelled
-- handler therefore leaves a row behind: a retry of the same id is answered
-- from the row (or refused as "outcome unknown") and is never executed twice.
-- request_fingerprint binds the id to (method, path, body): reusing an id for a
-- different request is a conflict, not a replay.
CREATE TABLE phone_command_replays (
    session_id TEXT NOT NULL CHECK(length(session_id) = 36)
        REFERENCES phone_sessions(id) ON DELETE CASCADE,
    command_id TEXT NOT NULL CHECK(length(command_id) = 36),
    request_fingerprint TEXT NOT NULL
        CHECK(length(request_fingerprint) = 64)
        CHECK(request_fingerprint NOT GLOB '*[^0-9a-f]*'),
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
    status INTEGER NOT NULL DEFAULT 0 CHECK(status BETWEEN 0 AND 599),
    content_type TEXT CHECK(content_type IS NULL OR length(content_type) <= 256),
    body BLOB,
    body_omitted INTEGER NOT NULL DEFAULT 0 CHECK(body_omitted IN (0, 1)),
    created_at TEXT NOT NULL CHECK(length(created_at) BETWEEN 20 AND 40),
    seq INTEGER NOT NULL,
    PRIMARY KEY (session_id, command_id)
);

CREATE INDEX phone_command_replays_order_idx ON phone_command_replays(session_id, seq);

UPDATE install_state SET schema_version = 32 WHERE singleton = 1 AND schema_version < 32;
