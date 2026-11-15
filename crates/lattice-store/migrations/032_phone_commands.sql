-- Keep reservations for the lifetime of the phone session, including across restarts.
CREATE TABLE phone_commands (
 session_id TEXT NOT NULL REFERENCES phone_sessions(id) ON DELETE CASCADE,
 command_id TEXT NOT NULL,
 fingerprint TEXT NOT NULL,
 PRIMARY KEY(session_id, command_id)
);
UPDATE install_state SET schema_version = 32 WHERE singleton = 1 AND schema_version < 32;
