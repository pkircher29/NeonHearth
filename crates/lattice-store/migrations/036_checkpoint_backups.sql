-- Copies of discovery checkpoints taken before a source-set migration rewrites them.
-- A checkpoint is never discarded: when the set of discovery interfaces changes, the old
-- bytes are kept here (newest 8 are retained by the service).
CREATE TABLE state_checkpoint_backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    saved_at TEXT NOT NULL,
    source_fingerprint TEXT NOT NULL,
    commit_sequence INTEGER NOT NULL,
    checkpoint_bytes BLOB NOT NULL
);
