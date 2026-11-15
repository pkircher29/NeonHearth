-- Audit attribution: add the 'phone' actor so remote phone-session actions are
-- no longer recorded as the owner. SQLite cannot alter a CHECK constraint, so
-- the table is rebuilt. Rows are copied verbatim (including entry_hash, which
-- commits to the unchanged actor strings), so the hash chain is preserved.
-- The append-only triggers are attached to the old table and vanish with it;
-- DROP TABLE does not fire DELETE triggers. They are re-created below exactly
-- as in 022_audit_log.sql.
CREATE TABLE audit_log_new (
    id INTEGER PRIMARY KEY NOT NULL CHECK(id >= 1),
    occurred_at TEXT NOT NULL CHECK(length(occurred_at) BETWEEN 20 AND 40),
    actor TEXT NOT NULL CHECK(actor IN ('owner', 'service', 'module', 'phone')),
    category TEXT NOT NULL CHECK(category IN ('approval', 'scan', 'enforcement', 'doctor_action', 'audit_module')),
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 128),
    subject TEXT CHECK(subject IS NULL OR length(subject) BETWEEN 1 AND 256),
    detail TEXT NOT NULL CHECK(json_valid(detail) AND length(detail) <= 16384),
    prev_hash TEXT NOT NULL
        CHECK(length(prev_hash) = 64)
        CHECK(lower(prev_hash) = prev_hash)
        CHECK(prev_hash NOT GLOB '*[^0-9a-f]*'),
    entry_hash TEXT NOT NULL UNIQUE
        CHECK(length(entry_hash) = 64)
        CHECK(lower(entry_hash) = entry_hash)
        CHECK(entry_hash NOT GLOB '*[^0-9a-f]*')
);

INSERT INTO audit_log_new(id, occurred_at, actor, category, action, subject, detail, prev_hash, entry_hash)
SELECT id, occurred_at, actor, category, action, subject, detail, prev_hash, entry_hash FROM audit_log;

DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;

CREATE INDEX audit_log_category_idx ON audit_log(category, id);
CREATE INDEX audit_log_occurred_idx ON audit_log(occurred_at, id);

CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

UPDATE install_state SET schema_version = 38 WHERE singleton = 1 AND schema_version < 38;
