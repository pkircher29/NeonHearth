-- RLS2: append-only hash-chained audit log.
--
-- 001_core.sql created a placeholder audit_log table that no code ever read
-- or wrote (no repository, no inserts anywhere in the workspace). It cannot
-- carry the hash chain, so it is replaced here rather than extended.
DROP TABLE audit_log;

--
-- Every entry commits to its predecessor through entry_hash = SHA-256 over the
-- canonical encoding of (id, occurred_at, actor, category, action, subject,
-- detail, prev_hash). The genesis entry's prev_hash is the SHA-256 of a fixed
-- domain-separation constant ("neonhearth.audit-log.genesis.v1"). Identifiers
-- are allocated by the store inside a write-locked transaction and are
-- contiguous, so a verifier can detect removed rows as id gaps.
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY NOT NULL CHECK(id >= 1),
    occurred_at TEXT NOT NULL CHECK(length(occurred_at) BETWEEN 20 AND 40),
    actor TEXT NOT NULL CHECK(actor IN ('owner', 'service', 'module')),
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

CREATE INDEX audit_log_category_idx ON audit_log(category, id);
CREATE INDEX audit_log_occurred_idx ON audit_log(occurred_at, id);

-- Append-only is enforced in the schema itself, not just the store API.
-- Retention pruning is the one sanctioned exception: it drops and re-creates
-- audit_log_no_delete inside a single write-locked transaction while removing
-- a contiguous oldest-side prefix and recording the anchor below.
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

-- RLS3 retention anchor: after an oldest-side prune, verification restarts
-- from (pruned_through_id, pruned_through_hash) instead of the genesis
-- constant. The anchor only ever moves forward.
CREATE TABLE audit_log_anchor (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
    pruned_through_id INTEGER NOT NULL CHECK(pruned_through_id >= 1),
    pruned_through_hash TEXT NOT NULL
        CHECK(length(pruned_through_hash) = 64)
        CHECK(lower(pruned_through_hash) = pruned_through_hash)
        CHECK(pruned_through_hash NOT GLOB '*[^0-9a-f]*'),
    pruned_at TEXT NOT NULL CHECK(length(pruned_at) BETWEEN 20 AND 40)
);

UPDATE install_state SET schema_version = 22 WHERE singleton = 1 AND schema_version < 22;
