-- Audit head anchor (review finding M10). Chain verification re-derives every
-- hash from the audit rows themselves, so a rewritten or truncated table
-- still verifies clean. This singleton row records the newest accepted head
-- (id + hash) OUTSIDE the audit table. It is advanced in the same transaction
-- as every append, and verification compares the live chain against it.
--
-- `diverged` is sticky: an append that finds the stored head is not the head
-- it extends sets it, and nothing clears it, so later appends cannot hide an
-- earlier rewrite.
CREATE TABLE audit_head_anchor (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
    head_id INTEGER NOT NULL CHECK(head_id >= 1),
    head_hash TEXT NOT NULL
        CHECK(length(head_hash) = 64)
        CHECK(lower(head_hash) = head_hash)
        CHECK(head_hash NOT GLOB '*[^0-9a-f]*'),
    diverged INTEGER NOT NULL DEFAULT 0 CHECK(diverged IN (0, 1)),
    recorded_at TEXT NOT NULL
);

-- Existing installs: take the current head as the first accepted head.
INSERT INTO audit_head_anchor(singleton, head_id, head_hash, diverged, recorded_at)
SELECT 1, id, entry_hash, 0, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
FROM audit_log ORDER BY id DESC LIMIT 1;

-- A fully pruned log's head is its retention anchor.
INSERT OR IGNORE INTO audit_head_anchor(singleton, head_id, head_hash, diverged, recorded_at)
SELECT 1, pruned_through_id, pruned_through_hash, 0, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
FROM audit_log_anchor WHERE singleton = 1;

UPDATE install_state SET schema_version = 40 WHERE singleton = 1 AND schema_version < 40;
