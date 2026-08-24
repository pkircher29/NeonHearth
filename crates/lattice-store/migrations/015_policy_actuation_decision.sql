-- A reservation must carry the exact decision it fences.  A later evaluation
-- may select another action; restart recovery still needs to acknowledge the
-- original evaluation/control causally, never rewrite it as the new one.
ALTER TABLE policy_actuation_journal ADD COLUMN decision_json TEXT;

UPDATE install_state SET schema_version=15 WHERE singleton=1 AND schema_version<15;
