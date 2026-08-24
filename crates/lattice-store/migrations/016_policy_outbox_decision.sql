-- The pending outbox must retain the exact event it is waiting to publish.
-- Fingerprints alone cannot safely reconstruct evaluation or enforcement state.
ALTER TABLE policy_outbox ADD COLUMN decision_json TEXT;

UPDATE install_state SET schema_version=16 WHERE singleton=1 AND schema_version<16;
