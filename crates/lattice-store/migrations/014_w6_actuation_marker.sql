ALTER TABLE w6_policy_prior_state ADD COLUMN action_json TEXT;
ALTER TABLE w6_policy_prior_state ADD COLUMN prepared_before_json TEXT;
ALTER TABLE w6_policy_prior_state ADD COLUMN verified_after_json TEXT;
UPDATE install_state SET schema_version=14 WHERE singleton=1 AND schema_version<14;
