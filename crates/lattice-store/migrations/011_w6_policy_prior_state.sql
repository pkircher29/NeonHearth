CREATE TABLE w6_policy_prior_state (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    state_json TEXT NOT NULL
);
