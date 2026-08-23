use lattice_sensor::InterfaceId;
use lattice_sensor::neighbor::NeighborSnapshotConfig;
use std::collections::BTreeSet;

#[test]
fn snapshot_config_fails_closed_for_empty_allowlist() {
    let config = NeighborSnapshotConfig::new(16, BTreeSet::new());
    assert!(config.is_err());
}

#[test]
fn snapshot_config_rejects_zero_capacity() {
    let config = NeighborSnapshotConfig::new(0, [InterfaceId::new(2)]);
    assert!(config.is_err());
}
