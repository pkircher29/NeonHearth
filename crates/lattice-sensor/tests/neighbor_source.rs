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

#[test]
fn snapshot_config_rejects_zero_interface_allowlist_entry() {
    let config = NeighborSnapshotConfig::new(16, [InterfaceId::new(0)]);
    assert!(config.is_err());
}

#[test]
fn snapshot_config_exposes_only_read_only_validated_limits() {
    let allowed = BTreeSet::from([InterfaceId::new(2)]);
    let config = NeighborSnapshotConfig::new(16, allowed.clone()).unwrap();
    assert_eq!(config.max_rows(), 16);
    assert_eq!(config.allowed_interfaces(), &allowed);
    assert_eq!(config.max_raw_messages(), 64);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn system_snapshot_smoke_test_uses_local_nonzero_interfaces() {
    use lattice_sensor::neighbor::{
        NeighborError, NeighborSnapshotSource, SystemNeighborSnapshotSource,
    };

    let allowed: BTreeSet<_> = pnet_datalink::interfaces()
        .into_iter()
        .filter_map(|interface| (interface.index != 0).then(|| InterfaceId::new(interface.index)))
        .collect();
    if allowed.is_empty() {
        return;
    }
    let config = NeighborSnapshotConfig::new(256, allowed.clone()).unwrap();
    match SystemNeighborSnapshotSource::new(config).snapshot().await {
        Ok(rows) => {
            assert!(rows.len() <= 256);
            assert!(
                rows.iter().all(|row| {
                    row.interface().get() != 0 && allowed.contains(&row.interface())
                })
            );
        }
        // Some hosts expose non-Ethernet neighbor entries through a locally
        // enumerated interface. Production must reject those malformed rows.
        Err(NeighborError::Malformed) => {}
        Err(error) => panic!("unexpected sanitized snapshot status: {error}"),
    }
}
