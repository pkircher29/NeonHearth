use chrono::{TimeZone, Utc};
use lattice_sensor::InterfaceId;
use lattice_sensor::neighbor::*;
use std::net::{IpAddr, Ipv4Addr};

fn mac(n: u8) -> LinkAddress {
    LinkAddress::try_from([0x02, 0, 0, 0, 0, n]).unwrap()
}
fn row(ip: IpAddr, m: LinkAddress, r: NeighborReachability) -> NeighborRow {
    NeighborRow::new(InterfaceId::new(2), ip, m, r).unwrap()
}
fn at(n: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(n, 0).unwrap()
}

#[test]
fn validates_addresses_and_redacts_debug() {
    assert!(LinkAddress::try_from([0; 6]).is_err());
    assert!(LinkAddress::try_from([1, 0, 0, 0, 0, 0]).is_err());
    assert!(LinkAddress::try_from([0xff; 6]).is_err());
    let m = mac(1);
    assert_eq!(m.to_string(), "02:00:00:00:00:01");
    assert!(!format!("{m:?}").contains("02:00"));
    let readable = row(
        "192.168.1.2".parse().unwrap(),
        m,
        NeighborReachability::Reachable,
    );
    assert_eq!(readable.interface(), InterfaceId::new(2));
    assert_eq!(readable.ip(), "192.168.1.2".parse::<IpAddr>().unwrap());
    assert_eq!(readable.link_address(), m);
    assert_eq!(readable.reachability(), NeighborReachability::Reachable);
    assert!(
        NeighborRow::new(
            InterfaceId::new(2),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            m,
            NeighborReachability::Reachable
        )
        .is_err()
    );
}

#[test]
fn groups_sorts_and_confirms_changes() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig::default()).unwrap();
    let m = mac(1);
    let rows = vec![
        row(
            "fe80::2".parse().unwrap(),
            m,
            NeighborReachability::Reachable,
        ),
        row(
            "192.168.1.2".parse().unwrap(),
            m,
            NeighborReachability::Stale,
        ),
        row(
            "192.168.1.2".parse().unwrap(),
            m,
            NeighborReachability::Stale,
        ),
    ];
    let e = t.observe(rows, at(1)).unwrap();
    assert!(matches!(
        &e[0],
        NeighborEvent::Appeared { device, .. }
            if device.addresses() == [
                "192.168.1.2".parse::<IpAddr>().unwrap(),
                "fe80::2".parse::<IpAddr>().unwrap(),
            ]
    ));
    let e = t
        .observe(
            vec![row(
                "192.168.1.2".parse().unwrap(),
                m,
                NeighborReachability::Probe,
            )],
            at(2),
        )
        .unwrap();
    assert!(matches!(
        &e[0],
        NeighborEvent::Confirmed { device, .. }
            if device.addresses() == ["192.168.1.2".parse::<IpAddr>().unwrap()]
                && !device.addresses().contains(&"fe80::2".parse().unwrap())
    ));
}

#[test]
fn noarp_rows_are_present_and_confirmed() {
    let mut tracker = NeighborTracker::new(NeighborTrackerConfig::default()).unwrap();
    let row = row(
        "192.168.1.2".parse().unwrap(),
        mac(1),
        NeighborReachability::NoArp,
    );
    assert!(matches!(
        tracker
            .observe(vec![row.clone()], at(1))
            .unwrap()
            .as_slice(),
        [NeighborEvent::Appeared { .. }]
    ));
    assert!(matches!(
        tracker.observe(vec![row], at(2)).unwrap().as_slice(),
        [NeighborEvent::Confirmed { .. }]
    ));
}

#[test]
fn departure_debounce_and_reappearance() {
    let cfg = NeighborTrackerConfig {
        missed_snapshots_before_departure: 2,
        ..Default::default()
    };
    let mut t = NeighborTracker::new(cfg).unwrap();
    let r = row(
        "192.168.1.2".parse().unwrap(),
        mac(1),
        NeighborReachability::Reachable,
    );
    assert!(matches!(
        t.observe(vec![r.clone()], at(1)).unwrap()[0],
        NeighborEvent::Appeared { .. }
    ));
    assert!(matches!(
        t.observe(vec![], at(2)).unwrap().as_slice(),
        [NeighborEvent::Missed {
            consecutive_misses: 1,
            ..
        }]
    ));
    assert!(matches!(
        t.observe(vec![], at(3)).unwrap().as_slice(),
        [
            NeighborEvent::Missed {
                consecutive_misses: 2,
                ..
            },
            NeighborEvent::Departed { .. }
        ]
    ));
    assert!(t.observe(vec![], at(4)).unwrap().is_empty());
    assert!(matches!(
        t.observe(vec![r], at(5)).unwrap()[0],
        NeighborEvent::Appeared { .. }
    ));
}

#[test]
fn non_present_and_conflict_are_atomic() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig::default()).unwrap();
    let ip = "192.168.1.2".parse().unwrap();
    let absent = row(ip, mac(1), NeighborReachability::Failed);
    assert!(t.observe(vec![absent], at(1)).unwrap().is_empty());
    let conflict = vec![
        row(ip, mac(1), NeighborReachability::Reachable),
        row(ip, mac(2), NeighborReachability::Reachable),
    ];
    assert!(matches!(
        t.observe(conflict, at(2)),
        Err(NeighborError::ConflictingDuplicate)
    ));
    assert!(
        t.observe(
            vec![row(ip, mac(1), NeighborReachability::Reachable)],
            at(3)
        )
        .unwrap()
        .iter()
        .any(|e| matches!(e, NeighborEvent::Appeared { .. }))
    );
}

#[test]
fn all_reachability_states_and_unknown_fail_closed() {
    for state in [
        NeighborReachability::Reachable,
        NeighborReachability::Stale,
        NeighborReachability::Delay,
        NeighborReachability::Probe,
        NeighborReachability::Permanent,
    ] {
        let mut t = NeighborTracker::new(NeighborTrackerConfig::default()).unwrap();
        assert_eq!(
            t.observe(
                vec![row("192.168.1.2".parse().unwrap(), mac(1), state)],
                at(1)
            )
            .unwrap()
            .len(),
            1
        );
    }
    for state in [
        NeighborReachability::Incomplete,
        NeighborReachability::Failed,
        NeighborReachability::Unknown,
    ] {
        let mut t = NeighborTracker::new(NeighborTrackerConfig::default()).unwrap();
        assert!(
            t.observe(
                vec![row("192.168.1.2".parse().unwrap(), mac(1), state)],
                at(1)
            )
            .unwrap()
            .is_empty()
        );
    }
}

#[test]
fn every_zero_config_is_typed_invalid() {
    for cfg in [
        NeighborTrackerConfig {
            max_rows: 0,
            ..Default::default()
        },
        NeighborTrackerConfig {
            max_devices: 0,
            ..Default::default()
        },
        NeighborTrackerConfig {
            missed_snapshots_before_departure: 0,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            NeighborTracker::new(cfg),
            Err(NeighborError::InvalidConfig)
        ));
    }
}

#[test]
fn events_are_redacted_and_ordered() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig::default()).unwrap();
    let rows = vec![
        row(
            "192.168.1.3".parse().unwrap(),
            mac(2),
            NeighborReachability::Reachable,
        ),
        row(
            "192.168.1.2".parse().unwrap(),
            mac(1),
            NeighborReachability::Reachable,
        ),
    ];
    let events = t.observe(rows, at(1)).unwrap();
    assert!(matches!(events[0], NeighborEvent::Appeared { .. }));
    for e in events {
        let d = format!("{e:?}");
        assert!(!d.contains("02:00"));
        assert!(!d.contains("192.168.1."));
    }
}

#[test]
fn max_rows_failure_is_atomic_for_departure_misses() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig {
        max_rows: 1,
        missed_snapshots_before_departure: 2,
        ..Default::default()
    })
    .unwrap();
    let a = row(
        "192.168.1.2".parse().unwrap(),
        mac(1),
        NeighborReachability::Reachable,
    );
    t.observe(vec![a], at(1)).unwrap();
    assert!(matches!(
        t.observe(vec![], at(2)).unwrap().as_slice(),
        [NeighborEvent::Missed { .. }]
    ));
    assert_eq!(
        t.observe(
            vec![
                row(
                    "192.168.1.3".parse().unwrap(),
                    mac(2),
                    NeighborReachability::Reachable
                ),
                row(
                    "192.168.1.4".parse().unwrap(),
                    mac(3),
                    NeighborReachability::Reachable
                ),
            ],
            at(3),
        ),
        Err(NeighborError::Capacity)
    );
    assert!(matches!(
        t.observe(vec![], at(4)).unwrap().as_slice(),
        [
            NeighborEvent::Missed {
                consecutive_misses: 2,
                ..
            },
            NeighborEvent::Departed { .. }
        ]
    ));
}

#[test]
fn max_devices_failures_are_atomic_and_respect_live_capacity() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig {
        max_devices: 1,
        missed_snapshots_before_departure: 2,
        ..Default::default()
    })
    .unwrap();
    let a = row(
        "192.168.1.2".parse().unwrap(),
        mac(1),
        NeighborReachability::Reachable,
    );
    let b = row(
        "192.168.1.3".parse().unwrap(),
        mac(2),
        NeighborReachability::Reachable,
    );
    t.observe(vec![a.clone()], at(1)).unwrap();
    assert_eq!(
        t.observe(vec![a.clone(), b.clone()], at(2)),
        Err(NeighborError::Capacity)
    );
    assert!(matches!(
        t.observe(vec![a.clone()], at(3)).unwrap().as_slice(),
        [NeighborEvent::Confirmed { device, .. }] if device.link_address() == mac(1)
    ));
    assert_eq!(
        t.observe(vec![b.clone()], at(4)),
        Err(NeighborError::Capacity)
    );
    assert!(matches!(
        t.observe(vec![], at(5)).unwrap().as_slice(),
        [NeighborEvent::Missed {
            consecutive_misses: 1,
            ..
        }]
    ));
    assert!(matches!(
        t.observe(vec![], at(6)).unwrap().as_slice(),
        [NeighborEvent::Missed { consecutive_misses: 2, .. }, NeighborEvent::Departed { device, .. }] if device.link_address() == mac(1)
    ));
    assert!(matches!(
        t.observe(vec![b], at(7)).unwrap().as_slice(),
        [NeighborEvent::Appeared { device, .. }] if device.link_address() == mac(2)
    ));
}

#[test]
fn conflict_after_a_miss_is_atomic_even_for_non_present_rows() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig {
        missed_snapshots_before_departure: 2,
        ..Default::default()
    })
    .unwrap();
    let a = row(
        "192.168.1.2".parse().unwrap(),
        mac(1),
        NeighborReachability::Reachable,
    );
    let conflicting_ip: IpAddr = "192.168.1.3".parse().unwrap();
    t.observe(vec![a], at(1)).unwrap();
    assert!(matches!(
        t.observe(vec![], at(2)).unwrap().as_slice(),
        [NeighborEvent::Missed { .. }]
    ));
    assert_eq!(
        t.observe(
            vec![
                row(conflicting_ip, mac(2), NeighborReachability::Failed),
                row(conflicting_ip, mac(3), NeighborReachability::Unknown),
            ],
            at(3),
        ),
        Err(NeighborError::ConflictingDuplicate)
    );
    assert!(matches!(
        t.observe(vec![], at(4)).unwrap().as_slice(),
        [
            NeighborEvent::Missed {
                consecutive_misses: 2,
                ..
            },
            NeighborEvent::Departed { .. }
        ]
    ));
    assert!(t.observe(vec![], at(5)).unwrap().is_empty());
}

#[test]
fn event_order_is_present_key_sorted_then_departures_key_sorted() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig {
        missed_snapshots_before_departure: 1,
        ..Default::default()
    })
    .unwrap();
    t.observe(
        vec![
            row(
                "192.168.1.2".parse().unwrap(),
                mac(3),
                NeighborReachability::Reachable,
            ),
            row(
                "192.168.1.3".parse().unwrap(),
                mac(1),
                NeighborReachability::Reachable,
            ),
        ],
        at(1),
    )
    .unwrap();
    let events = t
        .observe(
            vec![
                row(
                    "192.168.1.4".parse().unwrap(),
                    mac(2),
                    NeighborReachability::Reachable,
                ),
                row(
                    "192.168.1.5".parse().unwrap(),
                    mac(1),
                    NeighborReachability::Reachable,
                ),
            ],
            at(2),
        )
        .unwrap();
    assert!(
        matches!(&events[0], NeighborEvent::Confirmed { device, .. } if device.link_address() == mac(1))
    );
    assert!(
        matches!(&events[1], NeighborEvent::Appeared { device, .. } if device.link_address() == mac(2))
    );
    assert!(
        matches!(&events[2], NeighborEvent::Missed { device, consecutive_misses: 1, .. } if device.link_address() == mac(3))
    );
    assert!(
        matches!(&events[3], NeighborEvent::Departed { device, .. } if device.link_address() == mac(3))
    );
}

#[test]
fn first_miss_reports_device_and_count() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig::default()).unwrap();
    let r = row(
        "192.168.1.2".parse().unwrap(),
        mac(1),
        NeighborReachability::Reachable,
    );
    t.observe(vec![r], at(1)).unwrap();
    assert!(matches!(t.observe(vec![], at(2)).unwrap().as_slice(),
        [NeighborEvent::Missed { device, observed_at, consecutive_misses: 1 }] if device.link_address() == mac(1) && *observed_at == at(2)));
}

#[test]
fn final_miss_reports_then_departs_and_reappearance_resets_count() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig {
        missed_snapshots_before_departure: 2,
        ..Default::default()
    })
    .unwrap();
    let r = row(
        "192.168.1.2".parse().unwrap(),
        mac(1),
        NeighborReachability::Reachable,
    );
    t.observe(vec![r.clone()], at(1)).unwrap();
    assert!(matches!(
        t.observe(vec![], at(2)).unwrap().as_slice(),
        [NeighborEvent::Missed {
            consecutive_misses: 1,
            ..
        }]
    ));
    assert!(matches!(
        t.observe(vec![], at(3)).unwrap().as_slice(),
        [
            NeighborEvent::Missed {
                consecutive_misses: 2,
                ..
            },
            NeighborEvent::Departed { .. }
        ]
    ));
    t.observe(vec![r.clone()], at(4)).unwrap();
    assert!(matches!(
        t.observe(vec![], at(5)).unwrap().as_slice(),
        [NeighborEvent::Missed {
            consecutive_misses: 1,
            ..
        }]
    ));
}

#[test]
fn failed_rows_still_count_as_absent_and_missed_debug_is_redacted() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig::default()).unwrap();
    let r = row(
        "192.168.1.42".parse().unwrap(),
        mac(42),
        NeighborReachability::Reachable,
    );
    t.observe(vec![r.clone()], at(1)).unwrap();
    let failed = row(
        "192.168.1.42".parse().unwrap(),
        mac(42),
        NeighborReachability::Failed,
    );
    let event = t.observe(vec![failed], at(2)).unwrap().remove(0);
    assert!(matches!(
        event,
        NeighborEvent::Missed {
            consecutive_misses: 1,
            ..
        }
    ));
    let debug = format!("{event:?}");
    assert!(!debug.contains("192.168.1.42"));
    assert!(!debug.contains("02:00:00:00:00:2a"));
}

#[test]
fn departed_devices_are_removed_and_reappearance_is_appeared() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig {
        max_devices: 1,
        missed_snapshots_before_departure: 1,
        ..Default::default()
    })
    .unwrap();
    let a = row(
        "192.168.1.2".parse().unwrap(),
        mac(1),
        NeighborReachability::Reachable,
    );
    let b = row(
        "192.168.1.3".parse().unwrap(),
        mac(2),
        NeighborReachability::Reachable,
    );
    t.observe(vec![a.clone()], at(1)).unwrap();
    t.observe(vec![], at(2)).unwrap();
    assert!(matches!(
        t.observe(vec![b], at(3)).unwrap().as_slice(),
        [NeighborEvent::Appeared { .. }]
    ));
    t.observe(vec![], at(4)).unwrap();
    assert!(matches!(
        t.observe(vec![a], at(5)).unwrap().as_slice(),
        [NeighborEvent::Appeared { .. }]
    ));
}

#[test]
fn row_and_each_event_debug_redact_all_network_identifiers() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig {
        missed_snapshots_before_departure: 1,
        ..Default::default()
    })
    .unwrap();
    let r = row(
        "192.168.1.42".parse().unwrap(),
        mac(42),
        NeighborReachability::Reachable,
    );
    let r6 = row(
        "fe80::42".parse().unwrap(),
        mac(42),
        NeighborReachability::Reachable,
    );
    let row_debug = format!("{r:?}");
    assert!(!row_debug.contains("02:00:00:00:00:2a"));
    assert!(!row_debug.contains("192.168.1.42"));
    let appeared = t
        .observe(vec![r.clone(), r6.clone()], at(1))
        .unwrap()
        .remove(0);
    let confirmed = t.observe(vec![r, r6], at(2)).unwrap().remove(0);
    let departed = t.observe(vec![], at(3)).unwrap().remove(0);
    for event in [appeared, confirmed, departed] {
        let debug = format!("{event:?}");
        assert!(!debug.contains("02:00:00:00:00:2a"));
        assert!(!debug.contains("192.168.1.42"));
        assert!(!debug.contains("fe80::42"));
    }
}

#[test]
fn clock_rollback_after_a_miss_is_atomic_and_equal_time_is_allowed() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig {
        missed_snapshots_before_departure: 2,
        ..Default::default()
    })
    .unwrap();
    let a = row(
        "192.168.1.2".parse().unwrap(),
        mac(1),
        NeighborReachability::Reachable,
    );
    t.observe(vec![a], at(10)).unwrap();
    assert!(matches!(
        t.observe(vec![], at(11)).unwrap().as_slice(),
        [NeighborEvent::Missed { .. }]
    ));
    assert_eq!(t.observe(vec![], at(10)), Err(NeighborError::ClockRollback));
    assert!(matches!(
        t.observe(vec![], at(11)).unwrap().as_slice(),
        [
            NeighborEvent::Missed {
                consecutive_misses: 2,
                ..
            },
            NeighborEvent::Departed { .. }
        ]
    ));
}

#[test]
fn failed_future_snapshot_does_not_advance_the_clock() {
    let mut t = NeighborTracker::new(NeighborTrackerConfig {
        max_rows: 1,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        t.observe(
            vec![
                row(
                    "192.168.1.2".parse().unwrap(),
                    mac(1),
                    NeighborReachability::Reachable,
                ),
                row(
                    "192.168.1.3".parse().unwrap(),
                    mac(2),
                    NeighborReachability::Reachable,
                ),
            ],
            at(100),
        ),
        Err(NeighborError::Capacity)
    );
    assert!(matches!(
        t.observe(
            vec![row(
                "192.168.1.2".parse().unwrap(),
                mac(1),
                NeighborReachability::Reachable,
            )],
            at(1),
        )
        .unwrap()
        .as_slice(),
        [NeighborEvent::Appeared { .. }]
    ));

    let mut conflict_tracker = NeighborTracker::new(NeighborTrackerConfig::default()).unwrap();
    let ip: IpAddr = "192.168.1.2".parse().unwrap();
    assert_eq!(
        conflict_tracker.observe(
            vec![
                row(ip, mac(1), NeighborReachability::Reachable),
                row(ip, mac(2), NeighborReachability::Reachable),
            ],
            at(100),
        ),
        Err(NeighborError::ConflictingDuplicate)
    );
    assert!(matches!(
        conflict_tracker
            .observe(
                vec![row(ip, mac(1), NeighborReachability::Reachable)],
                at(1)
            )
            .unwrap()
            .as_slice(),
        [NeighborEvent::Appeared { .. }]
    ));
}
