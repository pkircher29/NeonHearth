use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use lattice_sensor::{
    Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory, InterfaceOverride,
    TargetGuard, TargetGuardError, classify_interface, diff_inventory,
};

fn address(ip: &str, prefix: u8) -> Address {
    Address {
        ip: ip.parse().unwrap(),
        prefix,
    }
}

fn interface(
    id: u32,
    name: &str,
    up: bool,
    class: InterfaceClass,
    addresses: Vec<Address>,
) -> Interface {
    Interface {
        id: InterfaceId::new(id),
        name: name.to_owned(),
        description: None,
        up,
        class,
        addresses,
        owner_role: None,
    }
}

#[test]
fn classification_is_conservative_across_windows_and_linux_names() {
    assert_eq!(
        classify_interface("Ethernet", None, false),
        InterfaceClass::PhysicalWired
    );
    assert_eq!(
        classify_interface("Wi-Fi", None, false),
        InterfaceClass::PhysicalWifi
    );
    assert_eq!(
        classify_interface("wlp2s0", None, false),
        InterfaceClass::PhysicalWifi
    );
    assert_eq!(
        classify_interface("lo", None, true),
        InterfaceClass::Loopback
    );
    assert_eq!(
        classify_interface("tailscale0", None, false),
        InterfaceClass::Tailscale
    );
    assert_eq!(
        classify_interface("wg0", None, false),
        InterfaceClass::VpnTunnel
    );
    assert_eq!(
        classify_interface("docker0", None, false),
        InterfaceClass::Container
    );
    assert_eq!(
        classify_interface("vEthernet (Default Switch)", None, false),
        InterfaceClass::VirtualMachine
    );
    assert_eq!(
        classify_interface("mystery", None, false),
        InterfaceClass::Unknown
    );
}

#[test]
fn eligibility_excludes_risky_interfaces_and_only_owner_can_enable_private_exclusions() {
    let wifi = interface(
        1,
        "Wi-Fi",
        true,
        InterfaceClass::PhysicalWifi,
        vec![address("192.168.1.10", 24)],
    );
    let down = interface(
        2,
        "Ethernet",
        false,
        InterfaceClass::PhysicalWired,
        vec![address("192.168.1.11", 24)],
    );
    let tailscale = interface(
        3,
        "tailscale0",
        true,
        InterfaceClass::Tailscale,
        vec![address("100.64.0.1", 32)],
    );
    let loopback = interface(
        4,
        "lo",
        true,
        InterfaceClass::Loopback,
        vec![address("127.0.0.1", 8)],
    );
    assert!(wifi.discovery_eligible(InterfaceOverride::Default));
    assert!(!down.discovery_eligible(InterfaceOverride::Default));
    assert!(!tailscale.discovery_eligible(InterfaceOverride::Default));
    assert!(!loopback.discovery_eligible(InterfaceOverride::Enable));
    assert!(down.discovery_eligible(InterfaceOverride::Enable));
    assert!(tailscale.discovery_eligible(InterfaceOverride::Enable));
}

#[test]
fn corporate_is_an_owner_role_not_a_name_guess() {
    let named = interface(1, "CorpNet", true, InterfaceClass::Unknown, vec![]);
    assert_eq!(named.class, InterfaceClass::Unknown);
    let corporate = Interface {
        owner_role: Some(lattice_sensor::InterfaceRole::Corporate),
        ..named
    };
    assert!(!corporate.discovery_eligible(InterfaceOverride::Default));
    assert!(corporate.discovery_eligible(InterfaceOverride::Enable));
}

#[test]
fn inventory_diff_reports_add_remove_and_change() {
    let before = InterfaceInventory::new(vec![
        interface(
            1,
            "Ethernet",
            true,
            InterfaceClass::PhysicalWired,
            vec![address("192.168.1.2", 24)],
        ),
        interface(
            2,
            "Wi-Fi",
            true,
            InterfaceClass::PhysicalWifi,
            vec![address("192.168.1.3", 24)],
        ),
    ]);
    let after = InterfaceInventory::new(vec![
        interface(
            1,
            "Ethernet",
            false,
            InterfaceClass::PhysicalWired,
            vec![address("192.168.1.2", 24)],
        ),
        interface(
            3,
            "Wi-Fi",
            true,
            InterfaceClass::PhysicalWifi,
            vec![address("192.168.1.4", 24)],
        ),
    ]);
    let diff = diff_inventory(&before, &after);
    assert_eq!(diff.added, vec![InterfaceId::new(3)]);
    assert_eq!(diff.removed, vec![InterfaceId::new(2)]);
    assert_eq!(diff.changed, vec![InterfaceId::new(1)]);
}

fn guard() -> TargetGuard {
    TargetGuard::new(
        InterfaceInventory::new(vec![
            interface(
                1,
                "Ethernet",
                true,
                InterfaceClass::PhysicalWired,
                vec![
                    address("192.168.1.10", 24),
                    address("fd42::1", 64),
                    address("fe80::1", 64),
                ],
            ),
            interface(
                2,
                "Wi-Fi",
                true,
                InterfaceClass::PhysicalWifi,
                vec![address("10.1.2.3", 24)],
            ),
            interface(
                3,
                "tailscale0",
                true,
                InterfaceClass::Tailscale,
                vec![address("100.64.0.1", 32)],
            ),
        ]),
        [
            (InterfaceId::new(1), InterfaceOverride::Default),
            (InterfaceId::new(2), InterfaceOverride::Default),
            (InterfaceId::new(3), InterfaceOverride::Enable),
        ],
    )
    .unwrap()
}

#[test]
fn target_guard_accepts_only_private_on_the_owning_eligible_interface() {
    let guard = guard();
    for target in ["192.168.1.1", "192.168.1.254", "fd42::9", "fe80::2"] {
        assert!(
            guard
                .authorize(InterfaceId::new(1), target.parse().unwrap())
                .is_ok(),
            "{target}"
        );
    }
    assert!(
        guard
            .authorize(InterfaceId::new(2), "10.1.2.9".parse().unwrap())
            .is_ok()
    );
    assert_eq!(
        guard.authorize(InterfaceId::new(2), "192.168.1.1".parse().unwrap()),
        Err(TargetGuardError::OutsideApprovedPrefix)
    );
}

#[test]
fn target_guard_rejects_public_special_cgnat_and_cross_interface_targets() {
    let guard = guard();
    for target in [
        "8.8.8.8",
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "100.64.0.1",
        "::1",
        "::",
        "ff02::1",
        "::ffff:8.8.8.8",
        "::ffff:192.168.1.1",
    ] {
        assert!(
            guard
                .authorize(InterfaceId::new(1), target.parse().unwrap())
                .is_err(),
            "{target}"
        );
    }
    assert_eq!(
        guard.authorize(InterfaceId::new(3), "100.64.0.2".parse().unwrap()),
        Err(TargetGuardError::TargetNotPrivate)
    );
    assert!(
        guard
            .authorize(InterfaceId::new(1), "192.168.1.255".parse().unwrap())
            .is_err()
    );
}

#[test]
fn target_guard_rejects_invalid_prefixes_and_public_override() {
    let invalid = InterfaceInventory::new(vec![interface(
        1,
        "Ethernet",
        true,
        InterfaceClass::PhysicalWired,
        vec![address("192.168.1.1", 33)],
    )]);
    assert!(matches!(
        TargetGuard::new(invalid, [(InterfaceId::new(1), InterfaceOverride::Default)]),
        Err(TargetGuardError::InvalidPrefix { .. })
    ));
    let public = InterfaceInventory::new(vec![interface(
        1,
        "Ethernet",
        true,
        InterfaceClass::PhysicalWired,
        vec![address("8.8.8.8", 24)],
    )]);
    assert!(matches!(
        TargetGuard::new(public, [(InterfaceId::new(1), InterfaceOverride::Enable)]),
        Err(TargetGuardError::PublicApprovedPrefix { .. })
    ));
}

#[test]
fn real_enumeration_returns_structurally_valid_records() {
    let inventory = lattice_sensor::SystemInterfaceManager.snapshot().unwrap();
    for interface in inventory.interfaces() {
        assert!(!interface.name.is_empty());
        for address in &interface.addresses {
            assert!(match address.ip {
                IpAddr::V4(_) => address.prefix <= 32,
                IpAddr::V6(_) => address.prefix <= 128,
            });
        }
    }
    let _ = (Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST);
}
