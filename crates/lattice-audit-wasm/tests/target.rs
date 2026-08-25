use lattice_audit_wasm::{AuthorizedTarget, TargetError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn accepts_only_explicit_private_or_link_local_unicast_targets() {
    for target in [
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.2",
        "fd00::1",
        "fe80::1",
    ] {
        assert!(
            AuthorizedTarget::new(target.parse().unwrap(), 7, 443).is_ok(),
            "{target}"
        );
    }
    for target in [
        "8.8.8.8",
        "127.0.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "100.64.0.1",
        "100.127.255.254",
        "::1",
        "::",
        "ff02::1",
        "::ffff:192.168.1.1",
    ] {
        assert_eq!(
            AuthorizedTarget::new(target.parse().unwrap(), 7, 443),
            Err(TargetError::InvalidTarget),
            "{target}"
        );
    }
}

#[test]
fn rejects_zero_interface_and_port() {
    let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(
        AuthorizedTarget::new(target, 0, 80),
        Err(TargetError::InvalidInterface)
    );
    assert_eq!(
        AuthorizedTarget::new(target, 1, 0),
        Err(TargetError::InvalidPort)
    );
    let mapped = IpAddr::V6("::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap());
    assert_eq!(
        AuthorizedTarget::new(mapped, 1, 80),
        Err(TargetError::InvalidTarget)
    );
}
