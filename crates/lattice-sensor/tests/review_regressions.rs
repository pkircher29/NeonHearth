//! Regressions for the sensor review (scope, sanitising, parser tolerance).
use async_trait::async_trait;
use lattice_sensor::{
    Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory, TargetApproval,
    TargetGuard, TargetGuardError,
    active::{
        ActiveEngine, ActiveError, AttemptTransport, ProbeDescriptor, ProbeMode, ProbeOutcome,
        ProbeRequest, TransportResponse, catalog, parse_http_metadata,
    },
    sanitize::display_text,
};
use std::sync::Arc;

fn interface() -> Interface {
    Interface {
        id: InterfaceId::new(5),
        name: "eth0".into(),
        description: None,
        up: true,
        class: InterfaceClass::PhysicalWired,
        addresses: vec![Address {
            ip: "192.168.1.10".parse().unwrap(),
            prefix: 24,
        }],
        owner_role: None,
    }
}

/// The scan service approves each neighbor as a /32, which used to bypass the broadcast check.
#[test]
fn host_approvals_cannot_name_subnet_network_or_broadcast_addresses() {
    for target in ["192.168.1.255", "192.168.1.0"] {
        let ip: std::net::IpAddr = target.parse().unwrap();
        let guard = TargetGuard::new(
            InterfaceInventory::new(vec![interface()]),
            [],
            [TargetApproval {
                interface: InterfaceId::new(5),
                prefix: Address { ip, prefix: 32 },
            }],
        )
        .unwrap();
        assert_eq!(
            guard.authorize(InterfaceId::new(5), ip),
            Err(TargetGuardError::BroadcastOrNetworkAddress),
            "{target}"
        );
    }
    let guard = TargetGuard::new(
        InterfaceInventory::new(vec![interface()]),
        [],
        [TargetApproval {
            interface: InterfaceId::new(5),
            prefix: Address {
                ip: "192.168.1.77".parse().unwrap(),
                prefix: 32,
            },
        }],
    )
    .unwrap();
    assert!(
        guard
            .authorize(InterfaceId::new(5), "192.168.1.77".parse().unwrap())
            .is_ok()
    );
}

struct Spoof;
#[async_trait]
impl AttemptTransport for Spoof {
    async fn attempt(
        &self,
        _: &TargetGuard,
        _: &ProbeRequest,
        _: &ProbeDescriptor,
        _: Option<&lattice_sensor::active::ProbeCredential>,
    ) -> Result<TransportResponse, ActiveError> {
        Ok(TransportResponse::Success(vec![(
            "banner".into(),
            "safe\u{202e}evil\u{0}\u{1b}[31m".into(),
        )]))
    }
}

/// Every active fact passes `normalize`, so a device cannot smuggle bidi or control characters.
#[tokio::test]
async fn active_facts_never_carry_bidi_overrides_or_control_characters() {
    let guard = Arc::new(
        TargetGuard::new(
            InterfaceInventory::new(vec![interface()]),
            [],
            [TargetApproval {
                interface: InterfaceId::new(5),
                prefix: Address {
                    ip: "192.168.1.20".parse().unwrap(),
                    prefix: 32,
                },
            }],
        )
        .unwrap(),
    );
    let engine = ActiveEngine::new(guard, Arc::new(Spoof), catalog().unwrap());
    let outcome = engine
        .execute(
            ProbeRequest {
                interface: InterfaceId::new(5),
                target: "192.168.1.20".parse().unwrap(),
                probe_id: "tcp.ssh.22".into(),
                mode: ProbeMode::Default,
                owner_approved: true,
            },
            None,
        )
        .await
        .unwrap();
    let ProbeOutcome::Success { facts } = outcome else {
        panic!("expected success")
    };
    assert_eq!(facts[0].value, "safeevil[31m");
}

#[test]
fn display_text_is_shared_and_bounded() {
    assert_eq!(display_text("a\u{2067}b", 8), "ab");
}

/// A Latin-1 `Server` header used to fail the whole probe with `Protocol`.
#[test]
fn non_utf8_http_header_bytes_do_not_discard_the_response() {
    let mut response = b"HTTP/1.0 200 OK\r\nX-Name: caf".to_vec();
    response.push(0xe9);
    response.extend_from_slice(b"\r\nServer: nginx\r\n\r\n");
    let facts = parse_http_metadata(&response).unwrap();
    assert!(facts.contains(&("server".into(), "nginx".into())));
    assert!(facts.contains(&("status".into(), "200".into())));
}
