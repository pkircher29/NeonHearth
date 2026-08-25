use chrono::Utc;
use lattice_camera::CameraEvidenceFamily;
use lattice_sensor::{
    Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory, InterfaceOverride,
    TargetApproval, TargetGuard, TargetGuardError,
    camera_detection::{CameraObservationError, camera_evidence_from_observation},
};
use std::net::{IpAddr, Ipv4Addr};

fn guard() -> TargetGuard {
    let id = InterfaceId::new(1);
    let inventory = InterfaceInventory::new(vec![Interface {
        id,
        name: "eth0".into(),
        description: None,
        up: true,
        class: InterfaceClass::PhysicalWired,
        addresses: vec![Address {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            prefix: 24,
        }],
        owner_role: None,
    }]);
    TargetGuard::new(
        inventory,
        [(id, InterfaceOverride::Default)],
        [TargetApproval {
            interface: id,
            prefix: Address {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                prefix: 24,
            },
        }],
    )
    .unwrap()
}

#[test]
fn adapter_rejects_public_and_cross_interface_targets_before_evidence() {
    let g = guard();
    for target in [
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    ] {
        assert!(matches!(
            camera_evidence_from_observation(
                &g,
                InterfaceId::new(1),
                target,
                CameraEvidenceFamily::Onvif,
                "fixture",
                "onvif_camera_profile",
                1.0,
                Utc::now()
            ),
            Err(CameraObservationError::Target(
                TargetGuardError::TargetNotPrivate
            )) | Err(CameraObservationError::Target(
                TargetGuardError::OutsideApprovedPrefix
            ))
        ));
    }
    assert!(matches!(
        camera_evidence_from_observation(
            &g,
            InterfaceId::new(99),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
            CameraEvidenceFamily::Onvif,
            "fixture",
            "onvif_camera_profile",
            1.0,
            Utc::now()
        ),
        Err(CameraObservationError::Target(
            TargetGuardError::InterfaceNotEligible
        ))
    ));
    assert!(matches!(
        camera_evidence_from_observation(
            &g,
            InterfaceId::new(1),
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 4)),
            CameraEvidenceFamily::Onvif,
            "fixture",
            "onvif_camera_profile",
            1.0,
            Utc::now()
        ),
        Err(CameraObservationError::Target(
            TargetGuardError::OutsideApprovedPrefix
        ))
    ));
}

#[test]
fn adapter_reports_invalid_evidence_without_forging_target_rejection() {
    assert!(matches!(
        camera_evidence_from_observation(
            &guard(),
            InterfaceId::new(1),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
            CameraEvidenceFamily::Http,
            "fixture",
            "https://secret.invalid",
            0.5,
            Utc::now(),
        ),
        Err(CameraObservationError::InvalidEvidence)
    ));
}
