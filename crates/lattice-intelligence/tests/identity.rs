use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily};
use lattice_intelligence::{
    Decision, Identification, IdentityConfig, IdentityEngine, IdentityError,
};

fn id(n: u8) -> DeviceId {
    DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}
fn fact(family: EvidenceFamily, key: &str, value: &str, confidence: f32) -> EvidenceFact {
    let now = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    EvidenceFact {
        family,
        source: "test".into(),
        key: key.into(),
        value: value.into(),
        confidence,
        observed_at: now,
        expires_at: None,
        owner_confirmed: false,
    }
}
fn engine() -> IdentityEngine {
    IdentityEngine::new(
        IdentityConfig::default(),
        vec![id(1), id(2), id(3)].into_iter(),
    )
    .unwrap()
}

#[test]
fn stable_mac_keeps_identity_across_dhcp_ip_change() {
    let mut e = engine();
    let d = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::LinkLayer, "mac", "00:11:22:33:44:55", 0.98),
                fact(EvidenceFamily::Addressing, "dhcp_client_id", "client", 0.98),
                fact(EvidenceFamily::Addressing, "ip", "192.168.1.2", 0.7),
            ],
        )
        .unwrap();
    assert_eq!(
        d,
        e.observe(
            None,
            vec![
                fact(EvidenceFamily::LinkLayer, "mac", "00:11:22:33:44:55", 0.98),
                fact(EvidenceFamily::Addressing, "dhcp_client_id", "client", 0.98),
                fact(EvidenceFamily::Addressing, "ip", "192.168.1.99", 0.7)
            ]
        )
        .unwrap()
    );
}

#[test]
fn private_mac_rotation_requires_two_independent_strong_families() {
    let mut e = engine();
    let d = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::LinkLayer, "mac", "02:11:22:33:44:55", 0.95),
                fact(EvidenceFamily::Cryptographic, "tls_spki", "abc", 0.95),
                fact(EvidenceFamily::Service, "onvif_uuid", "cam", 0.95),
            ],
        )
        .unwrap();
    let d2 = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::LinkLayer, "mac", "06:11:22:33:44:66", 0.95),
                fact(EvidenceFamily::Cryptographic, "tls_spki", "abc", 0.95),
                fact(EvidenceFamily::Service, "onvif_uuid", "cam", 0.95),
            ],
        )
        .unwrap();
    assert_eq!(d, d2);
}

#[test]
fn weak_single_factors_never_merge_and_ambiguity_proposes() {
    for f in [
        fact(EvidenceFamily::Service, "vendor", "Acme", 0.99),
        fact(EvidenceFamily::Addressing, "ip", "192.168.1.8", 0.99),
        fact(EvidenceFamily::RouterHint, "label", "TV", 0.99),
        fact(EvidenceFamily::Naming, "hostname", "same", 0.99),
    ] {
        let mut e = engine();
        let a = e.observe(None, vec![f.clone()]).unwrap();
        let b = e.observe(None, vec![f]).unwrap();
        assert_ne!(a, b);
    }
    let mut e = engine();
    let a = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.9),
                fact(EvidenceFamily::Service, "uuid", "u", 0.9),
            ],
        )
        .unwrap();
    let b = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Cryptographic, "tls_spki", "y", 0.9),
                fact(EvidenceFamily::Service, "uuid", "u2", 0.9),
            ],
        )
        .unwrap();
    let c = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.9),
                fact(EvidenceFamily::Service, "uuid", "u2", 0.9),
            ],
        )
        .unwrap();
    assert_ne!(c, a);
    assert_ne!(c, b);
    assert!(!e.proposals().is_empty());
}

#[test]
fn contradiction_blocks_matching() {
    let mut e = engine();
    let a = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Service, "serial", "A", 0.99),
                fact(EvidenceFamily::Service, "uuid", "u", 0.95),
            ],
        )
        .unwrap();
    let b = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Service, "serial", "B", 0.99),
                fact(EvidenceFamily::Service, "uuid", "u", 0.95),
            ],
        )
        .unwrap();
    assert_ne!(a, b);
}

#[test]
fn one_weak_matching_family_does_not_complete_a_merge() {
    let mut e = engine();
    let a = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.95),
                fact(EvidenceFamily::Service, "onvif_uuid", "u", 0.84),
            ],
        )
        .unwrap();
    let b = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.95),
                fact(EvidenceFamily::Service, "onvif_uuid", "u", 0.84),
            ],
        )
        .unwrap();
    assert_ne!(a, b);
}

#[test]
fn contradictory_high_confidence_classification_requires_review() {
    let mut e = engine();
    let d = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Naming, "vendor", "Acme", 0.95),
                fact(EvidenceFamily::Service, "class", "camera", 0.95),
                fact(EvidenceFamily::Cryptographic, "vendor", "Other", 0.95),
            ],
        )
        .unwrap();
    assert_eq!(e.identification(d).unwrap(), None);
}

#[test]
fn identification_threshold_router_cap_and_independent_families_are_exact() {
    let mut e = engine();
    let below = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Naming, "vendor", "Acme", 0.849),
                fact(EvidenceFamily::Service, "class", "camera", 0.9),
            ],
        )
        .unwrap();
    assert_eq!(e.identification(below).unwrap(), None);
    let one = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Naming, "vendor", "Acme", 0.85),
                fact(EvidenceFamily::Naming, "class", "camera", 1.0),
            ],
        )
        .unwrap();
    assert_eq!(e.identification(one).unwrap(), None);
    e.add_facts(
        one,
        vec![fact(EvidenceFamily::Service, "class", "camera", 0.85)],
    )
    .unwrap();
    assert_eq!(e.identification(one).unwrap().unwrap().vendor, "Acme");
    let r = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::RouterHint, "vendor", "RouterCo", 1.0),
                fact(EvidenceFamily::RouterHint, "class", "tv", 1.0),
            ],
        )
        .unwrap();
    assert_eq!(
        e.facts(r).unwrap()[0].confidence,
        IdentityConfig::default().router_hint_cap
    );
    assert_eq!(e.identification(r).unwrap(), None);
}

#[test]
fn owner_values_override_until_explicit_clear() {
    let mut e = engine();
    let d = e.observe(None, vec![]).unwrap();
    e.set_owner_fact(d, "vendor", "Mine", Utc::now()).unwrap();
    e.add_facts(
        d,
        vec![
            fact(EvidenceFamily::Naming, "vendor", "Auto", 1.0),
            fact(EvidenceFamily::Service, "class", "camera", 1.0),
            fact(EvidenceFamily::Naming, "class", "camera", 1.0),
        ],
    )
    .unwrap();
    assert_eq!(e.identification(d).unwrap().unwrap().vendor, "Mine");
    e.clear_owner_fact(d, "vendor").unwrap();
    assert_eq!(e.identification(d).unwrap().unwrap().vendor, "Auto");
}

#[test]
fn proposals_accept_reject_and_undo_preserve_facts_and_audit() {
    let mut e = engine();
    let a = e
        .observe(
            None,
            vec![fact(EvidenceFamily::Naming, "hostname", "one", 0.9)],
        )
        .unwrap();
    let b = e
        .observe(
            None,
            vec![fact(EvidenceFamily::Service, "uuid", "two", 0.9)],
        )
        .unwrap();
    let p = e
        .propose_merge(
            a,
            b,
            0.7,
            vec![EvidenceFamily::Naming, EvidenceFamily::Service],
            vec!["owner review".into()],
        )
        .unwrap();
    e.decide(p, Decision::Accept).unwrap();
    assert_eq!(e.resolve(b).unwrap(), a);
    assert_eq!(e.facts(a).unwrap().len(), 2);
    e.undo(p).unwrap();
    assert_eq!(e.resolve(b).unwrap(), b);
    assert_eq!(e.facts(a).unwrap().len(), 1);
    assert_eq!(e.facts(b).unwrap().len(), 1);
    let q = e
        .propose_merge(a, b, 0.6, vec![EvidenceFamily::Naming], vec!["weak".into()])
        .unwrap();
    e.decide(q, Decision::Reject).unwrap();
    assert_eq!(e.resolve(b).unwrap(), b);
    assert_eq!(e.audit().len(), 3);
}

#[test]
fn accepted_merge_remains_canonical_for_later_observations() {
    let mut e = engine();
    let a = e
        .observe(
            None,
            vec![fact(EvidenceFamily::Naming, "hostname", "a", 0.9)],
        )
        .unwrap();
    let b = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Cryptographic, "tls_spki", "key", 0.95),
                fact(EvidenceFamily::Service, "onvif_uuid", "camera", 0.95),
            ],
        )
        .unwrap();
    let p = e
        .propose_merge(
            a,
            b,
            0.8,
            vec![EvidenceFamily::Cryptographic],
            vec!["owner".into()],
        )
        .unwrap();
    e.decide(p, Decision::Accept).unwrap();
    let observed = e
        .observe(
            None,
            vec![
                fact(EvidenceFamily::Cryptographic, "tls_spki", "key", 0.95),
                fact(EvidenceFamily::Service, "onvif_uuid", "camera", 0.95),
            ],
        )
        .unwrap();
    assert_eq!(observed, a);
}

#[test]
fn expiry_validation_capacity_and_ordering_are_bounded() {
    let mut e = IdentityEngine::new(
        IdentityConfig {
            max_facts_per_device: 2,
            max_proposals: 1,
            ..Default::default()
        },
        vec![id(1), id(2), id(3)].into_iter(),
    )
    .unwrap();
    let now = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    let mut expired = fact(EvidenceFamily::Service, "serial", "x", 1.0);
    expired.expires_at = Some(now - Duration::seconds(1));
    let a = e.observe_at(None, vec![expired], now).unwrap();
    let b = e
        .observe_at(
            None,
            vec![fact(EvidenceFamily::Service, "serial", "x", 1.0)],
            now,
        )
        .unwrap();
    assert_ne!(a, b);
    assert!(matches!(
        e.add_facts(
            a,
            vec![
                fact(EvidenceFamily::Naming, "hostname", "one", 0.5),
                fact(EvidenceFamily::Service, "uuid", "two", 0.5)
            ]
        ),
        Err(IdentityError::Capacity(_))
    ));
    let mut nan = fact(EvidenceFamily::Naming, "x", "y", f32::NAN);
    assert!(matches!(
        e.add_facts(a, vec![nan.clone()]),
        Err(IdentityError::InvalidConfidence)
    ));
    nan.confidence = 2.0;
    assert!(e.add_facts(a, vec![nan]).is_err());
    assert!(
        e.add_facts(
            a,
            vec![fact(EvidenceFamily::Naming, &"x".repeat(200), "v", 0.5)]
        )
        .is_err()
    );
    let p = e
        .propose_merge(a, b, 0.5, vec![EvidenceFamily::Naming], vec!["z".into()])
        .unwrap();
    assert!(e.propose_merge(a, b, 0.5, vec![], vec![]).is_err());
    assert_eq!(e.proposals()[0].id, p);
}

#[test]
fn expired_classification_cannot_identify() {
    let now = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    let mut e = engine();
    let mut vendor = fact(EvidenceFamily::Naming, "vendor", "Acme", 1.0);
    vendor.expires_at = Some(now - Duration::seconds(1));
    let d = e
        .observe_at(
            None,
            vec![
                vendor,
                fact(EvidenceFamily::Service, "class", "camera", 1.0),
            ],
            now,
        )
        .unwrap();
    assert_eq!(e.identification_at(d, now).unwrap(), None);
}

#[test]
fn public_identification_shape_is_stable() {
    let _ = Identification {
        vendor: "v".into(),
        device_class: "c".into(),
        model: None,
        firmware: None,
        confidence: 0.85,
        families: vec![],
    };
}
