use chrono::{TimeZone, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily};
use lattice_intelligence::{Decision, IdentityConfig, IdentityEngine};
fn id(n: u8) -> DeviceId {
    DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}
fn f(family: EvidenceFamily, key: &str, value: &str, c: f32) -> EvidenceFact {
    EvidenceFact {
        family,
        source: "test".into(),
        key: key.into(),
        value: value.into(),
        confidence: c,
        observed_at: Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap(),
        expires_at: None,
        owner_confirmed: false,
    }
}
fn e() -> IdentityEngine {
    IdentityEngine::new(IdentityConfig::default(), (1..30).map(id)).unwrap()
}

#[test]
fn config_is_fallible() {
    for c in [
        IdentityConfig {
            router_hint_cap: 0.85,
            ..Default::default()
        },
        IdentityConfig {
            auto_identification_threshold: 0.849,
            ..Default::default()
        },
        IdentityConfig {
            match_threshold: f32::NAN,
            ..Default::default()
        },
        IdentityConfig {
            max_facts_per_device: 0,
            ..Default::default()
        },
    ] {
        assert!(IdentityEngine::new(c, (1..3).map(id)).is_err())
    }
}
#[test]
fn mac_is_canonical_strict_and_never_single_family() {
    let mut x = e();
    let a = x
        .observe(
            None,
            vec![f(
                EvidenceFamily::LinkLayer,
                "mac",
                "00-11-22-33-44-55",
                0.95,
            )],
        )
        .unwrap();
    assert_eq!(x.facts(a).unwrap()[0].value, "00:11:22:33:44:55");
    let b = x
        .observe(
            None,
            vec![f(EvidenceFamily::LinkLayer, "mac", "0011.2233.4455", 0.95)],
        )
        .unwrap();
    assert_ne!(a, b);
    assert!(!x.proposals().is_empty());
    for m in ["01:00:5e:00:00:01", "zz:11:22:33:44:55", "00:11:22:33:44"] {
        assert!(
            x.observe(None, vec![f(EvidenceFamily::LinkLayer, "mac", m, 0.9)])
                .is_err()
        )
    }
}
#[test]
fn stable_mac_plus_dhcp_is_two_families() {
    let mut x = e();
    let facts = || {
        vec![
            f(EvidenceFamily::LinkLayer, "mac", "00:11:22:33:44:55", 0.9),
            f(EvidenceFamily::Addressing, "dhcp_client_id", "client", 0.9),
        ]
    };
    let a = x.observe(None, facts()).unwrap();
    assert_eq!(a, x.observe(None, facts()).unwrap())
}
#[test]
fn family_spoofing_is_rejected() {
    let mut x = e();
    assert!(
        x.observe(None, vec![f(EvidenceFamily::Naming, "tls_spki", "x", 1.0)])
            .is_err()
    );
    let mut forged = f(EvidenceFamily::Owner, "vendor", "x", 1.0);
    forged.owner_confirmed = true;
    assert!(x.observe(None, vec![forged]).is_err())
}
#[test]
fn ambiguity_and_uncertainty_always_propose() {
    let mut x = e();
    let a = x
        .observe(
            None,
            vec![f(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.9)],
        )
        .unwrap();
    let b = x
        .observe(
            None,
            vec![f(EvidenceFamily::Service, "onvif_uuid", "u", 0.9)],
        )
        .unwrap();
    let c = x
        .observe(
            None,
            vec![
                f(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.9),
                f(EvidenceFamily::Service, "onvif_uuid", "u", 0.9),
            ],
        )
        .unwrap();
    assert_ne!(c, a);
    assert_ne!(c, b);
    assert_eq!(x.proposals().len(), 2);
    let d = x
        .observe(
            None,
            vec![f(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.9)],
        )
        .unwrap();
    assert_ne!(d, a);
    assert!(x.proposals().len() >= 3)
}
#[test]
fn contradiction_boundary_is_exact() {
    let mut x = e();
    let base = vec![
        f(EvidenceFamily::LinkLayer, "mac", "00:11:22:33:44:55", 0.9),
        f(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.9),
        f(EvidenceFamily::Service, "serial", "A", 0.9),
    ];
    let a = x.observe(None, base).unwrap();
    let near = vec![
        f(EvidenceFamily::LinkLayer, "mac", "00:11:22:33:44:55", 0.9),
        f(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.9),
        f(EvidenceFamily::Service, "serial", "B", 0.849),
    ];
    assert_eq!(x.observe(None, near).unwrap(), a);
    let exact = vec![
        f(EvidenceFamily::LinkLayer, "mac", "00:11:22:33:44:55", 0.9),
        f(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.9),
        f(EvidenceFamily::Service, "serial", "C", 0.85),
    ];
    assert_ne!(x.observe(None, exact).unwrap(), a)
}
#[test]
fn owner_history_is_explicit_nonexpiring_and_audited() {
    let mut x = e();
    let d = x.observe(None, vec![]).unwrap();
    let expired = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
    x.set_owner_fact(d, "vendor", "Mine", expired).unwrap();
    x.set_owner_fact(d, "class", "camera", expired).unwrap();
    assert_eq!(x.identification(d).unwrap().unwrap().vendor, "Mine");
    x.set_owner_fact(d, "vendor", "New", expired).unwrap();
    assert_eq!(x.identification(d).unwrap().unwrap().vendor, "New");
    x.clear_owner_fact(d, "vendor").unwrap();
    assert_eq!(x.identification(d).unwrap(), None);
    assert_eq!(x.owner_audit().len(), 4)
}
#[test]
fn alias_observation_returns_canonical() {
    let mut x = e();
    let a = x.observe(None, vec![]).unwrap();
    let b = x.observe(None, vec![]).unwrap();
    let p = x
        .propose_merge(
            a,
            b,
            0.8,
            vec![EvidenceFamily::Service],
            vec!["owner".into()],
        )
        .unwrap();
    x.decide(p, Decision::Accept).unwrap();
    assert_eq!(
        x.observe(
            Some(b),
            vec![f(EvidenceFamily::Naming, "hostname", "alias", 0.5)]
        )
        .unwrap(),
        x.resolve(a).unwrap()
    )
}
#[test]
fn merge_graph_undo_is_order_independent_and_duplicate_safe() {
    let mut x = e();
    let a = x.observe(None, vec![]).unwrap();
    let b = x.observe(None, vec![]).unwrap();
    let c = x.observe(None, vec![]).unwrap();
    let ab = x
        .propose_merge(a, b, 0.8, vec![EvidenceFamily::Service], vec!["ab".into()])
        .unwrap();
    let bc = x
        .propose_merge(b, c, 0.8, vec![EvidenceFamily::Service], vec!["bc".into()])
        .unwrap();
    x.decide(ab, Decision::Accept).unwrap();
    x.decide(bc, Decision::Accept).unwrap();
    let duplicate = x
        .propose_merge(
            a,
            c,
            0.8,
            vec![EvidenceFamily::Service],
            vec!["duplicate".into()],
        )
        .unwrap();
    x.decide(duplicate, Decision::Accept).unwrap();
    x.undo(ab).unwrap();
    assert_eq!(x.resolve(b).unwrap(), x.resolve(c).unwrap());
    assert_ne!(x.resolve(a).unwrap(), x.resolve(b).unwrap());
    x.undo(duplicate).unwrap();
    assert_eq!(x.resolve(b).unwrap(), x.resolve(c).unwrap());
    x.undo(bc).unwrap();
    assert_ne!(x.resolve(b).unwrap(), x.resolve(c).unwrap())
}

#[test]
fn diamond_and_cycle_edges_recompute_without_false_splits() {
    let mut x = e();
    let ids: Vec<_> = (0..4).map(|_| x.observe(None, vec![]).unwrap()).collect();
    let mut add = |a, b, label: &str| {
        let p = x
            .propose_merge(
                ids[a],
                ids[b],
                0.9,
                vec![EvidenceFamily::Service],
                vec![label.into()],
            )
            .unwrap();
        x.decide(p, Decision::Accept).unwrap();
        p
    };
    let ab = add(0, 1, "ab");
    let ac = add(0, 2, "ac");
    let bd = add(1, 3, "bd");
    let cd = add(2, 3, "cd");
    let cycle = add(1, 2, "cycle");
    x.undo(ab).unwrap();
    assert_eq!(x.resolve(ids[0]).unwrap(), x.resolve(ids[2]).unwrap());
    assert_eq!(x.resolve(ids[1]).unwrap(), x.resolve(ids[3]).unwrap());
    x.undo(cycle).unwrap();
    assert_eq!(x.resolve(ids[0]).unwrap(), x.resolve(ids[2]).unwrap());
    x.undo(cd).unwrap();
    assert_eq!(x.resolve(ids[1]).unwrap(), x.resolve(ids[3]).unwrap());
    x.undo(ac).unwrap();
    x.undo(bd).unwrap();
}
#[test]
fn capacity_failures_are_atomic() {
    let mut x = IdentityEngine::new(
        IdentityConfig {
            max_proposals: 1,
            ..Default::default()
        },
        (1..10).map(id),
    )
    .unwrap();
    let a = x.observe(None, vec![]).unwrap();
    let b = x.observe(None, vec![]).unwrap();
    x.propose_merge(a, b, 0.5, vec![EvidenceFamily::Naming], vec!["one".into()])
        .unwrap();
    let before = x.snapshot();
    assert!(
        x.observe(
            None,
            vec![f(EvidenceFamily::Cryptographic, "tls_spki", "x", 0.9)]
        )
        .is_ok()
    );
    let after_id = x.snapshot();
    assert_ne!(before, after_id);
    let before = x.snapshot();
    assert!(
        x.propose_merge(a, b, 0.5, vec![EvidenceFamily::Naming], vec!["two".into()])
            .is_err()
    );
    assert_eq!(before, x.snapshot())
}
