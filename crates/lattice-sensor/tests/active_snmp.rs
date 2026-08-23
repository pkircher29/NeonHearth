use async_snmp::{
    FixedCardinalityOperation, FixedCardinalityResponse, ResponseMetadata, Value, VarBind,
};
use bytes::Bytes;
use lattice_sensor::active::{
    ProbeCredential, SnmpAuthProtocol, SnmpAuthentication, SnmpPrivProtocol, SnmpPrivacy,
    normalize_snmp_inventory,
};

fn response(bindings: Vec<VarBind>) -> FixedCardinalityResponse {
    FixedCardinalityResponse {
        operation: FixedCardinalityOperation::Get,
        varbinds: bindings,
        anomalies: vec![],
        metadata: ResponseMetadata::default(),
    }
}

#[test]
fn snmp_inventory_accepts_only_exact_bounded_sysdescr_and_sysobjectid() {
    let facts = normalize_snmp_inventory(response(vec![
        VarBind::new(
            async_snmp::oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString(Bytes::from_static(b"Camera OS 1.2")),
        ),
        VarBind::new(
            async_snmp::oid!(1, 3, 6, 1, 2, 1, 1, 2, 0),
            Value::ObjectIdentifier(async_snmp::oid!(1, 3, 6, 1, 4, 1, 8072)),
        ),
    ]))
    .unwrap();
    assert_eq!(facts[0], ("sys_descr".into(), "Camera OS 1.2".into()));
    assert_eq!(facts[1].0, "sys_object_id");

    assert!(
        normalize_snmp_inventory(response(vec![VarBind::new(
            async_snmp::oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString(Bytes::from_static(b"wrong"))
        )]))
        .is_err()
    );
    assert!(
        normalize_snmp_inventory(response(vec![
            VarBind::new(
                async_snmp::oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                Value::OctetString(Bytes::from(vec![b'x'; 513]))
            ),
            VarBind::new(
                async_snmp::oid!(1, 3, 6, 1, 2, 1, 1, 2, 0),
                Value::ObjectIdentifier(async_snmp::oid!(1, 3, 6))
            ),
        ]))
        .is_err()
    );
}

#[test]
fn every_supported_snmp_credential_debug_is_redacted() {
    let credentials = [
        ProbeCredential::SnmpV1 {
            community: "v1-secret".into(),
        },
        ProbeCredential::SnmpV2c {
            community: "v2-secret".into(),
        },
        ProbeCredential::SnmpV3 {
            username: "owner".into(),
            authentication: None,
            privacy: None,
        },
        ProbeCredential::SnmpV3 {
            username: "owner".into(),
            authentication: Some(SnmpAuthentication {
                protocol: SnmpAuthProtocol::Sha256,
                password: "auth-secret".into(),
            }),
            privacy: Some(SnmpPrivacy {
                protocol: SnmpPrivProtocol::Aes128,
                password: "priv-secret".into(),
            }),
        },
    ];
    let debug = format!("{credentials:?}");
    for secret in ["v1-secret", "v2-secret", "auth-secret", "priv-secret"] {
        assert!(!debug.contains(secret));
    }
    assert!(debug.contains("[REDACTED]"));
}
