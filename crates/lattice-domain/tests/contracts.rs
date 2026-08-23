use chrono::{TimeZone, Utc};
use lattice_domain::{
    Coverage, DeviceId, EventEnvelope, EventPayload, PresenceChanged, PresenceState,
};

#[test]
fn public_event_contract_serializes_stable_names() {
    let device_id = DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445566").unwrap();
    let occurred_at = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    let envelope = EventEnvelope {
        sequence: 42,
        occurred_at,
        payload: EventPayload::PresenceChanged(PresenceChanged {
            device_id,
            from: PresenceState::Quiet,
            to: PresenceState::Online,
            reason: "arp_reply".to_owned(),
        }),
    };

    let json = serde_json::to_value(envelope).unwrap();
    assert_eq!(json["sequence"], 42);
    assert_eq!(json["payload"]["type"], "presence_changed");
    assert_eq!(json["payload"]["data"]["to"], "online");
    assert_eq!(
        serde_json::to_string(&Coverage::RouterReported).unwrap(),
        "\"router-reported\""
    );
}
