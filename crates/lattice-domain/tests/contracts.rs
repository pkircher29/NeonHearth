use chrono::{TimeZone, Utc};
use lattice_domain::{
    Coverage, DeviceId, EnforcementStatus, Evaluation, EventEnvelope, EventPayload, PolicyChanged,
    PolicyReason, PresenceChanged, PresenceState, RequestedAction, ServiceStatus,
};

#[test]
fn public_event_contract_serializes_stable_names() {
    let device_id = DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445566").unwrap();
    let occurred_at = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    let envelope = EventEnvelope {
        sequence: 42,
        occurred_at,
        payload: EventPayload::PresenceChanged(PresenceChanged {
            transition_id: 7,
            device_id,
            from: PresenceState::Quiet,
            to: PresenceState::Online,
            occurred_at,
            reason: "arp_reply".to_owned(),
            trigger_source: "arp".to_owned(),
            trigger_kind: "traffic".to_owned(),
            evidence_observed_at: occurred_at,
            evidence_valid_until: None,
            trigger_arrival_at: occurred_at,
            correction_of: None,
        }),
    };

    let json = serde_json::to_value(&envelope).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "sequence": 42,
            "occurred_at": "2026-08-23T12:00:00Z",
            "payload": {
                "type": "presence_changed",
                "data": {
                    "transition_id": 7,
                    "device_id": "018f47a0-9b5c-7a22-8a33-112233445566",
                    "from": "quiet",
                    "to": "online",
                    "occurred_at": "2026-08-23T12:00:00Z",
                    "reason": "arp_reply",
                    "trigger_source": "arp",
                    "trigger_kind": "traffic",
                    "evidence_observed_at": "2026-08-23T12:00:00Z",
                    "evidence_valid_until": null,
                    "trigger_arrival_at": "2026-08-23T12:00:00Z",
                    "correction_of": null
                }
            }
        })
    );
    assert_eq!(
        serde_json::from_value::<EventEnvelope>(json).unwrap(),
        envelope
    );

    let service_payload = EventPayload::ServiceStatus(ServiceStatus {
        state: "ready".to_owned(),
        detail: "collector active".to_owned(),
    });
    let service_json = serde_json::to_value(&service_payload).unwrap();
    assert_eq!(
        service_json,
        serde_json::json!({
            "type": "service_status",
            "data": { "state": "ready", "detail": "collector active" }
        })
    );
    assert_eq!(
        serde_json::from_value::<EventPayload>(service_json).unwrap(),
        service_payload
    );

    assert_eq!(
        serde_json::to_string(&Coverage::RouterReported).unwrap(),
        "\"router-reported\""
    );

    assert_eq!(
        device_id.to_string(),
        "018f47a0-9b5c-7a22-8a33-112233445566"
    );
    assert_eq!(DeviceId::parse(&device_id.to_string()).unwrap(), device_id);
    assert!(DeviceId::parse("not-a-uuid").is_err());
}

#[test]
fn policy_event_contract_serializes_stable_names() {
    let device_id = DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445566").unwrap();
    let payload = EventPayload::PolicyChanged(PolicyChanged {
        device_id,
        policy_version: 1,
        evaluation: Evaluation::quarantine(PolicyReason::UnknownDeadlineExpired),
        requested_action: RequestedAction::Quarantine,
        evidence_summary: "policy facts evaluated".into(),
        enforcement_result: EnforcementStatus::Verified,
        undo_available: false,
    });
    assert_eq!(serde_json::to_value(&payload).unwrap(), serde_json::json!({
        "type": "policy_changed", "data": {
            "device_id": "018f47a0-9b5c-7a22-8a33-112233445566",
            "policy_version": 1,
            "evaluation": {"policy_version": 1, "reason": "unknown_deadline_expired", "requested_action": "quarantine", "deadline": null, "warning": null},
            "requested_action": "quarantine",
            "evidence_summary": "policy facts evaluated",
            "enforcement_result": "verified",
            "undo_available": false
        }
    }));
}
