use super::*;
use chrono::TimeZone;

// Frozen pre-optimization encoder: intentional duplication establishes the
// persisted digest format independently of the borrowed representation.
fn legacy_digest(
    input: &CommitInput,
    flow: Option<Vec<serde_json::Value>>,
) -> Result<Vec<u8>, CheckpointError> {
    let mut devices: Vec<_> = input.devices.iter().map(|d| json!({"device_id":d.device_id.to_string(),"first_seen_at":d.first_seen_at.to_rfc3339(),"last_seen_at":d.last_seen_at.to_rfc3339(),"owner_name":d.owner_name,"owner_type":d.owner_type,"owner_confirmed":d.owner_confirmed})).collect();
    let mut evidence: Vec<_> = input.evidence.iter().map(|e| { let f=&e.fact; json!({"device_id":e.device_id.to_string(),"family":evidence_family(f.family),"source":f.source,"key":f.key,"value":f.value,"confidence":f.confidence,"observed_at":f.observed_at.to_rfc3339(),"expires_at":f.expires_at.map(|x|x.to_rfc3339()),"owner_confirmed":f.owner_confirmed}) }).collect();
    let mut transitions: Vec<_> = input.transitions.iter().map(|t| json!({"transition_id":t.transition_id,"device_id":t.device_id.to_string(),"from":presence_state(t.from),"to":presence_state(t.to),"occurred_at":t.occurred_at.to_rfc3339(),"reason":t.reason,"trigger_source":t.trigger_source,"trigger_kind":t.trigger_kind,"evidence_observed_at":t.evidence_observed_at.to_rfc3339(),"evidence_valid_until":t.evidence_valid_until.map(|x|x.to_rfc3339()),"trigger_arrival_at":t.trigger_arrival_at.to_rfc3339(),"correction_of":t.correction_of})).collect();
    sort_json_values(&mut devices);
    sort_json_values(&mut evidence);
    sort_json_values(&mut transitions);
    let c = &input.checkpoint;
    let canonical = json!({"checkpoint":{"format_version":c.format_version,"bytes":c.bytes,"source_fingerprint":c.source_fingerprint,"commit_sequence":c.commit_sequence,"written_at":c.written_at.to_rfc3339()},"devices":devices,"evidence":evidence,"transitions":transitions,"discovery":input.discovery.as_ref().map(|d|json!({"input_hash":d.input_hash,"source":d.source,"result_summary":d.result_summary,"committed_at":d.committed_at.to_rfc3339()})),"flow":flow});
    Ok(Sha256::digest(serde_json::to_vec(&canonical).map_err(|e| {
        CheckpointError::Invalid(format!("canonical commit serialization failed: {e}"))
    })?)
    .to_vec())
}

fn sample_input(full: bool) -> CommitInput {
    let at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let device = DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445599").unwrap();
    CommitInput {
        checkpoint: CheckpointInput {
            format_version: 1,
            bytes: if full { (0..=255).collect() } else { vec![] },
            source_fingerprint: "r\"eseau\\\n日本語".into(),
            commit_sequence: 7,
            written_at: at,
        },
        devices: if full {
            vec![DeviceProjection {
                device_id: device,
                first_seen_at: at,
                last_seen_at: at,
                owner_name: Some("Café 🏠\n\"owner\"".into()),
                owner_type: None,
                owner_confirmed: true,
            }]
        } else {
            vec![]
        },
        evidence: if full {
            vec![EvidenceProjection {
                device_id: device,
                fact: EvidenceFact {
                    family: EvidenceFamily::LinkLayer,
                    source: "日本語".into(),
                    key: "clé".into(),
                    value: "café\\\n".into(),
                    confidence: 0.9,
                    observed_at: at,
                    expires_at: Some(at),
                    owner_confirmed: false,
                },
            }]
        } else {
            vec![]
        },
        transitions: if full {
            vec![PresenceChanged {
                transition_id: 3,
                device_id: device,
                from: PresenceState::Quiet,
                to: PresenceState::Online,
                occurred_at: at,
                reason: "observé 🏠".into(),
                trigger_source: "日本語".into(),
                trigger_kind: "alive".into(),
                evidence_observed_at: at,
                evidence_valid_until: None,
                trigger_arrival_at: at,
                correction_of: Some(1),
            }]
        } else {
            vec![]
        },
        discovery: if full {
            Some(DiscoveryCommit {
                input_hash: [255; 32],
                source: "日本語".into(),
                result_summary: b"\0\xff\"\\".to_vec(),
                committed_at: at,
            })
        } else {
            None
        },
    }
}

#[test]
fn borrowed_digest_matches_persisted_legacy_encoding_with_empty_optional_and_unicode_data() {
    for full in [false, true] {
        let mut input = sample_input(full);
        for optional in [false, true] {
            if optional {
                for device in &mut input.devices {
                    device.owner_name = None;
                    device.owner_type = Some("résident".into());
                }
                for evidence in &mut input.evidence {
                    evidence.fact.expires_at = None;
                }
                for transition in &mut input.transitions {
                    transition.evidence_valid_until = Some(input.checkpoint.written_at);
                    transition.correction_of = None;
                }
            }
            for flow in [
                None,
                Some(vec![]),
                Some(vec![
                    json!({"scope":"日本語","bytes":[0,1,255],"optional":null}),
                ]),
            ] {
                assert_eq!(
                    logical_commit_digest_extra(&input, flow.clone()).unwrap(),
                    legacy_digest(&input, flow).unwrap()
                );
            }
        }
    }
}

#[test]
fn characterize_large_checkpoint_digest_without_timing_assertions() {
    use std::{hint::black_box, time::Instant};
    let mut input = sample_input(true);
    input.checkpoint.bytes =
        serde_json::to_vec(&json!({"version":1,"padding":"x".repeat(512*1024)})).unwrap();
    let mut legacy_elapsed = std::time::Duration::ZERO;
    let mut borrowed_elapsed = std::time::Duration::ZERO;
    for _ in 0..8 {
        let start = Instant::now();
        let legacy = black_box(legacy_digest(black_box(&input), Some(vec![])).unwrap());
        legacy_elapsed += start.elapsed();
        let start = Instant::now();
        let borrowed =
            black_box(logical_commit_digest_extra(black_box(&input), Some(vec![])).unwrap());
        borrowed_elapsed += start.elapsed();
        assert_eq!(legacy, borrowed);
    }
    println!(
        "digest characterization: bytes={}, iterations=8, legacy_us={}, borrowed_us={}, optimized={}",
        input.checkpoint.bytes.len(),
        legacy_elapsed.as_micros(),
        borrowed_elapsed.as_micros(),
        !cfg!(debug_assertions)
    );
}
