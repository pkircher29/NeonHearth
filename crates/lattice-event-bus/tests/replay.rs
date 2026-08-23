use chrono::{TimeZone, Utc};
use lattice_domain::{EventPayload, ServiceStatus};
use lattice_event_bus::{EventBus, Resume};

fn payload(detail: impl Into<String>) -> EventPayload {
    EventPayload::ServiceStatus(ServiceStatus {
        state: "ready".to_owned(),
        detail: detail.into(),
    })
}

#[tokio::test]
async fn replays_after_sequence_and_requires_resync_when_gap_is_too_old() {
    let bus = EventBus::new(3, 8);
    for detail in 1..=4 {
        bus.publish(Utc::now(), payload(detail.to_string())).await;
    }

    let replay = bus.resume_after(2).await;
    assert!(
        matches!(replay, Resume::Events(events) if events.iter().map(|event| event.sequence).collect::<Vec<_>>() == vec![3, 4])
    );
    assert_eq!(bus.resume_after(0).await, Resume::SnapshotRequired);
}

#[tokio::test]
async fn resume_at_head_is_empty_and_future_sequence_requires_resync() {
    let bus = EventBus::new(3, 8);
    assert_eq!(bus.resume_after(0).await, Resume::Events(vec![]));
    bus.publish(Utc::now(), payload("1")).await;
    assert_eq!(bus.resume_after(1).await, Resume::Events(vec![]));
    assert_eq!(bus.resume_after(99).await, Resume::SnapshotRequired);
}

#[tokio::test]
async fn subscriber_receives_the_same_sequenced_event() {
    let bus = EventBus::new(3, 8);
    let mut receiver = bus.subscribe();
    let timestamp = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    let expected = bus.publish(timestamp, payload("1")).await;
    assert_eq!(receiver.recv().await.unwrap(), expected);
}

#[tokio::test]
async fn concurrent_publishers_get_unique_monotonic_sequences() {
    let bus = EventBus::new(16, 16);
    let mut tasks = Vec::new();
    for detail in 1..=16 {
        let bus = bus.clone();
        tasks.push(tokio::spawn(async move {
            bus.publish(Utc::now(), payload(detail.to_string()))
                .await
                .sequence
        }));
    }
    let mut sequences = Vec::new();
    for task in tasks {
        sequences.push(task.await.unwrap());
    }
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=16).collect::<Vec<_>>());
    assert!(matches!(bus.resume_after(0).await, Resume::Events(events) if events.len() == 16));
}
