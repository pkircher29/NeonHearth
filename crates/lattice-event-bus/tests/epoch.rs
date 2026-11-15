use chrono::Utc;
use lattice_domain::{EventPayload, ServiceStatus};
use lattice_event_bus::{EventBus, Resume};

fn payload() -> EventPayload {
    EventPayload::ServiceStatus(ServiceStatus {
        state: "ready".to_owned(),
        detail: "x".to_owned(),
    })
}

/// Finding 11: sequence numbers restart at 1 after a restart, so a client
/// holding (old epoch, 5) must not be resumed from the new run's event 6+.
#[tokio::test]
async fn position_from_another_epoch_requires_a_snapshot() {
    let old = EventBus::new(16, 8);
    std::thread::sleep(std::time::Duration::from_millis(2));
    let restarted = EventBus::new(16, 8);
    assert_ne!(old.epoch(), restarted.epoch());
    for _ in 0..10 {
        restarted.publish(Utc::now(), payload()).await;
    }
    // Legacy epoch-less resume silently mixes runs (kept for compatibility).
    assert!(matches!(restarted.resume_after(5).await, Resume::Events(e) if e.len() == 5));
    // Epoch-aware resume refuses.
    assert_eq!(
        restarted.resume_after_epoch(Some(old.epoch()), 5).await,
        Resume::SnapshotRequired
    );
    assert!(matches!(
        restarted.resume_after_epoch(Some(restarted.epoch()), 5).await,
        Resume::Events(e) if e.len() == 5
    ));
    assert!(matches!(
        restarted.resume_after_epoch(None, 5).await,
        Resume::Events(e) if e.len() == 5
    ));
}

#[tokio::test]
async fn subscribe_and_resume_loses_nothing_between_replay_and_live() {
    let bus = EventBus::new(16, 64);
    bus.publish(Utc::now(), payload()).await;
    let (mut receiver, resume) = bus.subscribe_and_resume(Some(bus.epoch()), 0).await;
    let Resume::Events(replayed) = resume else {
        panic!("expected replay");
    };
    assert_eq!(replayed.len(), 1);
    bus.publish(Utc::now(), payload()).await;
    let live = receiver.recv().await.unwrap();
    assert_eq!(live.sequence, 2);
    let (_receiver, stale) = bus.subscribe_and_resume(Some(bus.epoch() + 1), 0).await;
    assert_eq!(stale, Resume::SnapshotRequired);
}
