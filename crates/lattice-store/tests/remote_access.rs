//! Phone-session PIN accounting: the failure counter, window, and lock are
//! one atomic statement, so concurrent failures never observe a stale count.

use chrono::{Duration, TimeZone, Utc};
use lattice_store::{NewPhoneSession, PinFailureOutcome, RemoteAccessRepository, connect_memory};
use uuid::Uuid;

#[tokio::test]
async fn pin_failures_are_charged_atomically_windowed_and_lock_at_the_limit() {
    let repo = RemoteAccessRepository::new(connect_memory().await.unwrap());
    let now = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
    let window = Duration::minutes(15);
    let id = Uuid::new_v4();
    repo.insert_phone_session(&NewPhoneSession {
        id,
        secret_hash: "a".repeat(64),
        device_label: "pixel".to_owned(),
        pin_hash: "$argon2id$fixture".to_owned(),
        created_at: now,
        expires_at: now + Duration::days(30),
    })
    .await
    .unwrap();

    // An unknown session charges nothing.
    assert_eq!(
        repo.record_pin_failure(Uuid::new_v4(), now, window, 5)
            .await
            .unwrap(),
        None
    );

    // Four failures inside the window count up without locking; the window
    // stays anchored on the first failure.
    for n in 1..=4u32 {
        let outcome = repo
            .record_pin_failure(id, now + Duration::seconds(i64::from(n)), window, 5)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome,
            PinFailureOutcome {
                failed_count: n,
                locked_until: None,
            }
        );
    }
    let row = repo.load_phone_session(id).await.unwrap().unwrap();
    assert_eq!(row.pin_window_started_at, Some(now + Duration::seconds(1)));

    // The fifth locks until a full window after that failure.
    let fifth_at = now + Duration::seconds(5);
    let outcome = repo
        .record_pin_failure(id, fifth_at, window, 5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        outcome,
        PinFailureOutcome {
            failed_count: 5,
            locked_until: Some(fifth_at + window),
        }
    );
    let row = repo.load_phone_session(id).await.unwrap().unwrap();
    assert_eq!(row.pin_failed_count, 5);
    assert_eq!(row.pin_locked_until, Some(fifth_at + window));

    // Once the window has elapsed a failure opens a fresh one and the lock
    // is gone.
    let later = now + Duration::minutes(16) + Duration::seconds(1);
    let outcome = repo
        .record_pin_failure(id, later, window, 5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        outcome,
        PinFailureOutcome {
            failed_count: 1,
            locked_until: None,
        }
    );
    let row = repo.load_phone_session(id).await.unwrap().unwrap();
    assert_eq!(row.pin_window_started_at, Some(later));
    assert_eq!(row.pin_locked_until, None);

    // Concurrent failures each see the previous one: no two share a count.
    let at = later + Duration::seconds(1);
    let (a, b, c, d) = tokio::join!(
        repo.record_pin_failure(id, at, window, 5),
        repo.record_pin_failure(id, at, window, 5),
        repo.record_pin_failure(id, at, window, 5),
        repo.record_pin_failure(id, at, window, 5),
    );
    let mut counts: Vec<u32> = [a, b, c, d]
        .into_iter()
        .map(|outcome| outcome.unwrap().unwrap().failed_count)
        .collect();
    counts.sort_unstable();
    assert_eq!(counts, [2, 3, 4, 5]);
    let row = repo.load_phone_session(id).await.unwrap().unwrap();
    assert_eq!(row.pin_locked_until, Some(at + window));

    // A step-up grant clears the accounting entirely.
    repo.grant_stepup(id, at + Duration::minutes(5))
        .await
        .unwrap();
    let row = repo.load_phone_session(id).await.unwrap().unwrap();
    assert_eq!(row.pin_failed_count, 0);
    assert_eq!(row.pin_window_started_at, None);
    assert_eq!(row.pin_locked_until, None);
}
