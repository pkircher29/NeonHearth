//! Phone-session PIN accounting: the failure counter, window, and lock are
//! one atomic statement, so concurrent failures never observe a stale count.

use chrono::{Duration, TimeZone, Utc};
use lattice_store::{
    NewPhoneSession, PinFailureOutcome, PinReservation, RemoteAccessRepository, connect_memory,
};
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

    // A step-up grant is refused while the session is locked (this test
    // previously asserted the opposite: a grant cleared a live lock).
    assert!(
        !repo
            .grant_stepup(id, at, at + Duration::minutes(5))
            .await
            .unwrap()
    );
    let row = repo.load_phone_session(id).await.unwrap().unwrap();
    assert_eq!(row.pin_locked_until, Some(at + window));
    assert_eq!(row.stepup_expires_at, None);

    // Once the lock lapses, a grant clears the accounting entirely.
    let unlocked = at + window;
    assert!(
        repo.grant_stepup(id, unlocked, unlocked + Duration::minutes(5))
            .await
            .unwrap()
    );
    let row = repo.load_phone_session(id).await.unwrap().unwrap();
    assert_eq!(row.pin_failed_count, 0);
    assert_eq!(row.pin_window_started_at, None);
    assert_eq!(row.pin_locked_until, None);
}

async fn session(repo: &RemoteAccessRepository, now: chrono::DateTime<Utc>) -> Uuid {
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
    id
}

#[tokio::test]
async fn reservations_admit_at_most_the_budget_however_many_race() {
    let repo = RemoteAccessRepository::new(connect_memory().await.unwrap());
    let now = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
    let window = Duration::minutes(15);
    let id = session(&repo, now).await;
    let attempts = (0..60).map(|_| repo.reserve_pin_attempt(id, now, window, 5));
    let results = futures_util::future::join_all(attempts).await;
    let admitted = results
        .iter()
        .filter(|r| matches!(r.as_ref().unwrap(), PinReservation::Reserved { .. }))
        .count();
    assert_eq!(admitted, 5, "only the budget may be verified");
    assert!(
        results
            .iter()
            .all(|r| !matches!(r.as_ref().unwrap(), PinReservation::NoSession))
    );
    assert_eq!(
        repo.reserve_pin_attempt(Uuid::new_v4(), now, window, 5)
            .await
            .unwrap(),
        PinReservation::NoSession
    );
}

#[tokio::test]
async fn a_spent_budget_locks_and_a_correct_pin_cannot_unlock_it() {
    let repo = RemoteAccessRepository::new(connect_memory().await.unwrap());
    let now = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
    let window = Duration::minutes(15);
    let id = session(&repo, now).await;
    for expected in 1..=5 {
        assert_eq!(
            repo.reserve_pin_attempt(id, now, window, 5).await.unwrap(),
            PinReservation::Reserved { attempt: expected }
        );
        let outcome = repo
            .finish_pin_failure(id, expected, now, window, 5)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.locked_until.is_some(), expected == 5);
    }
    assert!(matches!(
        repo.reserve_pin_attempt(id, now, window, 5).await.unwrap(),
        PinReservation::Locked { .. }
    ));
    assert!(
        !repo
            .grant_stepup(id, now, now + Duration::minutes(5))
            .await
            .unwrap()
    );
    // After the window lapses a new budget opens.
    let later = now + window + Duration::seconds(1);
    assert!(matches!(
        repo.reserve_pin_attempt(id, later, window, 5).await.unwrap(),
        PinReservation::Reserved { attempt: 1 }
    ));
}

#[tokio::test]
async fn touch_never_resurrects_revoked_or_expired_sessions_and_purge_removes_them() {
    let repo = RemoteAccessRepository::new(connect_memory().await.unwrap());
    let now = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
    let live = session(&repo, now).await;
    let revoked = session(&repo, now).await;
    repo.revoke_phone_session(revoked).await.unwrap();
    let new_expiry = now + Duration::days(30);
    assert!(repo.touch_phone_session(live, now, new_expiry).await.unwrap());
    assert!(!repo.touch_phone_session(revoked, now, new_expiry).await.unwrap());
    let far = now + Duration::days(31);
    assert!(!repo.touch_phone_session(live, far, far).await.unwrap());
    let removed = repo
        .purge_dead_phone_sessions(far, Duration::days(7))
        .await
        .unwrap();
    assert_eq!(removed, 2);
    assert!(repo.list_phone_sessions().await.unwrap().is_empty());
}

#[tokio::test]
async fn command_claims_are_durable_exclusive_and_bodies_trimmed() {
    let repo = RemoteAccessRepository::new(connect_memory().await.unwrap());
    let now = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
    let id = session(&repo, now).await;
    let command = Uuid::new_v4();
    let fingerprint = "b".repeat(64);
    assert_eq!(
        repo.claim_command(id, command, &fingerprint, now).await.unwrap(),
        None
    );
    // In flight: a second claim sees an incomplete record.
    let seen = repo
        .claim_command(id, command, &fingerprint, now)
        .await
        .unwrap()
        .unwrap();
    assert!(!seen.completed);
    repo.complete_command(id, command, 200, Some("application/json"), Some(b"{}"), 2)
        .await
        .unwrap();
    let seen = repo
        .claim_command(id, command, &fingerprint, now)
        .await
        .unwrap()
        .unwrap();
    assert!(seen.completed && seen.status == 200 && seen.body == b"{}");
    for _ in 0..4 {
        let other = Uuid::new_v4();
        repo.claim_command(id, other, &fingerprint, now).await.unwrap();
        repo.complete_command(id, other, 204, None, Some(b""), 2)
            .await
            .unwrap();
    }
    // Trimmed to the newest two settled records.
    let first = repo
        .claim_command(id, command, &fingerprint, now)
        .await
        .unwrap();
    assert_eq!(first, None, "the oldest record was evicted");
}
