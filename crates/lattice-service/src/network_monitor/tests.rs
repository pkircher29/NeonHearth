use super::*;
use lattice_sensor::{
    Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory, InterfaceRole,
};
use std::net::Ipv4Addr;

fn interface(id: u32, class: InterfaceClass, ip: &str, prefix: u8) -> Interface {
    Interface {
        id: InterfaceId::new(id),
        name: format!("eth{id}"),
        description: None,
        up: true,
        class,
        addresses: vec![Address {
            ip: ip.parse().unwrap(),
            prefix,
        }],
        owner_role: None,
    }
}
#[test]
fn discovery_excludes_non_home_adapters_own_addresses_and_large_subnets() {
    let mut corporate = interface(5, InterfaceClass::PhysicalWired, "10.4.0.1", 24);
    corporate.owner_role = Some(InterfaceRole::Corporate);
    let inventory = InterfaceInventory::new(vec![
        interface(1, InterfaceClass::PhysicalWired, "192.168.1.50", 24),
        interface(2, InterfaceClass::VpnTunnel, "10.2.0.1", 24),
        interface(3, InterfaceClass::PhysicalWifi, "8.8.8.8", 24),
        interface(4, InterfaceClass::PhysicalWired, "10.0.0.1", 8),
        corporate,
    ]);
    let plan = lan::plan(&inventory);
    assert_eq!(plan.targets.len(), 253);
    assert_eq!(plan.skipped, 2);
    assert!(
        plan.targets
            .iter()
            .all(|t| t.interface == 1
                && t.ip != "192.168.1.50".parse::<std::net::Ipv4Addr>().unwrap())
    );
    assert!(
        !plan
            .targets
            .iter()
            .any(|t| t.ip.octets()[3] == 0 || t.ip.octets()[3] == 255)
    );
}
#[test]
fn router_parser_handles_split_sse_and_rejects_unbounded_or_invalid_rates() {
    let mut feed = router::Feed::default();
    for part in b"data: {\"Message\":\"NOTIFICATION_WIFI_vnstat\",\"Field\":{\"rxbytespersecond\":\"1234\",\"txbytespersecond\":42}}\n\n".chunks(3) { feed.push(part).unwrap(); }
    assert_eq!(feed.rate.take(), Some((1234.0, 42.0)));
    for value in ["-1", "NaN", "Infinity", "1000000000001"] {
        feed.push(format!("data: {{\"Message\":\"NOTIFICATION_WIFI_vnstat\",\"Field\":{{\"rxbytespersecond\":\"{value}\",\"txbytespersecond\":0}}}}\n").as_bytes()).unwrap();
        assert!(feed.rate.is_none());
    }
    feed.push(b"data: {\"Message\":\"SSID\",\"Field\":{\"secret\":\"not retained\"}}\n")
        .unwrap();
    assert!(feed.rate.is_none());
    assert!(feed.push(&vec![b'x'; 65537]).is_err());
}
#[tokio::test]
async fn failed_or_partial_scans_cannot_create_departures_and_returns_are_persisted() {
    let hub = NetworkMonitor::new(lattice_store::connect_memory().await.unwrap());
    let now = Utc::now();
    let sighting = lan::Sighting {
        interface: 1,
        ip: "192.168.1.2".into(),
        mac: "02:12:34:56:78:90".into(),
    };
    let target = lan::Target {
        interface: 1,
        source: "192.168.1.1".parse().unwrap(),
        ip: "192.168.1.2".parse().unwrap(),
    };
    hub.persist_sightings(
        std::slice::from_ref(&sighting),
        std::slice::from_ref(&target),
        true,
        now,
    )
    .await
    .unwrap();
    for i in 1..4 {
        hub.persist_sightings(
            &[],
            std::slice::from_ref(&target),
            false,
            now + chrono::Duration::minutes(i),
        )
        .await
        .unwrap();
    }
    assert_eq!(hub.snapshot(5).await.unwrap().devices[0].missed, 0);
    hub.persist_sightings(&[], &[], true, now + chrono::Duration::minutes(4))
        .await
        .unwrap();
    assert_eq!(hub.snapshot(5).await.unwrap().devices[0].missed, 0);
    for i in 5..7 {
        hub.persist_sightings(
            &[],
            std::slice::from_ref(&target),
            true,
            now + chrono::Duration::minutes(i),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        hub.snapshot(5).await.unwrap().events[0].kind,
        "not_responding"
    );
    hub.persist_sightings(
        &[sighting],
        &[target],
        true,
        now + chrono::Duration::minutes(7),
    )
    .await
    .unwrap();
    let restored = NetworkMonitor::new(hub.pool.clone())
        .snapshot(5)
        .await
        .unwrap();
    assert_eq!(restored.events[0].kind, "responding_again");
    assert_eq!(restored.events.len(), 3);
    assert_eq!(restored.devices[0].first_seen, now.to_rfc3339());
    assert_eq!(restored.devices[0].missed, 0);
}
#[tokio::test]
async fn monitor_routes_require_owner_and_reject_external_targets() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let pool = lattice_store::connect_memory().await.unwrap();
    let token = "owner-network-test-012345678901234567890123456789";
    let app = crate::app(
        crate::AppState::new(token, lattice_store::M2StateRepository::new(pool)).unwrap(),
    );
    for (method, path) in [
        ("GET", "/api/v1/network/monitor"),
        ("GET", "/api/v1/network/monitor/settings"),
        ("POST", "/api/v1/network/discover"),
        ("POST", "/api/v1/network/discover/cancel"),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    for ip in [
        "8.8.8.8",
        "127.0.0.1",
        "169.254.169.254",
        "router.example",
        "192.168.1.1/path",
        "192.168.1.1@8.8.8.8",
    ] {
        let body = serde_json::json!({"router_ip":ip,"router_port":8080,"interval_seconds":120,"discovery_enabled":false});
        let response = app
            .clone()
            .oneshot(
                Request::put("/api/v1/network/monitor/settings")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn discovery_waits_for_other_database_writers_before_reading_previous_state() {
    let directory = tempfile::tempdir().unwrap();
    let pool = lattice_store::connect_path(&directory.path().join("concurrent.db"))
        .await
        .unwrap();
    let hub = NetworkMonitor::new(pool.clone());
    let mut writer = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    sqlx::query("INSERT INTO network_presence(interface,mac,ip,first_seen,last_seen,missed) VALUES(1,'02:12:34:56:78:90','192.168.1.2','2026-09-01T00:00:00Z','2026-09-01T00:00:00Z',2)").execute(&mut *writer).await.unwrap();
    let task = tokio::spawn(async move {
        hub.persist_sightings(
            &[lan::Sighting {
                interface: 1,
                ip: "192.168.1.2".into(),
                mac: "02:12:34:56:78:90".into(),
            }],
            &[],
            false,
            Utc::now(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    writer.commit().await.unwrap();
    task.await.unwrap().unwrap();
    let event: String = sqlx::query_scalar("SELECT kind FROM network_presence_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(event, "responding_again");
}
#[tokio::test]
async fn sweep_snapshots_and_plans_once_and_probes_every_target_once() {
    use std::sync::atomic::AtomicUsize;
    let hub = NetworkMonitor::new(lattice_store::connect_memory().await.unwrap());
    *hub.discovery.lock().await = Some(Discovery::default());
    let snapshots = Arc::new(AtomicUsize::new(0));
    let plans = Arc::new(AtomicUsize::new(0));
    let probed: Arc<std::sync::Mutex<Vec<Ipv4Addr>>> = Arc::default();
    let batches = Arc::new(AtomicUsize::new(0));
    let snapshot = {
        let snapshots = Arc::clone(&snapshots);
        move || {
            snapshots.fetch_add(1, Ordering::SeqCst);
            Ok(InterfaceInventory::new(Vec::new()))
        }
    };
    let planner = {
        let plans = Arc::clone(&plans);
        move |_: &InterfaceInventory| {
            plans.fetch_add(1, Ordering::SeqCst);
            lan::Plan {
                targets: (1..=200u8)
                    .map(|n| lan::Target {
                        interface: 1,
                        source: Ipv4Addr::new(192, 168, 1, 250),
                        ip: Ipv4Addr::new(192, 168, 1, n),
                    })
                    .collect(),
                skipped: 0,
            }
        }
    };
    let prober = {
        let probed = Arc::clone(&probed);
        let batches = Arc::clone(&batches);
        move |batch: Vec<lan::Target>, _names: Arc<BTreeMap<u32, String>>| {
            let probed = Arc::clone(&probed);
            batches.fetch_add(1, Ordering::SeqCst);
            async move {
                probed
                    .lock()
                    .unwrap()
                    .extend(batch.iter().map(|target| target.ip));
                batch
                    .iter()
                    .map(|_| Ok::<Option<lan::Sighting>, ()>(None))
                    .collect::<Vec<_>>()
            }
        }
    };
    hub.run_sweep(snapshot, planner, prober).await.unwrap();
    assert_eq!(
        snapshots.load(Ordering::SeqCst),
        1,
        "one interface snapshot per sweep"
    );
    assert_eq!(plans.load(Ordering::SeqCst), 1, "one plan per sweep");
    assert!(
        batches.load(Ordering::SeqCst) > 1,
        "the sweep must span several batches"
    );
    let mut probed = probed.lock().unwrap().clone();
    probed.sort();
    let expected: Vec<Ipv4Addr> = (1..=200u8).map(|n| Ipv4Addr::new(192, 168, 1, n)).collect();
    assert_eq!(
        probed, expected,
        "every planned target is probed exactly once"
    );
    let status = hub.discovery.lock().await.clone().unwrap();
    assert_eq!(
        (status.total, status.completed, status.errors),
        (200, 200, 0)
    );
}
#[test]
fn router_prune_runs_first_then_at_most_once_per_interval() {
    let start = std::time::Instant::now();
    assert!(router::prune_due(None, start));
    assert!(!router::prune_due(Some(start), start));
    assert!(!router::prune_due(
        Some(start),
        start + Duration::from_secs(59)
    ));
    assert!(router::prune_due(
        Some(start),
        start + Duration::from_secs(60)
    ));
    assert!(router::prune_due(
        Some(start),
        start + Duration::from_secs(3600)
    ));
    // A clock that reads earlier than the last prune must not trigger a prune.
    assert!(!router::prune_due(
        Some(start + Duration::from_secs(120)),
        start
    ));
}
#[tokio::test]
async fn router_prune_drops_day_old_and_excess_samples_and_keeps_fresh_ones() {
    let pool = lattice_store::connect_memory().await.unwrap();
    let now: i64 = 2_000_000_000;
    for (at, label) in [
        (now - 86_401, "old"),
        (now - 86_400, "edge"),
        (now - 5, "fresh"),
    ] {
        sqlx::query(
            "INSERT INTO network_router_samples(at,source,download,upload) VALUES(?,?,1,1)",
        )
        .bind(at)
        .bind(label)
        .execute(&pool)
        .await
        .unwrap();
    }
    router::prune_samples(&pool, now).await.unwrap();
    let kept: Vec<String> =
        sqlx::query_scalar("SELECT source FROM network_router_samples ORDER BY at")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(kept, ["edge", "fresh"]);
    // Beyond the row ceiling only the newest rows survive, even when all are recent.
    sqlx::query("DELETE FROM network_router_samples")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 50004) INSERT INTO network_router_samples(at,source,download,upload) SELECT ? + i, 's', 0, 0 FROM n")
        .bind(now - 80_000)
        .execute(&pool)
        .await
        .unwrap();
    router::prune_samples(&pool, now).await.unwrap();
    let (count, oldest): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), MIN(at) FROM network_router_samples")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 50_000);
    assert_eq!(oldest, now - 80_000 + 5);
}
#[tokio::test]
async fn router_settings_are_cached_between_rechecks_and_a_change_is_picked_up_afterwards() {
    use std::sync::atomic::AtomicUsize;
    let start = std::time::Instant::now();
    let current = Settings::default();
    let changed = Settings {
        router_port: 9090,
        ..Settings::default()
    };
    let reads = Arc::new(AtomicUsize::new(0));
    let reader = |value: Settings| {
        let reads = Arc::clone(&reads);
        move || {
            reads.fetch_add(1, Ordering::SeqCst);
            async move { Some(value) }
        }
    };
    let mut watch = router::SettingsWatch::new(start);
    // A burst of samples inside the recheck period never touches the database.
    for ms in (0..5000).step_by(50) {
        let at = start + Duration::from_millis(ms);
        assert!(
            watch
                .still_current(at, reader(changed.clone()), &current)
                .await
        );
    }
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    // Once the period has elapsed one read confirms unchanged settings...
    assert!(
        watch
            .still_current(
                start + Duration::from_secs(5),
                reader(current.clone()),
                &current
            )
            .await
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    // ...and restarts the period: the next samples are served from the cache again.
    assert!(
        watch
            .still_current(
                start + Duration::from_secs(9),
                reader(changed.clone()),
                &current
            )
            .await
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    // After the next period a changed setting is noticed (and an unreadable one too).
    assert!(
        !watch
            .still_current(start + Duration::from_secs(10), reader(changed), &current)
            .await
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert!(
        !watch
            .still_current(start + Duration::from_secs(10), || async { None }, &current)
            .await
    );
}

#[tokio::test]
async fn a_stalled_router_feed_is_abandoned_after_the_idle_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    // A router that answers with valid event-stream headers and one event, then
    // goes silent without ever closing the connection.
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut buffer = [0u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = socket.read(&mut buffer).await.unwrap();
            if read == 0 {
                return;
            }
            head.extend_from_slice(&buffer[..read]);
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\ndata: {\"Message\":\"keepalive\"}\n\n",
            )
            .await
            .unwrap();
        socket.flush().await.unwrap();
        std::future::pending::<()>().await;
    });

    // Real time: reqwest's timeout is not driven by paused tokio time. The idle
    // timeout is 200 ms; the outer bound only keeps a regression from hanging.
    let client = router::feed_client_builder(Ipv4Addr::LOCALHOST, Duration::from_millis(200))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{port}/cgi-bin/sse_cgi");
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        let response = router::open_feed(&client, &url)
            .await
            .expect("the feed opens on a 200 event stream");
        let mut stream = response.bytes_stream();
        let mut chunks = 0;
        loop {
            match stream.next().await {
                Some(Ok(_)) => chunks += 1,
                Some(Err(error)) => break (chunks, Some(error)),
                None => break (chunks, None),
            }
        }
    })
    .await;
    server.abort();

    let (chunks, error) = outcome.expect("the idle timeout, not the outer bound, ended the read");
    assert!(chunks >= 1, "the event sent before the stall is delivered");
    let error = error.expect("a stalled stream ends with an error, not a clean close");
    assert!(error.is_timeout(), "{error}");
}
