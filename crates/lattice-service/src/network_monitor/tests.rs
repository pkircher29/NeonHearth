use super::*;
use lattice_sensor::{
    Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory, InterfaceRole,
};

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
