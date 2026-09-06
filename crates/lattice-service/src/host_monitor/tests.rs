use super::*;
use lattice_store::connect_memory;
use serde_json::json;

fn snapshot(counter: u64, app: &str) -> HostSnapshot {
    HostSnapshot {
        observed_at: Utc::now().to_rfc3339(),
        status: "ready".into(),
        interfaces: vec![
            InterfaceCounter {
                id: "physical".into(),
                physical: true,
                sent_bytes: counter,
                received_bytes: counter,
                ..Default::default()
            },
            InterfaceCounter {
                id: "vpn".into(),
                physical: false,
                sent_bytes: counter * 10,
                received_bytes: counter * 10,
                ..Default::default()
            },
        ],
        applications: vec![Application {
            app_id: app.into(),
            name: format!("{app}.exe"),
            executable: Some(format!("C:/fixtures/{app}.exe")),
            pid: 100,
            started: "1".into(),
            ..Default::default()
        }],
        connections: vec![Connection {
            connection_id: format!("{app}-connection"),
            app_id: app.into(),
            pid: 100,
            protocol: "tcp".into(),
            local_address: "192.0.2.1".into(),
            local_port: 12345,
            remote_address: Some("198.51.100.1".into()),
            remote_port: Some(443),
            state: "established".into(),
            sent_bytes: Some(counter),
            received_bytes: Some(counter),
        }],
        ..Default::default()
    }
}
#[test]
fn measurement_excludes_virtual_double_counting_resets_new_connections_and_sleep_gaps() {
    let old = snapshot(100, "a");
    let new = snapshot(200, "a");
    let samples = sample_delta(&old, &new, 2000);
    assert_eq!(samples.len(), 2);
    assert_eq!(samples[0].sent_bytes, 100);
    assert_eq!(samples[1].sent_bytes, 100);
    assert!(sample_delta(&new, &old, 2000).is_empty());
    assert!(sample_delta(&old, &new, 30_000).is_empty());
    let other = snapshot(200, "b");
    assert_eq!(sample_delta(&old, &other, 2000).len(), 1);
    let mut unavailable = new;
    unavailable.connections[0].sent_bytes = None;
    assert_eq!(sample_delta(&old, &unavailable, 2000).len(), 1);
}
#[tokio::test]
async fn persists_usage_history_alerts_and_privacy_without_mutating_guard() {
    let pool = connect_memory().await.unwrap();
    let monitor = HostMonitor::new(pool.clone());
    let old = snapshot(100, "a");
    let new = snapshot(200, "a");
    monitor.persist(&old, None, &[]).await.unwrap();
    monitor
        .persist(&new, Some(&old), &sample_delta(&old, &new, 2000))
        .await
        .unwrap();
    let history = monitor.history(60, None).await.unwrap();
    assert_eq!(history["points"][0]["sent_bytes"], 100);
    assert_eq!(history["alerts"], json!([]));
    let next = snapshot(250, "b");
    monitor
        .persist(&next, Some(&new), &sample_delta(&new, &next, 2000))
        .await
        .unwrap();
    let history = monitor.history(60, None).await.unwrap();
    assert_eq!(history["alerts"][0]["kind"], "new_application");
    let id = history["alerts"][0]["id"].as_i64().unwrap();
    assert!(monitor.acknowledge(id).await.unwrap());
    let app = monitor.history(60, Some("a")).await.unwrap();
    assert_eq!(app["points"][0]["received_bytes"], 100);
    assert_eq!(app["connections"].as_array().unwrap().len(), 1);
    let mut settings = monitor.settings().await.unwrap();
    settings.record_history = false;
    monitor.update_settings(&settings).await.unwrap();
    monitor
        .persist(&snapshot(300, "private"), Some(&next), &[])
        .await
        .unwrap();
    let recorded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM host_apps WHERE app_id='private'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(recorded, 0);
    let devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(devices, 0);
}
#[test]
fn firewall_protects_monitoring_remote_access_and_system_programs() {
    for path in [
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\NeonHearth\\lattice-service.exe",
        "C:\\Tools\\tailscale.exe",
        "C:\\Tools\\mosquitto.exe",
    ] {
        assert!(firewall::protected_program(path));
    }
    assert!(!firewall::protected_program(
        "C:\\Fixtures\\network-test.exe"
    ));
}
#[cfg(windows)]
#[tokio::test]
async fn native_windows_inventory_identifies_an_owned_tcp_connection_without_sending_requests() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(address).await.unwrap();
    let (_peer, _) = listener.accept().await.unwrap();
    let snapshot = tokio::task::spawn_blocking(platform::snapshot)
        .await
        .unwrap()
        .unwrap();
    let connection = snapshot
        .connections
        .iter()
        .find(|c| {
            c.local_port == client.local_addr().unwrap().port()
                && c.remote_port == Some(address.port())
                && c.pid == std::process::id()
        })
        .unwrap();
    assert_eq!(connection.protocol, "tcp");
    assert_eq!(connection.state, "established");
    let app = snapshot
        .applications
        .iter()
        .find(|a| a.app_id == connection.app_id)
        .unwrap();
    assert!(app.executable.is_some());
    assert!(!app.started.is_empty());
    assert!(snapshot.memory_total_bytes.is_some());
}
