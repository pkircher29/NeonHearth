//! Opt-in acceptance against the authenticated local Mosquitto hub.
use lattice_service::{AppState, mqtt};
use lattice_store::{M2StateRepository, connect_memory};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};
use tokio::sync::{mpsc, watch};

#[tokio::test]
#[ignore = "requires NEONHEARTH_TEST_MQTT_DIRECTORY and the local authenticated broker"]
async fn broker_rejects_anonymous_enforces_topics_and_delivers_bridge_inventory() {
    let directory = PathBuf::from(
        std::env::var_os("NEONHEARTH_TEST_MQTT_DIRECTORY")
            .expect("set the private test broker directory"),
    );
    let accounts: Value =
        serde_json::from_slice(&std::fs::read(directory.join("accounts.json")).unwrap()).unwrap();
    let config: Value =
        serde_json::from_slice(&std::fs::read(directory.join("client.json")).unwrap()).unwrap();
    let port = config["port"].as_u64().unwrap() as u16;
    let options = MqttOptions::new("neonhearth-anonymous-test", "127.0.0.1", port);
    let (_, mut anonymous) = AsyncClient::new(options, 4);
    let anonymous_result = tokio::time::timeout(Duration::from_secs(5), anonymous.poll())
        .await
        .expect("broker must respond");
    assert!(
        anonymous_result.is_err(),
        "anonymous MQTT access must be rejected"
    );

    let mut options = MqttOptions::new("neonhearth-reader-test", "127.0.0.1", port);
    options.set_credentials("homeassistant", accounts["homeassistant"].as_str().unwrap());
    let (reader, mut events) = AsyncClient::new(options, 8);
    reader
        .subscribe("neonhearth/#", QoS::AtLeastOnce)
        .await
        .unwrap();
    let (messages, mut receive) = mpsc::channel(32);
    let reader_task = tokio::spawn(async move {
        loop {
            match events.poll().await {
                Ok(Event::Incoming(Packet::Publish(message))) => {
                    if messages.send(message).await.is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    let state = AppState::new(
        "mqtt-test-owner-0123456789abcdefghijkl",
        M2StateRepository::new(connect_memory().await.unwrap()),
    )
    .unwrap();
    let (stop, shutdown) = watch::channel(false);
    let bridge = mqtt::start(state.clone(), directory.join("client.json"), shutdown);
    let payload = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let message = receive.recv().await.expect("reader alive");
            if message.topic == "neonhearth/automation/inventory" {
                break message.payload;
            }
        }
    })
    .await
    .expect("bridge must publish inventory");
    let inventory: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(inventory["api_version"], "v1");
    assert_eq!(inventory["devices"], json!([]));
    assert!(!String::from_utf8_lossy(&payload).contains(accounts["neonhearth"].as_str().unwrap()));
    assert_eq!(
        state.automation().snapshot().await.unwrap().mqtt.status,
        "connected"
    );

    let mut options = MqttOptions::new("neonhearth-device-test", "127.0.0.1", port);
    options.set_credentials("test-device", accounts["test-device"].as_str().unwrap());
    let (device, mut events) = AsyncClient::new(options, 8);
    let device_task = tokio::spawn(async move { while events.poll().await.is_ok() {} });
    // The second publish is an ordering fence on this connection. The reader
    // must receive the permitted message without ever receiving the forged one.
    device
        .publish(
            "neonhearth/network/forged",
            QoS::AtLeastOnce,
            false,
            "forged",
        )
        .await
        .unwrap();
    device
        .publish(
            "neonhearth/devices/test-device/state",
            QoS::AtLeastOnce,
            false,
            "fixture-state",
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let message = receive.recv().await.expect("reader alive");
            assert_ne!(
                message.topic, "neonhearth/network/forged",
                "device ACL must deny the bridge namespace"
            );
            if message.topic == "neonhearth/devices/test-device/state" {
                assert_eq!(&message.payload[..], b"fixture-state");
                break;
            }
        }
    })
    .await
    .expect("allowed device topic must arrive");
    stop.send(true).unwrap();
    bridge.await.unwrap();
    reader_task.abort();
    device_task.abort();
}
