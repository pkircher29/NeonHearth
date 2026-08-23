use axum::{body::Body, http::Request};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use lattice_domain::{EventPayload, ServiceStatus};
use lattice_event_bus::EventBus;
use lattice_service::ws::{ServerMessage, resume_messages};
use lattice_service::{AppState, app};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

async fn issue_ticket(state: &AppState) -> String {
    let response = app(state.clone())
        .oneshot(
            Request::post("/api/v1/events/ticket")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn start_server(state: AppState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    format!("ws://{address}/api/v1/events")
}

fn payload() -> EventPayload {
    EventPayload::ServiceStatus(ServiceStatus {
        state: "ready".to_owned(),
        detail: "test".to_owned(),
    })
}

#[tokio::test]
async fn resume_requires_resync_when_replay_has_a_gap() {
    let bus = EventBus::new(1, 8);
    bus.publish(Utc::now(), payload()).await;
    bus.publish(Utc::now(), payload()).await;

    assert_eq!(
        resume_messages(&bus, 0).await,
        vec![ServerMessage::ResyncRequired]
    );
}

#[tokio::test]
async fn resume_returns_events_after_cursor_in_order_and_empty_at_head() {
    let bus = EventBus::new(8, 8);
    bus.publish(Utc::now(), payload()).await;
    bus.publish(Utc::now(), payload()).await;
    bus.publish(Utc::now(), payload()).await;

    let messages = resume_messages(&bus, 1).await;
    assert!(
        matches!(messages.as_slice(), [ServerMessage::Event(first), ServerMessage::Event(second)] if first.sequence == 2 && second.sequence == 3)
    );
    assert!(resume_messages(&bus, 3).await.is_empty());
}

#[tokio::test]
async fn websocket_streams_events_and_consumes_ticket_once() {
    let state = AppState::new(TOKEN).unwrap();
    let address = start_server(state.clone()).await;
    let ticket = issue_ticket(&state).await;
    let (mut socket, _) = connect_async(format!("{address}?ticket={ticket}&after_sequence=0"))
        .await
        .unwrap();

    let ping_payload = b"neonhearth-ping".to_vec();
    socket
        .send(Message::Ping(ping_payload.clone().into()))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Message::Pong(ping_payload.into())
    );

    state.events().publish(Utc::now(), payload()).await;
    let message = socket.next().await.unwrap().unwrap();
    let Message::Text(message) = message else {
        panic!("expected text event")
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&message).unwrap()["type"],
        "event"
    );

    let reused = connect_async(format!("{address}?ticket={ticket}&after_sequence=1")).await;
    let tokio_tungstenite::tungstenite::Error::Http(response) = reused.unwrap_err() else {
        panic!("expected rejected HTTP upgrade")
    };
    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn websocket_stale_cursor_receives_resync_required() {
    let state = AppState::new(TOKEN).unwrap();
    for _ in 0..4097 {
        state.events().publish(Utc::now(), payload()).await;
    }
    let address = start_server(state.clone()).await;
    let ticket = issue_ticket(&state).await;
    let (mut socket, _) = connect_async(format!("{address}?ticket={ticket}&after_sequence=0"))
        .await
        .unwrap();

    let message = socket.next().await.unwrap().unwrap();
    let Message::Text(message) = message else {
        panic!("expected text resync")
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&message).unwrap(),
        serde_json::json!({"type": "resync_required"})
    );
    assert!(matches!(socket.next().await, Some(Ok(Message::Close(_)))));
}

#[tokio::test]
async fn websocket_rejects_unsolicited_text_with_unsupported_close_code() {
    let state = AppState::new(TOKEN).unwrap();
    let address = start_server(state.clone()).await;
    let ticket = issue_ticket(&state).await;
    let (mut socket, _) = connect_async(format!("{address}?ticket={ticket}&after_sequence=0"))
        .await
        .unwrap();

    socket.send(Message::Text("command".into())).await.unwrap();
    let Some(Ok(Message::Close(Some(frame)))) = socket.next().await else {
        panic!("expected close frame")
    };
    assert_eq!(
        frame.code,
        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Unsupported
    );
}
