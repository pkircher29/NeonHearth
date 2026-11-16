//! Adding and removing a camera through the real router.
//!
//! No camera, no real ffmpeg, no internet and no privileges: the ONVIF side is
//! either a scripted in-process transport or the real HTTP transport talking to
//! a loopback fake device through its explicit test seam, the vault is the
//! in-memory test vault, the network is a fixed interface list, and nothing is
//! ever spawned.

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use lattice_camera::{
    CameraId, FakeMediaProcessFactory, OnvifAction, OnvifCredential, OnvifError, OnvifRequest,
    OnvifResponseWriter, OnvifTransport, StreamId, TargetAddress,
};
use lattice_sensor::{Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory};
use lattice_service::{
    AppState, FakeVault, Vault, app,
    cameras::{
        CameraSessionError, CameraSessionManager, CameraTargetRegistry,
        FakeAuthorizedRtspConnector,
        onboarding::{
            ApprovedHost, CameraOnboarding, CameraTargetBook, FixedInterfaces, OnvifConnector,
        },
        onvif_http::{
            ForeignServiceFlag, HttpOnvifTransport,
            fake_device::{Behavior, Config, FakeOnvifDevice},
        },
    },
};
use lattice_store::{CameraRepository, M2StateRepository, connect_memory};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
const USER: &str = "camera-user";
const PASSWORD: &str = "p@ss:w/rd%41-sentinel";
const ADDRESS: &str = "192.168.1.50";
const RTSP: &str = "rtsp://192.168.1.50:8554/main";

fn interface(name: &str, up: bool, ip: &str, prefix: u8) -> Interface {
    Interface {
        id: InterfaceId::new(if name == "eth0" { 2 } else { 3 }),
        name: name.to_owned(),
        description: None,
        up,
        class: InterfaceClass::PhysicalWired,
        addresses: vec![Address {
            ip: ip.parse().unwrap(),
            prefix,
        }],
        owner_role: None,
    }
}

fn network(eth0_up: bool) -> InterfaceInventory {
    InterfaceInventory::new(vec![
        interface("eth0", eth0_up, "192.168.1.10", 24),
        interface("eth1", true, "10.5.0.2", 24),
    ])
}

// --- a scripted ONVIF transport ---------------------------------------------

#[derive(Clone)]
enum Script {
    /// A camera that accepts USER/PASSWORD and returns this stream address.
    Camera { stream_uri: String, profiles: usize },
    /// Refuses every sign-in.
    RefusesSignIn,
    /// Nothing answers.
    Silent,
}

struct ScriptedTransport {
    script: Script,
    calls: Arc<AtomicUsize>,
    audited_before_contact: Arc<AtomicBool>,
    pool: SqlitePool,
}

#[async_trait]
impl OnvifTransport for ScriptedTransport {
    async fn request(
        &self,
        target: &TargetAddress,
        request: &OnvifRequest,
        credential: Option<&OnvifCredential>,
        response: &mut OnvifResponseWriter,
    ) -> Result<(), OnvifError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            // The intent must already be in the audit log before the first byte
            // goes to the camera.
            let recorded: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_log WHERE action = 'camera_add_requested'",
            )
            .fetch_one(&self.pool)
            .await
            .unwrap();
            self.audited_before_contact
                .store(recorded == 1, Ordering::SeqCst);
        }
        assert_eq!(target.address(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
        let (stream_uri, profiles) = match &self.script {
            Script::Silent => return Err(OnvifError::Timeout),
            Script::RefusesSignIn => return Err(OnvifError::Authentication),
            Script::Camera {
                stream_uri,
                profiles,
            } => (stream_uri.clone(), *profiles),
        };
        let credential = credential.ok_or(OnvifError::Authentication)?;
        if credential.username() != USER || credential.password().expose_secret() != PASSWORD {
            return Err(OnvifError::Authentication);
        }
        let (action, body) = match request.action() {
            OnvifAction::GetDeviceInformation => ("http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse", "<tds:GetDeviceInformationResponse><tds:Manufacturer>FixtureCam</tds:Manufacturer><tds:Model>M4</tds:Model><tds:FirmwareVersion>2.1</tds:FirmwareVersion><tds:SerialNumber>OWNER-42</tds:SerialNumber></tds:GetDeviceInformationResponse>".to_owned()),
            OnvifAction::GetCapabilities => ("http://www.onvif.org/ver10/device/wsdl/GetCapabilitiesResponse", "<tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media/></tds:Capabilities></tds:GetCapabilitiesResponse>".to_owned()),
            OnvifAction::GetProfiles => {
                let items: String = (0..profiles)
                    .map(|n| format!("<trt:Profiles token=\"profile{n}\"/>"))
                    .collect();
                ("http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse", format!("<trt:GetProfilesResponse>{items}</trt:GetProfilesResponse>"))
            }
            OnvifAction::GetStreamUri { .. } => ("http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse", format!("<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>{stream_uri}</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>")),
            OnvifAction::GetSystemDateAndTime => ("http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse", "<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:DateTimeType>NTP</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings><tt:UTCDateTime><tt:Time><tt:Hour>12</tt:Hour><tt:Minute>34</tt:Minute><tt:Second>56</tt:Second></tt:Time><tt:Date><tt:Year>2026</tt:Year><tt:Month>8</tt:Month><tt:Day>24</tt:Day></tt:Date></tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>".to_owned()),
        };
        response.append_chunk(format!("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Header><wsa:Action>{action}</wsa:Action><wsa:RelatesTo>{}</wsa:RelatesTo></s:Header><s:Body>{body}</s:Body></s:Envelope>", request.message_id().as_str()).as_bytes())
    }
}

struct ScriptedConnector {
    script: Script,
    calls: Arc<AtomicUsize>,
    audited_before_contact: Arc<AtomicBool>,
    pool: SqlitePool,
}

impl OnvifConnector for ScriptedConnector {
    fn transport(
        &self,
        host: &ApprovedHost,
        _: ForeignServiceFlag,
    ) -> Result<Arc<dyn OnvifTransport>, OnvifError> {
        assert_eq!(host.address, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(host.interface_name, "eth0");
        Ok(Arc::new(ScriptedTransport {
            script: self.script.clone(),
            calls: self.calls.clone(),
            audited_before_contact: self.audited_before_contact.clone(),
            pool: self.pool.clone(),
        }))
    }
}

/// The real HTTP transport aimed at a loopback fake device.
struct LoopbackConnector(SocketAddr);

impl OnvifConnector for LoopbackConnector {
    fn transport(
        &self,
        host: &ApprovedHost,
        foreign_service: ForeignServiceFlag,
    ) -> Result<Arc<dyn OnvifTransport>, OnvifError> {
        Ok(Arc::new(HttpOnvifTransport::with_loopback_endpoint(
            host.address,
            self.0,
            foreign_service,
        )?))
    }
}

// --- the rig ----------------------------------------------------------------

struct Rig {
    router: Router,
    pool: SqlitePool,
    vault: Arc<FakeVault>,
    book: Arc<CameraTargetBook>,
    manager: Arc<CameraSessionManager>,
    interfaces: Arc<FixedInterfaces>,
    media: Arc<FakeMediaProcessFactory>,
    calls: Arc<AtomicUsize>,
    audited_before_contact: Arc<AtomicBool>,
    _directory: tempfile::TempDir,
}

impl Rig {
    async fn scripted(script: Script) -> Self {
        Self::build(|pool, calls, audited| {
            Arc::new(ScriptedConnector {
                script,
                calls,
                audited_before_contact: audited,
                pool,
            })
        })
        .await
    }

    async fn loopback(device: SocketAddr) -> Self {
        Self::build(|_, _, _| Arc::new(LoopbackConnector(device))).await
    }

    async fn build(
        connector: impl FnOnce(SqlitePool, Arc<AtomicUsize>, Arc<AtomicBool>) -> Arc<dyn OnvifConnector>,
    ) -> Self {
        let pool = connect_memory().await.unwrap();
        let vault = Arc::new(FakeVault::new());
        let interfaces = Arc::new(FixedInterfaces::new(network(true)));
        let book = Arc::new(CameraTargetBook::new(interfaces.clone()));
        let media = Arc::new(FakeMediaProcessFactory::new());
        let directory = tempfile::tempdir().unwrap();
        let manager = Arc::new(
            CameraSessionManager::new(
                CameraRepository::new(pool.clone()),
                vault.clone(),
                book.clone(),
                media.clone(),
                Arc::new(FakeAuthorizedRtspConnector::new(Vec::new())),
                PathBuf::from(directory.path()),
                Default::default(),
            )
            .unwrap(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let audited = Arc::new(AtomicBool::new(false));
        let onboarding = Arc::new(CameraOnboarding::new(
            pool.clone(),
            vault.clone(),
            book.clone(),
            manager.clone(),
            interfaces.clone(),
            connector(pool.clone(), calls.clone(), audited.clone()),
        ));
        let state = AppState::new(TOKEN, M2StateRepository::new(pool.clone()))
            .unwrap()
            .with_camera_sessions(manager.clone())
            .with_camera_onboarding(onboarding);
        Self {
            router: app(state),
            pool,
            vault,
            book,
            manager,
            interfaces,
            media,
            calls,
            audited_before_contact: audited,
            _directory: directory,
        }
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        body: Option<Value>,
        authorization: Option<String>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(value) = authorization {
            builder = builder.header("authorization", value);
        }
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let response = self
            .router
            .clone()
            .oneshot(
                builder
                    .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn owner(&self, method: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let (status, text) = self
            .call(method, uri, body, Some(format!("Bearer {TOKEN}")))
            .await;
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn add(&self, address: &str, password: &str) -> (StatusCode, Value) {
        self.owner(
            Method::POST,
            "/api/v1/cameras",
            Some(json!({"address": address, "username": USER, "password": password, "name": "Porch"})),
        )
        .await
    }

    async fn nothing_stored(&self) {
        let repository = CameraRepository::new(self.pool.clone());
        let (cameras, _) = repository.list_cameras(256, None).await.unwrap();
        assert!(cameras.is_empty(), "a camera row was left behind");
        assert!(repository.list_camera_targets().await.unwrap().is_empty());
        let streams: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM camera_stream_refs")
            .fetch_one(&self.pool)
            .await
            .unwrap();
        assert_eq!(streams, 0);
        assert!(self.book.is_empty().await, "an approval was left behind");
    }

    /// Every secret ever written to the vault has been deleted again.
    async fn vault_is_clean(&self) {
        let written = self.vault.labels().await.len();
        let deleted = self.vault.delete_attempts().await.len();
        assert_eq!(written, deleted, "{written} written, {deleted} deleted");
    }

    async fn audit_dump(&self) -> (Vec<String>, String) {
        let rows: Vec<(String, String, Option<String>)> =
            sqlx::query_as("SELECT action, detail, subject FROM audit_log ORDER BY id")
                .fetch_all(&self.pool)
                .await
                .unwrap();
        let actions = rows.iter().map(|row| row.0.clone()).collect();
        let text = rows
            .iter()
            .map(|row| format!("{} {} {:?}", row.0, row.1, row.2))
            .collect::<Vec<_>>()
            .join("\n");
        (actions, text)
    }
}

fn good_camera() -> Script {
    Script::Camera {
        stream_uri: RTSP.to_owned(),
        profiles: 1,
    }
}

fn assert_no_secret(label: &str, text: &str) {
    for forbidden in [PASSWORD, USER, "p%40ss", "p@ss"] {
        assert!(
            !text.contains(forbidden),
            "{label} leaked {forbidden}: {text}"
        );
    }
}

// --- adding -----------------------------------------------------------------

#[tokio::test]
async fn adding_a_camera_stores_the_camera_its_streams_its_approval_and_its_secret() {
    let rig = Rig::scripted(good_camera()).await;
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_no_secret("response", &body.to_string());
    assert_eq!(body["name"], "Porch");
    let camera: uuid::Uuid = body["camera_id"].as_str().unwrap().parse().unwrap();
    let camera = CameraId::from_uuid(camera);
    let streams = body["streams"].as_array().unwrap();
    assert_eq!(streams.len(), 1);
    let stream: uuid::Uuid = streams[0]["stream_id"].as_str().unwrap().parse().unwrap();
    let stream = StreamId::from_uuid(stream);

    let repository = CameraRepository::new(rig.pool.clone());
    let stored = repository.load_camera(camera).await.unwrap().unwrap();
    assert_eq!(
        stored.classification,
        lattice_camera::CameraClassification::Camera
    );
    let inventory = repository.load_inventory(camera).await.unwrap().unwrap();
    assert_eq!(inventory.manufacturer.unwrap().as_str(), "FixtureCam");
    let profiles = repository.load_stream_refs(camera).await.unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].stream_id(), stream);
    let target = repository
        .load_camera_target(camera)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.address, Ipv4Addr::new(192, 168, 1, 50));
    assert_eq!(target.interface, "eth0");
    assert_eq!(target.onvif_port, 80);
    assert_eq!(target.rtsp_port, 8554);
    assert!(!target.allow_basic);
    assert_eq!(target.name.as_deref(), Some("Porch"));

    // The secret is in the vault, not the database: the stored stream address
    // names the camera's host and carries the sign-in the proxy will inject.
    let secret = rig
        .vault
        .get_stream_source(camera, stream, profiles[0].source_ref())
        .await
        .unwrap();
    assert!(secret.expose_secret().starts_with("rtsp://camera-user:"));
    assert!(secret.expose_secret().contains("@192.168.1.50:8554/main"));
    assert_eq!(rig.vault.labels().await.len(), 1);

    // The approval is live: the target registry resolves it to the interface's
    // own address as the source.
    let approved = rig.book.authorized_binding(camera, stream).await.unwrap();
    assert_eq!(approved.port(), 8554);
    assert_eq!(
        approved.binding().source,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))
    );

    // The existing list shows it, in the existing shape.
    let (status, list) = rig.owner(Method::GET, "/api/v1/cameras", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(list["items"][0]["camera_id"], camera.to_string());
    let (_, detail) = rig
        .owner(Method::GET, &format!("/api/v1/cameras/{camera}"), None)
        .await;
    assert_eq!(detail["streams"][0]["stream_id"], stream.to_string());
    assert_no_secret("detail", &detail.to_string());

    // Setup is reported as available.
    let (_, media) = rig.owner(Method::GET, "/api/v1/camera-media", None).await;
    assert_eq!(media["setup_available"], true);

    // Audited before contact, again afterwards, and never with a secret.
    assert!(rig.audited_before_contact.load(Ordering::SeqCst));
    let (actions, text) = rig.audit_dump().await;
    assert_eq!(actions, ["camera_add_requested", "camera_added"]);
    assert_no_secret("audit", &text);
    assert!(
        text.contains("principal") && text.contains("owner"),
        "{text}"
    );
    assert!(text.contains(ADDRESS), "the approved host is on the record");
    // Five exchanges: device information, capabilities, profiles, one stream
    // address, date and time.
    assert_eq!(rig.calls.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn the_basic_sign_in_choice_and_a_custom_port_are_stored_with_the_approval() {
    let rig = Rig::scripted(good_camera()).await;
    let (status, body) = rig
        .owner(
            Method::POST,
            "/api/v1/cameras",
            Some(
                json!({"address": ADDRESS, "username": USER, "password": PASSWORD,
                        "onvif_port": 8080, "allow_basic": true}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["name"], Value::Null);
    let camera = CameraId::from_uuid(body["camera_id"].as_str().unwrap().parse().unwrap());
    let target = CameraRepository::new(rig.pool.clone())
        .load_camera_target(camera)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.onvif_port, 8080);
    assert!(target.allow_basic);
    let stream = StreamId::from_uuid(
        body["streams"][0]["stream_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    );
    assert!(
        rig.book
            .authorized_binding(camera, stream)
            .await
            .unwrap()
            .basic_auth_allowed()
    );
}

#[tokio::test]
async fn each_failure_has_its_own_answer_and_leaves_nothing_behind() {
    let cases = [
        (
            Script::RefusesSignIn,
            StatusCode::UNPROCESSABLE_ENTITY,
            "sign_in_refused",
        ),
        (Script::Silent, StatusCode::BAD_GATEWAY, "unreachable"),
        (
            Script::Camera {
                stream_uri: "rtsp://192.168.1.99:554/main".into(),
                profiles: 1,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "streams_elsewhere",
        ),
        (
            Script::Camera {
                stream_uri: "rtsp://camera.example/main".into(),
                profiles: 1,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "streams_elsewhere",
        ),
        (
            Script::Camera {
                stream_uri: "rtsp://127.0.0.1/main".into(),
                profiles: 1,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "streams_elsewhere",
        ),
        (
            Script::Camera {
                stream_uri: RTSP.into(),
                profiles: 0,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "no_streams",
        ),
    ];
    for (script, status, code) in cases {
        let rig = Rig::scripted(script).await;
        let (got, body) = rig.add(ADDRESS, PASSWORD).await;
        assert_eq!(
            (got, body["error"].as_str().unwrap()),
            (status, code),
            "{body}"
        );
        assert!(body["message"].as_str().unwrap().len() > 10);
        assert_no_secret("failure response", &body.to_string());
        assert!(!body.to_string().contains(ADDRESS), "no address in {body}");
        rig.nothing_stored().await;
        rig.vault_is_clean().await;
        assert!(rig.vault.labels().await.is_empty(), "{code}: vault touched");
        // The attempt and its refusal are on the record, without secrets.
        let (actions, text) = rig.audit_dump().await;
        assert_eq!(
            actions,
            ["camera_add_requested", "camera_add_refused"],
            "{code}"
        );
        assert_no_secret("audit", &text);
        assert!(rig.audited_before_contact.load(Ordering::SeqCst), "{code}");
    }
}

#[tokio::test]
async fn a_failure_after_the_vault_write_removes_what_was_written() {
    let rig = Rig::scripted(good_camera()).await;
    // The same host is already approved for another camera, but the registry
    // has not seen it: only the store's uniqueness catches it, after the vault
    // write.
    let repository = CameraRepository::new(rig.pool.clone());
    let other = lattice_store::CameraRecord {
        id: CameraId::from_uuid(uuid::Uuid::from_u128(0xabc)),
        classification: lattice_camera::CameraClassification::Camera,
        confidence: lattice_camera::Confidence::new(1.0).unwrap(),
        health: lattice_camera::CameraHealth::Unknown,
        observed_at: chrono::Utc::now(),
    };
    repository.upsert_camera(&other).await.unwrap();
    repository
        .put_camera_target(&lattice_store::CameraTarget {
            camera_id: other.id,
            interface: "eth0".into(),
            address: Ipv4Addr::new(192, 168, 1, 50),
            onvif_port: 80,
            rtsp_port: 554,
            allow_basic: false,
            approved_at: chrono::Utc::now(),
            name: None,
        })
        .await
        .unwrap();
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "already_added");
    assert_eq!(rig.vault.labels().await.len(), 1, "the secret was written");
    rig.vault_is_clean().await;
    assert!(rig.book.is_empty().await);
    let (cameras, _) = repository.list_cameras(256, None).await.unwrap();
    assert_eq!(cameras.len(), 1, "only the pre-existing camera remains");
}

#[tokio::test]
async fn a_duplicate_address_is_refused_before_anything_is_sent() {
    let rig = Rig::scripted(good_camera()).await;
    assert_eq!(rig.add(ADDRESS, PASSWORD).await.0, StatusCode::CREATED);
    let calls = rig.calls.load(Ordering::SeqCst);
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "already_added");
    assert_eq!(rig.calls.load(Ordering::SeqCst), calls);
}

#[tokio::test]
async fn addresses_that_may_not_be_approved_are_refused_before_anything_is_sent() {
    let rig = Rig::scripted(good_camera()).await;
    for address in [
        "127.0.0.1",
        "169.254.10.10",
        "224.0.0.251",
        "255.255.255.255",
        "192.168.1.255",
        "0.0.0.0",
        "8.8.8.8",
        "192.168.1.10",
        "192.168.77.5",
        "camera.local",
        "::1",
        "fe80::1",
        "",
    ] {
        let (status, body) = rig.add(address, PASSWORD).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{address:?}: {body}"
        );
        assert_eq!(body["error"], "not_on_your_network", "{address:?}");
    }
    assert_eq!(rig.calls.load(Ordering::SeqCst), 0);
    let (actions, _) = rig.audit_dump().await;
    assert!(
        actions.is_empty(),
        "a refused address is not an attempt: {actions:?}"
    );
    rig.nothing_stored().await;
    // A down interface cannot carry a camera either.
    rig.interfaces.set(network(false));
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rig.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_requests_are_refused() {
    let rig = Rig::scripted(good_camera()).await;
    for body in [
        json!({"address": ADDRESS, "username": "", "password": PASSWORD}),
        json!({"address": ADDRESS, "username": USER, "password": ""}),
        json!({"address": ADDRESS, "username": USER, "password": PASSWORD, "onvif_port": 0}),
        json!({"address": ADDRESS, "username": USER, "password": PASSWORD, "name": "x".repeat(65)}),
        json!({"address": ADDRESS, "username": "bad user", "password": PASSWORD}),
        json!({"address": ADDRESS, "username": USER, "password": PASSWORD, "extra": 1}),
        json!({"address": ADDRESS, "username": USER}),
    ] {
        let (status, response) = rig
            .owner(Method::POST, "/api/v1/cameras", Some(body.clone()))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
        assert_eq!(response["error"], "invalid_request");
    }
    let (status, _) = rig
        .call(
            Method::POST,
            "/api/v1/cameras",
            None,
            Some(format!("Bearer {TOKEN}")),
        )
        .await;
    assert!(status.is_client_error());
    assert_eq!(rig.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unauthenticated_request_is_refused() {
    let rig = Rig::scripted(good_camera()).await;
    let (status, _) = rig
        .call(
            Method::POST,
            "/api/v1/cameras",
            Some(json!({"address": ADDRESS, "username": USER, "password": PASSWORD})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = rig
        .call(
            Method::DELETE,
            &format!("/api/v1/cameras/{}", uuid::Uuid::nil()),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(rig.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_paired_phone_cannot_add_or_remove_a_camera() {
    let rig = Rig::scripted(good_camera()).await;
    let (status, pair) = rig
        .owner(
            Method::POST,
            "/api/v1/remote/pair",
            Some(json!({"device_label": "walk", "pin": "123456"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{pair}");
    let credential = format!(
        "PhoneSession {}:{}",
        pair["session_id"].as_str().unwrap(),
        pair["secret"].as_str().unwrap()
    );
    let (status, _) = rig
        .call(
            Method::POST,
            "/api/v1/cameras",
            Some(json!({"address": ADDRESS, "username": USER, "password": PASSWORD})),
            Some(credential.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = rig
        .call(
            Method::DELETE,
            &format!("/api/v1/cameras/{}", uuid::Uuid::nil()),
            None,
            Some(credential),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(rig.calls.load(Ordering::SeqCst), 0);
    rig.nothing_stored().await;
}

#[tokio::test]
async fn attempts_are_rate_limited_so_the_route_cannot_spray_the_lan() {
    let rig = Rig::scripted(Script::RefusesSignIn).await;
    for attempt in 0..6 {
        let (status, body) = rig.add(ADDRESS, PASSWORD).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "attempt {attempt}: {body}"
        );
    }
    assert_eq!(rig.calls.load(Ordering::SeqCst), 6);
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "rate_limited");
    assert_eq!(rig.calls.load(Ordering::SeqCst), 6, "nothing was sent");
}

#[tokio::test]
async fn openapi_documents_adding_and_removing() {
    let rig = Rig::scripted(good_camera()).await;
    let (status, doc) = rig.owner(Method::GET, "/api/v1/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        doc["paths"]["/api/v1/cameras"]["post"]["requestBody"]["content"]["application/json"]["schema"]
            ["$ref"],
        "#/components/schemas/AddCameraBody"
    );
    assert!(doc["paths"]["/api/v1/cameras"]["get"].is_object());
    assert!(doc["paths"]["/api/v1/cameras/{id}"]["delete"].is_object());
    assert!(doc["paths"]["/api/v1/cameras/{id}"]["get"].is_object());
}

// --- removing ---------------------------------------------------------------

async fn added(rig: &Rig) -> (CameraId, StreamId) {
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (
        CameraId::from_uuid(body["camera_id"].as_str().unwrap().parse().unwrap()),
        StreamId::from_uuid(
            body["streams"][0]["stream_id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        ),
    )
}

#[tokio::test]
async fn removing_a_camera_closes_its_views_and_deletes_every_trace() {
    let rig = Rig::scripted(good_camera()).await;
    let (camera, stream) = added(&rig).await;
    rig.media
        .set_hls_output(
            b"#EXTM3U\n#EXTINF:2,\nsegment-000001.ts\n".to_vec(),
            vec![("segment-000001.ts".into(), b"segment".to_vec())],
        )
        .await;
    rig.manager.start_session(camera, stream).await.unwrap();
    assert_eq!(rig.manager.active_count().await, 1);

    let (status, _) = rig
        .owner(Method::DELETE, &format!("/api/v1/cameras/{camera}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(rig.manager.active_count().await, 0, "live views are closed");
    rig.nothing_stored().await;
    rig.vault_is_clean().await;
    assert_eq!(
        rig.manager.start_session(camera, stream).await.unwrap_err(),
        CameraSessionError::NotFound
    );
    let (status, _) = rig
        .owner(Method::GET, &format!("/api/v1/cameras/{camera}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (actions, text) = rig.audit_dump().await;
    assert_eq!(actions.last().map(String::as_str), Some("camera_removed"));
    assert_no_secret("audit", &text);

    // Removing it again, or something that never existed, is a 404.
    for id in [camera.to_string(), uuid::Uuid::from_u128(5).to_string()] {
        let (status, _) = rig
            .owner(Method::DELETE, &format!("/api/v1/cameras/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let (status, _) = rig
        .owner(Method::DELETE, "/api/v1/cameras/not-an-id", None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_removal_the_vault_cannot_finish_still_revokes_and_can_be_retried() {
    let rig = Rig::scripted(good_camera()).await;
    let (camera, stream) = added(&rig).await;
    let repository = CameraRepository::new(rig.pool.clone());
    let reference = repository.load_stream_refs(camera).await.unwrap()[0]
        .source_ref()
        .clone();
    rig.vault.fail_next_stream_delete(camera, stream, reference);

    let uri = format!("/api/v1/cameras/{camera}");
    let (status, body) = rig.owner(Method::DELETE, &uri, None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "incomplete");
    // Revoked even though cleanup is unfinished: the host is no longer
    // approved, in memory or in the store, and no view can start.
    assert!(rig.book.is_empty().await);
    assert!(
        repository
            .load_camera_target(camera)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        rig.manager.start_session(camera, stream).await.unwrap_err(),
        CameraSessionError::Unavailable
    );
    // The camera and its stream reference remain so the retry can finish.
    assert!(repository.load_camera(camera).await.unwrap().is_some());

    let (status, _) = rig.owner(Method::DELETE, &uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    rig.nothing_stored().await;
    let (actions, _) = rig.audit_dump().await;
    assert_eq!(
        actions
            .iter()
            .filter(|action| *action == "camera_removed")
            .count(),
        2
    );
}

#[tokio::test]
async fn a_changed_network_makes_an_added_camera_unreachable_until_it_matches_again() {
    let rig = Rig::scripted(good_camera()).await;
    let (camera, stream) = added(&rig).await;
    rig.media
        .set_hls_output(b"#EXTM3U\n".to_vec(), Vec::new())
        .await;
    rig.interfaces.set(network(false));
    assert_eq!(
        rig.manager.start_session(camera, stream).await.unwrap_err(),
        CameraSessionError::Unavailable
    );
    rig.interfaces.set(network(true));
    assert!(rig.manager.start_session(camera, stream).await.is_ok());
}

#[tokio::test]
async fn approvals_survive_a_restart() {
    let rig = Rig::scripted(good_camera()).await;
    let (camera, stream) = added(&rig).await;
    let fresh = CameraTargetBook::new(rig.interfaces.clone());
    assert!(fresh.authorized_binding(camera, stream).await.is_err());
    let loaded = fresh
        .load(&CameraRepository::new(rig.pool.clone()))
        .await
        .unwrap();
    assert_eq!(loaded, 1);
    assert!(fresh.authorized_binding(camera, stream).await.is_ok());
}

// --- the real HTTP transport, end to end through the route ------------------

fn device_config(stream_uri: &str) -> Config {
    Config::new(USER, PASSWORD, stream_uri)
}

#[tokio::test]
async fn adding_over_the_real_http_transport_to_a_loopback_fake_device() {
    let device = FakeOnvifDevice::start(device_config(RTSP)).await;
    let rig = Rig::loopback(device.addr()).await;
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(device.requests(), 5);
    assert_no_secret("response", &body.to_string());
    let camera = CameraId::from_uuid(body["camera_id"].as_str().unwrap().parse().unwrap());
    let stream = StreamId::from_uuid(
        body["streams"][0]["stream_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    );
    let profiles = CameraRepository::new(rig.pool.clone())
        .load_stream_refs(camera)
        .await
        .unwrap();
    let secret = rig
        .vault
        .get_stream_source(camera, stream, profiles[0].source_ref())
        .await
        .unwrap();
    assert!(secret.expose_secret().contains("@192.168.1.50:8554/main"));
    assert_no_secret("audit", &rig.audit_dump().await.1);
}

#[tokio::test]
async fn the_real_transport_failures_map_to_the_owner_facing_answers() {
    let wrong_password = FakeOnvifDevice::start(device_config(RTSP)).await;
    let rig = Rig::loopback(wrong_password.addr()).await;
    let (status, body) = rig.add(ADDRESS, "not-the-password").await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("sign_in_refused"))
    );
    rig.nothing_stored().await;
    rig.vault_is_clean().await;

    let elsewhere = FakeOnvifDevice::start(device_config("rtsp://192.168.1.77/main")).await;
    let rig = Rig::loopback(elsewhere.addr()).await;
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("streams_elsewhere"))
    );
    rig.nothing_stored().await;
    assert!(rig.vault.labels().await.is_empty());

    let mut config = device_config(RTSP);
    config.capabilities_xaddr = Some("http://192.168.1.99/onvif/media".into());
    let advertises_elsewhere = FakeOnvifDevice::start(config).await;
    let rig = Rig::loopback(advertises_elsewhere.addr()).await;
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("streams_elsewhere"))
    );
    rig.nothing_stored().await;

    let untouched = FakeOnvifDevice::start(device_config(RTSP)).await;
    let mut config = device_config(RTSP);
    config.behavior =
        Behavior::Redirect(format!("http://{}/onvif/device_service", untouched.addr()));
    let redirecting = FakeOnvifDevice::start(config).await;
    let rig = Rig::loopback(redirecting.addr()).await;
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_GATEWAY, Some("unreachable"))
    );
    assert_eq!(untouched.requests(), 0, "the redirect was followed");
    rig.nothing_stored().await;

    let mut config = device_config(RTSP);
    config.behavior = Behavior::Oversized;
    let oversized = FakeOnvifDevice::start(config).await;
    let rig = Rig::loopback(oversized.addr()).await;
    let (status, body) = rig.add(ADDRESS, PASSWORD).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("unexpected_answer"))
    );
    rig.nothing_stored().await;
}

#[tokio::test]
async fn without_camera_media_adding_says_video_support_is_not_available() {
    let pool = connect_memory().await.unwrap();
    let state = AppState::new(TOKEN, M2StateRepository::new(pool)).unwrap();
    let router = app(state);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/cameras")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"address": ADDRESS, "username": USER, "password": PASSWORD}).to_string(),
        ))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "video_unavailable");
    assert_eq!(body["reason"], "not_configured");
    assert!(!String::from_utf8_lossy(&bytes).contains(PASSWORD));
}
