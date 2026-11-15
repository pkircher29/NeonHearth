use super::*;
use axum::{body::Bytes, response::IntoResponse};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/network/capabilities", get(capabilities_route))
        .route(
            "/api/v1/network/capture",
            get(read_route).post(import_route),
        )
        .layer(DefaultBodyLimit::max(
            lattice_sensor::passive::MAX_PCAP_BYTES,
        ))
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct CaptureReport {
    pub imported_at: String,
    pub findings: Vec<Finding>,
    pub detail: String,
}
#[utoipa::path(get,path="/api/v1/network/capabilities",responses((status=200,body=avahi::DiscoveryCapabilities),(status=401)),security(("bearer_auth"=[])))]
pub(crate) async fn capabilities_route(_: LocalOwner) -> Json<avahi::DiscoveryCapabilities> {
    Json(avahi::capabilities())
}
#[utoipa::path(get,path="/api/v1/network/capture",responses((status=200,body=CaptureReport),(status=401)),security(("bearer_auth"=[])))]
pub(crate) async fn read_route(
    _: LocalOwner,
    State(state): State<AppState>,
) -> Result<Json<CaptureReport>, StatusCode> {
    let row:Option<(String,)>=sqlx::query_as("SELECT payload FROM network_discovery_snapshots WHERE kind='capture' AND length(payload)<=8388608").fetch_optional(&state.scans().pool).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
    let value = if let Some((json,)) = row {
        serde_json::from_str(&json).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    } else {
        CaptureReport {
            imported_at: String::new(),
            findings: vec![],
            detail:
                "Import an Ethernet PCAP to inspect CDP and LLDP advertisements from that link."
                    .into(),
        }
    };
    Ok(Json(value))
}
#[utoipa::path(post,path="/api/v1/network/capture",request_body(content=String,content_type="application/vnd.tcpdump.pcap"),responses((status=200,body=CaptureReport),(status=400),(status=401),(status=413)),security(("bearer_auth"=[])))]
pub(crate) async fn import_route(
    _: LocalOwner,
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let _start = state
        .scans()
        .start_lock
        .try_lock()
        .map_err(|_| StatusCode::CONFLICT)?;
    let observations = tokio::task::spawn_blocking(move || {
        lattice_sensor::OfflinePassiveAdapter.ingest_pcap(
            "owner_capture",
            &bytes,
            &lattice_sensor::PassiveOptions::default(),
        )
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    let now = Utc::now();
    let findings = observations
        .into_iter()
        .filter(|o| matches!(o.protocol.as_str(), "lldp" | "cdp"))
        .take(1024)
        .map(|o| {
            let withdrawn = o
                .facts
                .iter()
                .any(|f| f.key == "ttl_seconds" && f.value == "0");
            let expired = o
                .facts
                .iter()
                .all(|f| f.expires_at.is_some_and(|t| t <= now));
            Finding {
                device_id: None,
                address: o.subject_mac.unwrap_or_default(),
                protocol: o.protocol,
                port: None,
                status: if withdrawn {
                    "withdrawn"
                } else if expired {
                    "expired_advertisement"
                } else {
                    "advertised"
                }
                .into(),
                service_hint: None,
                facts: o
                    .facts
                    .into_iter()
                    .take(8)
                    .map(|f| (f.key, bounded_text(&f.value)))
                    .collect(),
                observed_at: o.observed_at.to_rfc3339(),
            }
        })
        .collect();
    let report=CaptureReport {imported_at:now.to_rfc3339(),findings,detail:"Capture metadata is advisory. Times come from the capture; imported advertisements do not establish current presence or control rights. Only the first 1024 CDP/LLDP advertisements are displayed.".into()};
    let json = serde_json::to_string(&report).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    sqlx::query("INSERT INTO network_discovery_snapshots(kind,payload,updated_at) VALUES('capture',?,?) ON CONFLICT(kind) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at").bind(json).bind(&report.imported_at).execute(&state.scans().pool).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(report))
}
