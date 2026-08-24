use lattice_camera::{CameraId, StreamId};
use lattice_service::{CredentialRef, FakeVault, Vault, VaultError};
use secrecy::SecretString;
use uuid::Uuid;

const CREDENTIAL_SENTINEL: &str = "credential-should-never-escape";
const STREAM_SENTINEL: &str = "rtsp://user:stream-should-never-escape@198.51.100.23/path";

#[tokio::test]
async fn sentinels_are_absent_from_error_debug_json_labels_and_api_like_projection() {
    let vault = FakeVault::new();
    let owner = CameraId::from_uuid(Uuid::from_u128(31));
    let stream = StreamId::from_uuid(Uuid::from_u128(32));
    let credential = vault
        .put_credential(owner, SecretString::from(CREDENTIAL_SENTINEL))
        .await
        .unwrap();
    let source = vault
        .put_stream_source(owner, stream, SecretString::from(STREAM_SENTINEL))
        .await
        .unwrap();

    let projection = serde_json::json!({
        "credential_ref": credential,
        "stream_source_ref": source,
        "error": VaultError::NotFound,
    });
    let observable = format!(
        "{projection} {:?} {:?}",
        vault.labels().await,
        VaultError::Unavailable
    );
    for sentinel in [
        CREDENTIAL_SENTINEL,
        STREAM_SENTINEL,
        "198.51.100.23",
        "user",
    ] {
        assert!(!observable.contains(sentinel), "leaked {sentinel}");
    }
}

#[test]
fn credential_ref_cannot_be_deserialized_from_secret_like_or_noncanonical_text() {
    for value in [
        CREDENTIAL_SENTINEL,
        "credential-ref-0190c6d1-1234-7abc-8def-0123456789ab",
        "0190c6d1-1234-7abc-8def-0123456789ab ",
    ] {
        assert!(serde_json::from_value::<CredentialRef>(serde_json::json!(value)).is_err());
    }
}
