use lattice_camera::{CameraId, StreamId, StreamSourceRef};
use lattice_service::{CredentialRef, FakeVault, Vault, VaultError};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

const CREDENTIAL_SENTINEL: &str = "camera-password-leak-sentinel";
const STREAM_SENTINEL: &str = "rtsp://viewer:camera-stream-leak-sentinel@192.0.2.17/live";

fn camera(n: u128) -> CameraId {
    CameraId::from_uuid(Uuid::from_u128(n))
}

#[tokio::test]
async fn fake_vault_binds_credential_and_stream_to_exact_camera_and_stream() {
    let vault = FakeVault::new();
    let owner = camera(1);
    let other_owner = camera(2);
    let stream = StreamId::from_uuid(Uuid::from_u128(3));
    let other_stream = StreamId::from_uuid(Uuid::from_u128(4));

    let credential = vault
        .put_credential(owner, SecretString::from(CREDENTIAL_SENTINEL))
        .await
        .unwrap();
    let source = vault
        .put_stream_source(owner, stream, SecretString::from(STREAM_SENTINEL))
        .await
        .unwrap();

    assert_eq!(
        vault
            .get_credential(owner, &credential)
            .await
            .unwrap()
            .expose_secret(),
        CREDENTIAL_SENTINEL
    );
    assert_eq!(
        vault
            .get_stream_source(owner, stream, &source)
            .await
            .unwrap()
            .expose_secret(),
        STREAM_SENTINEL
    );
    assert!(matches!(
        vault.get_credential(other_owner, &credential).await,
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        vault.get_stream_source(owner, other_stream, &source).await,
        Err(VaultError::NotFound)
    ));
}

#[tokio::test]
async fn fake_vault_delete_uses_exact_refs_is_idempotent_and_attempts_every_slot() {
    let vault = FakeVault::new();
    let owner = camera(10);
    let stream_a = StreamId::from_uuid(Uuid::from_u128(11));
    let stream_b = StreamId::from_uuid(Uuid::from_u128(12));
    let credential = vault
        .put_credential(owner, SecretString::from(CREDENTIAL_SENTINEL))
        .await
        .unwrap();
    let source_a = vault
        .put_stream_source(owner, stream_a, SecretString::from(STREAM_SENTINEL))
        .await
        .unwrap();
    let source_b = vault
        .put_stream_source(owner, stream_b, SecretString::from(STREAM_SENTINEL))
        .await
        .unwrap();

    vault.fail_next_stream_delete(owner, stream_a, source_a.clone());
    assert_eq!(
        vault
            .delete_camera_secrets(
                owner,
                Some(&credential),
                &[(stream_a, source_a.clone()), (stream_b, source_b.clone())],
            )
            .await,
        Err(VaultError::PartialDeletion)
    );
    assert_eq!(vault.delete_attempts().await.len(), 3);
    assert!(matches!(
        vault.get_credential(owner, &credential).await,
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        vault.get_stream_source(owner, stream_b, &source_b).await,
        Err(VaultError::NotFound)
    ));
    assert_eq!(
        vault
            .get_stream_source(owner, stream_a, &source_a)
            .await
            .unwrap()
            .expose_secret(),
        STREAM_SENTINEL
    );

    vault
        .delete_camera_secrets(
            owner,
            Some(&credential),
            &[(stream_a, source_a), (stream_b, source_b)],
        )
        .await
        .unwrap();
}

#[test]
fn opaque_refs_are_canonical_and_reject_malformed_values() {
    let ref_json = "\"0190c6d1-1234-7abc-8def-0123456789ab\"";
    let reference: CredentialRef = serde_json::from_str(ref_json).unwrap();
    assert_eq!(serde_json::to_string(&reference).unwrap(), ref_json);
    assert_eq!(format!("{reference:?}"), "CredentialRef([opaque])");
    for invalid in [
        "\"credential-secret\"",
        "\"0190c6d1-1234-4abc-8def-0123456789ab\"",
        "\"0190C6D1-1234-7ABC-8DEF-0123456789AB\"",
    ] {
        assert!(serde_json::from_str::<CredentialRef>(invalid).is_err());
    }
    assert!(StreamSourceRef::new("not-a-canonical-reference").is_ok());
}

#[tokio::test]
async fn fake_vault_accepts_shared_stream_source_refs_without_redefining_their_invariant() {
    let vault = FakeVault::new();
    let owner = camera(21);
    let stream = StreamId::from_uuid(Uuid::from_u128(22));
    let malformed = StreamSourceRef::new("not-a-canonical-reference").unwrap();

    assert!(matches!(
        vault.get_stream_source(owner, stream, &malformed).await,
        Err(VaultError::NotFound)
    ));
    vault
        .delete_camera_secrets(owner, None, &[(stream, malformed)])
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_accepts_a_shared_ref_and_removes_later_known_slots() {
    let vault = FakeVault::new();
    let owner = camera(23);
    let stream = StreamId::from_uuid(Uuid::from_u128(24));
    let source = vault
        .put_stream_source(owner, stream, SecretString::from(STREAM_SENTINEL))
        .await
        .unwrap();
    let malformed = StreamSourceRef::new("not-a-canonical-reference").unwrap();

    vault
        .delete_camera_secrets(
            owner,
            None,
            &[(stream, malformed), (stream, source.clone())],
        )
        .await
        .unwrap();
    assert!(matches!(
        vault.get_stream_source(owner, stream, &source).await,
        Err(VaultError::NotFound)
    ));
}

#[test]
fn credential_ref_rejects_plain_and_escaped_oversized_json_without_losing_canonical_validation() {
    let oversized = "x".repeat(8 * 1024);
    let escaped_oversized = "\\u0078".repeat(8 * 1024);
    assert!(serde_json::from_str::<CredentialRef>(&format!("\"{oversized}\"")).is_err());
    assert!(serde_json::from_str::<CredentialRef>(&format!("\"{escaped_oversized}\"")).is_err());
    assert!(
        serde_json::from_str::<CredentialRef>("\"0190c6d1-1234-7abc-8def-0123456789ab\"").is_ok()
    );
    assert!(
        serde_json::from_str::<CredentialRef>("\"\\u0030190c6d1-1234-7abc-8def-0123456789ab\"")
            .is_ok()
    );
}

#[test]
fn vault_errors_are_payload_free_and_safe_to_debug_or_serialize() {
    let error = VaultError::Unavailable;
    let debug = format!("{error:?}");
    let json = serde_json::to_string(&error).unwrap();
    for sentinel in [CREDENTIAL_SENTINEL, STREAM_SENTINEL] {
        assert!(!debug.contains(sentinel));
        assert!(!json.contains(sentinel));
    }
    assert_eq!(json, "\"unavailable\"");
}
