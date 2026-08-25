use async_trait::async_trait;
use lattice_camera::{CameraId, StreamId, StreamSourceRef};
use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize, de::Visitor};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use zeroize::Zeroize;

const CAMERA_VAULT_SERVICE: &str = "neonhearth-camera-vault-v1";
const CREDENTIAL_REF_BYTES: usize = 36;

#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CredentialRef(String);

impl CredentialRef {
    pub fn parse(value: impl Into<String>) -> Result<Self, VaultError> {
        let value = value.into();
        if is_canonical_opaque_id(&value) {
            Ok(Self(value))
        } else {
            Err(VaultError::InvalidReference)
        }
    }
    fn generate() -> Self {
        Self(Uuid::now_v7().hyphenated().to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CredentialRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialRef([opaque])")
    }
}

impl<'de> Deserialize<'de> for CredentialRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CredentialRefVisitor;

        impl Visitor<'_> for CredentialRefVisitor {
            type Value = CredentialRef;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical UUIDv7 credential reference")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() != CREDENTIAL_REF_BYTES {
                    return Err(E::custom("invalid credential reference"));
                }
                CredentialRef::parse(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(CredentialRefVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultError {
    InvalidReference,
    NotFound,
    Unavailable,
    PartialDeletion,
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidReference => "invalid vault reference",
            Self::NotFound => "vault secret not found",
            Self::Unavailable => "vault unavailable",
            Self::PartialDeletion => "vault deletion incomplete",
        })
    }
}
impl std::error::Error for VaultError {}

#[async_trait]
pub trait Vault: Send + Sync {
    async fn put_credential(
        &self,
        owner: CameraId,
        credential: SecretString,
    ) -> Result<CredentialRef, VaultError>;
    async fn get_credential(
        &self,
        owner: CameraId,
        reference: &CredentialRef,
    ) -> Result<SecretString, VaultError>;
    async fn put_stream_source(
        &self,
        owner: CameraId,
        stream: StreamId,
        source: SecretString,
    ) -> Result<StreamSourceRef, VaultError>;
    async fn get_stream_source(
        &self,
        owner: CameraId,
        stream: StreamId,
        reference: &StreamSourceRef,
    ) -> Result<SecretString, VaultError>;
    async fn delete_camera_secrets(
        &self,
        owner: CameraId,
        credential: Option<&CredentialRef>,
        streams: &[(StreamId, StreamSourceRef)],
    ) -> Result<(), VaultError>;
}

#[derive(Default)]
pub struct FakeVault {
    credentials: Mutex<HashMap<(CameraId, CredentialRef), SecretString>>,
    streams: Mutex<HashMap<(CameraId, StreamId, StreamSourceRef), SecretString>>,
    failed_stream_deletes: Mutex<HashSet<(CameraId, StreamId, StreamSourceRef)>>,
    delete_attempts: Mutex<Vec<String>>,
    labels: Mutex<Vec<String>>,
}

impl FakeVault {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn fail_next_stream_delete(
        &self,
        owner: CameraId,
        stream: StreamId,
        reference: StreamSourceRef,
    ) {
        self.failed_stream_deletes
            .lock()
            .expect("fake vault failure set poisoned")
            .insert((owner, stream, reference));
    }
    pub async fn delete_attempts(&self) -> Vec<String> {
        self.delete_attempts
            .lock()
            .expect("fake vault attempts poisoned")
            .clone()
    }
    pub async fn labels(&self) -> Vec<String> {
        self.labels
            .lock()
            .expect("fake vault labels poisoned")
            .clone()
    }
    fn record_label(&self, label: String) {
        self.labels
            .lock()
            .expect("fake vault labels poisoned")
            .push(label);
    }
}

#[async_trait]
impl Vault for FakeVault {
    async fn put_credential(
        &self,
        owner: CameraId,
        credential: SecretString,
    ) -> Result<CredentialRef, VaultError> {
        let reference = CredentialRef::generate();
        self.record_label(credential_slot(owner, &reference));
        self.credentials
            .lock()
            .expect("fake vault credentials poisoned")
            .insert((owner, reference.clone()), credential);
        Ok(reference)
    }
    async fn get_credential(
        &self,
        owner: CameraId,
        reference: &CredentialRef,
    ) -> Result<SecretString, VaultError> {
        validate_credential_ref(reference)?;
        self.credentials
            .lock()
            .expect("fake vault credentials poisoned")
            .get(&(owner, reference.clone()))
            .cloned()
            .ok_or(VaultError::NotFound)
    }
    async fn put_stream_source(
        &self,
        owner: CameraId,
        stream: StreamId,
        source: SecretString,
    ) -> Result<StreamSourceRef, VaultError> {
        let reference = generated_stream_ref()?;
        self.record_label(stream_slot(owner, stream, &reference));
        self.streams
            .lock()
            .expect("fake vault streams poisoned")
            .insert((owner, stream, reference.clone()), source);
        Ok(reference)
    }
    async fn get_stream_source(
        &self,
        owner: CameraId,
        stream: StreamId,
        reference: &StreamSourceRef,
    ) -> Result<SecretString, VaultError> {
        self.streams
            .lock()
            .expect("fake vault streams poisoned")
            .get(&(owner, stream, reference.clone()))
            .cloned()
            .ok_or(VaultError::NotFound)
    }
    async fn delete_camera_secrets(
        &self,
        owner: CameraId,
        credential: Option<&CredentialRef>,
        streams: &[(StreamId, StreamSourceRef)],
    ) -> Result<(), VaultError> {
        let mut failed = false;
        if let Some(reference) = credential {
            self.delete_attempts
                .lock()
                .expect("fake vault attempts poisoned")
                .push(credential_slot(owner, reference));
            if validate_credential_ref(reference).is_err() {
                failed = true;
            } else {
                self.credentials
                    .lock()
                    .expect("fake vault credentials poisoned")
                    .remove(&(owner, reference.clone()));
            }
        }
        for (stream, reference) in streams {
            let label = stream_slot(owner, *stream, reference);
            self.delete_attempts
                .lock()
                .expect("fake vault attempts poisoned")
                .push(label);
            let key = (owner, *stream, reference.clone());
            if self
                .failed_stream_deletes
                .lock()
                .expect("fake vault failure set poisoned")
                .remove(&key)
            {
                failed = true;
                continue;
            }
            self.streams
                .lock()
                .expect("fake vault streams poisoned")
                .remove(&key);
        }
        if failed {
            Err(VaultError::PartialDeletion)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultCapability {
    Available,
    Unavailable,
}

/// The keyring 4.1.6 `v1` backend uses native Credential Manager on Windows
/// and zbus Secret Service on Linux. No alternative secret store is used.
#[async_trait]
#[doc(hidden)]
trait KeyringBackend: Send + Sync {
    async fn put(&self, slot: String, secret: SecretString) -> Result<(), VaultError>;
    async fn get(&self, slot: String) -> Result<SecretString, VaultError>;
    /// `NotFound` means the exact slot was already absent and is idempotent.
    async fn delete(&self, slot: String) -> Result<(), VaultError>;
}

#[derive(Default)]
struct SystemKeyring;

/// Production vaults may only be constructed through [`KeyringVault::platform`].
///
/// ```compile_fail
/// let _ = lattice_service::KeyringVault::with_backend;
/// ```
#[derive(Clone)]
pub struct KeyringVault {
    backend: Arc<dyn KeyringBackend>,
}

impl fmt::Debug for KeyringVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyringVault")
    }
}

impl KeyringVault {
    #[doc(hidden)]
    fn with_backend(backend: Arc<dyn KeyringBackend>) -> Self {
        Self { backend }
    }

    fn system() -> Self {
        Self::with_backend(Arc::new(SystemKeyring))
    }

    pub async fn capability() -> VaultCapability {
        if Self::ensure_available().await.is_ok() {
            VaultCapability::Available
        } else {
            VaultCapability::Unavailable
        }
    }
    pub async fn platform() -> Result<Self, VaultError> {
        Self::ensure_available().await?;
        Ok(Self::system())
    }
    async fn ensure_available() -> Result<(), VaultError> {
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            run_os(|| {
                if keyring::Entry::store_status().is_ok() {
                    Ok(())
                } else {
                    Err(VaultError::Unavailable)
                }
            })
            .await
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err(VaultError::Unavailable)
        }
    }
}

#[async_trait]
impl Vault for KeyringVault {
    async fn put_credential(
        &self,
        owner: CameraId,
        credential: SecretString,
    ) -> Result<CredentialRef, VaultError> {
        let reference = CredentialRef::generate();
        self.backend
            .put(credential_slot(owner, &reference), credential)
            .await?;
        Ok(reference)
    }
    async fn get_credential(
        &self,
        owner: CameraId,
        reference: &CredentialRef,
    ) -> Result<SecretString, VaultError> {
        validate_credential_ref(reference)?;
        self.backend.get(credential_slot(owner, reference)).await
    }
    async fn put_stream_source(
        &self,
        owner: CameraId,
        stream: StreamId,
        source: SecretString,
    ) -> Result<StreamSourceRef, VaultError> {
        let reference = generated_stream_ref()?;
        self.backend
            .put(stream_slot(owner, stream, &reference), source)
            .await?;
        Ok(reference)
    }
    async fn get_stream_source(
        &self,
        owner: CameraId,
        stream: StreamId,
        reference: &StreamSourceRef,
    ) -> Result<SecretString, VaultError> {
        self.backend
            .get(stream_slot(owner, stream, reference))
            .await
    }
    async fn delete_camera_secrets(
        &self,
        owner: CameraId,
        credential: Option<&CredentialRef>,
        streams: &[(StreamId, StreamSourceRef)],
    ) -> Result<(), VaultError> {
        let mut partial_failure = false;
        let mut unavailable = false;
        if let Some(reference) = credential {
            if validate_credential_ref(reference).is_err() {
                partial_failure = true;
            } else {
                record_delete_result(
                    self.backend.delete(credential_slot(owner, reference)).await,
                    &mut unavailable,
                    &mut partial_failure,
                );
            }
        }
        for (stream, reference) in streams {
            record_delete_result(
                self.backend
                    .delete(stream_slot(owner, *stream, reference))
                    .await,
                &mut unavailable,
                &mut partial_failure,
            );
        }
        if unavailable {
            Err(VaultError::Unavailable)
        } else if partial_failure {
            Err(VaultError::PartialDeletion)
        } else {
            Ok(())
        }
    }
}

fn is_canonical_opaque_id(value: &str) -> bool {
    Uuid::parse_str(value)
        .map(|id| id.get_version_num() == 7 && id.hyphenated().to_string() == value)
        .unwrap_or(false)
}
fn validate_credential_ref(reference: &CredentialRef) -> Result<(), VaultError> {
    if is_canonical_opaque_id(reference.as_str()) {
        Ok(())
    } else {
        Err(VaultError::InvalidReference)
    }
}
fn generated_stream_ref() -> Result<StreamSourceRef, VaultError> {
    StreamSourceRef::new(Uuid::now_v7().hyphenated().to_string())
        .map_err(|_| VaultError::InvalidReference)
}
fn credential_slot(owner: CameraId, reference: &CredentialRef) -> String {
    format!("{owner}:{}", reference.as_str())
}
fn stream_slot(owner: CameraId, stream: StreamId, reference: &StreamSourceRef) -> String {
    format!("{owner}:{stream}:{}", reference.as_str())
}

fn record_delete_result(
    result: Result<(), VaultError>,
    unavailable: &mut bool,
    partial_failure: &mut bool,
) {
    match result {
        Ok(()) | Err(VaultError::NotFound) => {}
        Err(VaultError::Unavailable) => *unavailable = true,
        Err(VaultError::InvalidReference | VaultError::PartialDeletion) => *partial_failure = true,
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn map_keyring_error(error: keyring::Error) -> VaultError {
    match error {
        keyring::Error::NoEntry => VaultError::NotFound,
        keyring::Error::BadEncoding(mut bytes) => {
            bytes.zeroize();
            VaultError::Unavailable
        }
        keyring::Error::BadDataFormat(mut bytes, _) => {
            bytes.zeroize();
            VaultError::Unavailable
        }
        _ => VaultError::Unavailable,
    }
}
#[cfg(any(target_os = "windows", target_os = "linux"))]
async fn run_os<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, VaultError> + Send + 'static,
) -> Result<T, VaultError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| VaultError::Unavailable)?
}
#[cfg(any(target_os = "windows", target_os = "linux"))]
async fn put_secret(slot: String, secret: SecretString) -> Result<(), VaultError> {
    run_os(move || {
        let entry = keyring::Entry::new(CAMERA_VAULT_SERVICE, &slot).map_err(map_keyring_error)?;
        entry
            .set_password(secrecy::ExposeSecret::expose_secret(&secret))
            .map_err(map_keyring_error)
    })
    .await
}
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
async fn put_secret(_: String, _: SecretString) -> Result<(), VaultError> {
    Err(VaultError::Unavailable)
}
#[cfg(any(target_os = "windows", target_os = "linux"))]
async fn get_secret(slot: String) -> Result<SecretString, VaultError> {
    run_os(move || {
        let entry = keyring::Entry::new(CAMERA_VAULT_SERVICE, &slot).map_err(map_keyring_error)?;
        entry
            .get_password()
            .map(SecretString::from)
            .map_err(map_keyring_error)
    })
    .await
}
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
async fn get_secret(_: String) -> Result<SecretString, VaultError> {
    Err(VaultError::Unavailable)
}
#[cfg(any(target_os = "windows", target_os = "linux"))]
async fn delete_secret(slot: String) -> Result<(), VaultError> {
    run_os(move || {
        let entry = keyring::Entry::new(CAMERA_VAULT_SERVICE, &slot).map_err(map_keyring_error)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(map_keyring_error(error)),
        }
    })
    .await
}
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
async fn delete_secret(_: String) -> Result<(), VaultError> {
    Err(VaultError::Unavailable)
}

#[async_trait]
impl KeyringBackend for SystemKeyring {
    async fn put(&self, slot: String, secret: SecretString) -> Result<(), VaultError> {
        put_secret(slot, secret).await
    }

    async fn get(&self, slot: String) -> Result<SecretString, VaultError> {
        get_secret(slot).await
    }

    async fn delete(&self, slot: String) -> Result<(), VaultError> {
        delete_secret(slot).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    struct ScriptedKeyring {
        deletes: Mutex<VecDeque<Result<(), VaultError>>>,
        labels: Mutex<Vec<String>>,
    }

    impl ScriptedKeyring {
        fn new(deletes: impl IntoIterator<Item = Result<(), VaultError>>) -> Self {
            Self {
                deletes: Mutex::new(deletes.into_iter().collect()),
                labels: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl KeyringBackend for ScriptedKeyring {
        async fn put(&self, _: String, _: SecretString) -> Result<(), VaultError> {
            Ok(())
        }

        async fn get(&self, label: String) -> Result<SecretString, VaultError> {
            self.labels.lock().unwrap().push(label);
            Ok(SecretString::from("fixture-only"))
        }

        async fn delete(&self, label: String) -> Result<(), VaultError> {
            self.labels.lock().unwrap().push(label);
            self.deletes.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }
    }

    fn camera(n: u128) -> CameraId {
        CameraId::from_uuid(Uuid::from_u128(n))
    }

    #[tokio::test]
    async fn keyring_delete_attempts_every_valid_slot_and_unavailable_dominates_partial_failure() {
        let backend = Arc::new(ScriptedKeyring::new([
            Err(VaultError::Unavailable),
            Err(VaultError::NotFound),
            Err(VaultError::PartialDeletion),
        ]));
        let vault = KeyringVault::with_backend(backend.clone());
        let owner = camera(30);
        let credential: CredentialRef =
            serde_json::from_str("\"0190c6d1-1234-7abc-8def-0123456789ab\"").unwrap();
        let stream_a = StreamId::from_uuid(Uuid::from_u128(31));
        let stream_b = StreamId::from_uuid(Uuid::from_u128(32));
        let source_a = StreamSourceRef::new("opaque-source-ref").unwrap();
        let source_b = StreamSourceRef::new("another-opaque-source-ref").unwrap();

        assert!(matches!(
            vault
                .delete_camera_secrets(
                    owner,
                    Some(&credential),
                    &[(stream_a, source_a), (stream_b, source_b)],
                )
                .await,
            Err(VaultError::Unavailable)
        ));
        assert_eq!(backend.labels.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn keyring_delete_returns_partial_after_every_slot_when_no_slot_is_unavailable() {
        let backend = Arc::new(ScriptedKeyring::new([
            Err(VaultError::PartialDeletion),
            Err(VaultError::NotFound),
        ]));
        let vault = KeyringVault::with_backend(backend.clone());
        let owner = camera(35);
        let stream_a = StreamId::from_uuid(Uuid::from_u128(36));
        let stream_b = StreamId::from_uuid(Uuid::from_u128(37));
        let source_a = StreamSourceRef::new("opaque-source-ref").unwrap();
        let source_b = StreamSourceRef::new("another-opaque-source-ref").unwrap();

        assert!(matches!(
            vault
                .delete_camera_secrets(owner, None, &[(stream_a, source_a), (stream_b, source_b)])
                .await,
            Err(VaultError::PartialDeletion)
        ));
        assert_eq!(backend.labels.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn keyring_vault_accepts_all_shared_stream_source_refs_for_get_and_delete() {
        let backend = Arc::new(ScriptedKeyring::new([]));
        let vault = KeyringVault::with_backend(backend.clone());
        let owner = camera(33);
        let stream = StreamId::from_uuid(Uuid::from_u128(34));
        let shared_ref = StreamSourceRef::new("opaque-source-ref").unwrap();

        assert_eq!(
            vault
                .get_stream_source(owner, stream, &shared_ref)
                .await
                .unwrap()
                .expose_secret(),
            "fixture-only"
        );
        vault
            .delete_camera_secrets(owner, None, &[(stream, shared_ref)])
            .await
            .unwrap();
        assert_eq!(backend.labels.lock().unwrap().len(), 2);
    }
}
