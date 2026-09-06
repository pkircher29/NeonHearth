use async_trait::async_trait;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use lattice_camera::{CameraId, StreamId, StreamSourceRef};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, de::Visitor};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const CAMERA_VAULT_SERVICE: &str = "neonhearth-camera-vault-v1";
const CREDENTIAL_REF_BYTES: usize = 36;
/// File-vault container magic; bumps if the on-disk layout ever changes.
const FILE_VAULT_MAGIC: &[u8; 4] = b"NHV1";
const FILE_VAULT_KEY_BYTES: usize = 32;
const FILE_VAULT_NONCE_BYTES: usize = 24;
/// Largest container the file vault will read back (a few thousand camera
/// secrets); anything larger is corrupt, not a vault.
const FILE_VAULT_MAX_BYTES: u64 = 4 * 1024 * 1024;

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

/// Which backend [`platform_vault`] selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultBackend {
    /// The OS credential store (Windows Credential Manager / Secret Service).
    Keyring,
    /// The encrypted state-directory file (Linux fallback only).
    EncryptedFile,
}

/// The production vault for this host.
///
/// The OS keyring is preferred everywhere. On Linux the hardened service unit
/// runs as a system user with no session D-Bus, so the Secret Service is
/// unreachable by construction; there the vault falls back to an encrypted
/// file under `state_dir` (see [`FileVault`]). Windows stays on the
/// Credential Manager only: an unavailable keyring is an error, not a
/// fallback.
pub async fn platform_vault(
    state_dir: &Path,
) -> Result<(Arc<dyn Vault>, VaultBackend), VaultError> {
    match KeyringVault::platform().await {
        Ok(vault) => Ok((Arc::new(vault), VaultBackend::Keyring)),
        Err(VaultError::Unavailable) if cfg!(target_os = "linux") => {
            let vault = FileVault::open(state_dir.join("vault")).await?;
            Ok((Arc::new(vault), VaultBackend::EncryptedFile))
        }
        Err(error) => Err(error),
    }
}

/// Encrypted file-backed vault: `<dir>/vault.key` (32 random bytes) and
/// `<dir>/vault.dat` (XChaCha20-Poly1305 over the JSON slot map, keyed by
/// the key file, authenticated with the container magic). Both files and the
/// directory are created owner-only (`0600` / `0700`) and every write goes
/// through a temp file, `fsync`, and rename so a crash never leaves a torn
/// container behind. Secrets are only ever decrypted into zeroizing buffers.
#[derive(Clone)]
pub struct FileVault {
    inner: KeyringVault,
}

impl fmt::Debug for FileVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileVault")
    }
}

impl FileVault {
    /// Opens (creating on first use) the vault under `dir`. Fails closed when
    /// an existing container cannot be read with the key on disk.
    pub async fn open(dir: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let dir = dir.into();
        let shared = run_blocking(move || FileVaultShared::open(&dir)).await?;
        Ok(Self {
            inner: KeyringVault::with_backend(Arc::new(FileBackend {
                shared: Arc::new(shared),
            })),
        })
    }
}

#[async_trait]
impl Vault for FileVault {
    async fn put_credential(
        &self,
        owner: CameraId,
        credential: SecretString,
    ) -> Result<CredentialRef, VaultError> {
        self.inner.put_credential(owner, credential).await
    }
    async fn get_credential(
        &self,
        owner: CameraId,
        reference: &CredentialRef,
    ) -> Result<SecretString, VaultError> {
        self.inner.get_credential(owner, reference).await
    }
    async fn put_stream_source(
        &self,
        owner: CameraId,
        stream: StreamId,
        source: SecretString,
    ) -> Result<StreamSourceRef, VaultError> {
        self.inner.put_stream_source(owner, stream, source).await
    }
    async fn get_stream_source(
        &self,
        owner: CameraId,
        stream: StreamId,
        reference: &StreamSourceRef,
    ) -> Result<SecretString, VaultError> {
        self.inner.get_stream_source(owner, stream, reference).await
    }
    async fn delete_camera_secrets(
        &self,
        owner: CameraId,
        credential: Option<&CredentialRef>,
        streams: &[(StreamId, StreamSourceRef)],
    ) -> Result<(), VaultError> {
        self.inner
            .delete_camera_secrets(owner, credential, streams)
            .await
    }
}

/// The blocking side of [`FileVault`]: one lock around read-modify-write so
/// concurrent puts never lose each other's slots.
struct FileVaultShared {
    data: PathBuf,
    key: Zeroizing<[u8; FILE_VAULT_KEY_BYTES]>,
    lock: Mutex<()>,
}

impl FileVaultShared {
    fn open(dir: &Path) -> Result<Self, VaultError> {
        std::fs::create_dir_all(dir).map_err(|_| VaultError::Unavailable)?;
        restrict_directory(dir)?;
        let key = load_or_create_key(&dir.join("vault.key"))?;
        let shared = Self {
            data: dir.join("vault.dat"),
            key,
            lock: Mutex::new(()),
        };
        // A container this key cannot read is reported now, not on the
        // first camera credential lookup.
        shared.read_map()?;
        Ok(shared)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&*self.key).into())
    }

    fn read_map(&self) -> Result<HashMap<String, String>, VaultError> {
        let bytes = match std::fs::metadata(&self.data) {
            Ok(meta) if meta.len() > FILE_VAULT_MAX_BYTES => return Err(VaultError::Unavailable),
            Ok(_) => std::fs::read(&self.data).map_err(|_| VaultError::Unavailable)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(HashMap::new());
            }
            Err(_) => return Err(VaultError::Unavailable),
        };
        let header = FILE_VAULT_MAGIC.len() + FILE_VAULT_NONCE_BYTES;
        if bytes.len() < header || &bytes[..FILE_VAULT_MAGIC.len()] != FILE_VAULT_MAGIC {
            return Err(VaultError::Unavailable);
        }
        let nonce = XNonce::from_slice(&bytes[FILE_VAULT_MAGIC.len()..header]);
        let plaintext = Zeroizing::new(
            self.cipher()
                .decrypt(
                    nonce,
                    Payload {
                        msg: &bytes[header..],
                        aad: FILE_VAULT_MAGIC,
                    },
                )
                .map_err(|_| VaultError::Unavailable)?,
        );
        serde_json::from_slice(&plaintext).map_err(|_| VaultError::Unavailable)
    }

    fn write_map(&self, map: &HashMap<String, String>) -> Result<(), VaultError> {
        let plaintext =
            Zeroizing::new(serde_json::to_vec(map).map_err(|_| VaultError::Unavailable)?);
        let mut nonce = [0u8; FILE_VAULT_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| VaultError::Unavailable)?;
        let ciphertext = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: FILE_VAULT_MAGIC,
                },
            )
            .map_err(|_| VaultError::Unavailable)?;
        let mut container =
            Vec::with_capacity(FILE_VAULT_MAGIC.len() + nonce.len() + ciphertext.len());
        container.extend_from_slice(FILE_VAULT_MAGIC);
        container.extend_from_slice(&nonce);
        container.extend_from_slice(&ciphertext);
        write_private_atomically(&self.data, &container)
    }

    /// Runs `update` against the decrypted map under the lock and persists
    /// the result when it reports a change.
    fn modify<T>(
        &self,
        update: impl FnOnce(&mut HashMap<String, String>) -> Result<(T, bool), VaultError>,
    ) -> Result<T, VaultError> {
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut map = self.read_map()?;
        let result = update(&mut map);
        let persisted = match &result {
            Ok((_, true)) => self.write_map(&map),
            _ => Ok(()),
        };
        for secret in map.values_mut() {
            secret.zeroize();
        }
        persisted?;
        result.map(|(value, _)| value)
    }
}

struct FileBackend {
    shared: Arc<FileVaultShared>,
}

#[async_trait]
impl KeyringBackend for FileBackend {
    async fn put(&self, slot: String, secret: SecretString) -> Result<(), VaultError> {
        let shared = Arc::clone(&self.shared);
        run_blocking(move || {
            shared.modify(move |map| {
                if let Some(mut previous) = map.insert(slot, secret.expose_secret().to_owned()) {
                    previous.zeroize();
                }
                Ok(((), true))
            })
        })
        .await
    }

    async fn get(&self, slot: String) -> Result<SecretString, VaultError> {
        let shared = Arc::clone(&self.shared);
        run_blocking(move || {
            shared.modify(move |map| {
                map.get(&slot)
                    .map(|secret| (SecretString::from(secret.clone()), false))
                    .ok_or(VaultError::NotFound)
            })
        })
        .await
    }

    async fn delete(&self, slot: String) -> Result<(), VaultError> {
        let shared = Arc::clone(&self.shared);
        run_blocking(move || {
            shared.modify(move |map| match map.remove(&slot) {
                Some(mut secret) => {
                    secret.zeroize();
                    Ok(((), true))
                }
                None => Err(VaultError::NotFound),
            })
        })
        .await
    }
}

fn load_or_create_key(path: &Path) -> Result<Zeroizing<[u8; FILE_VAULT_KEY_BYTES]>, VaultError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            if bytes.len() != FILE_VAULT_KEY_BYTES {
                return Err(VaultError::Unavailable);
            }
            let mut key = Zeroizing::new([0u8; FILE_VAULT_KEY_BYTES]);
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut key = Zeroizing::new([0u8; FILE_VAULT_KEY_BYTES]);
            getrandom::fill(&mut *key).map_err(|_| VaultError::Unavailable)?;
            write_private_atomically(path, &*key)?;
            Ok(key)
        }
        Err(_) => Err(VaultError::Unavailable),
    }
}

fn restrict_directory(dir: &Path) -> Result<(), VaultError> {
    #[cfg(not(unix))]
    let _ = dir;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| VaultError::Unavailable)?;
    }
    Ok(())
}

/// Writes `bytes` to `path` owner-only via temp file + fsync + rename, then
/// fsyncs the directory so the rename itself is durable.
fn write_private_atomically(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let parent = path.parent().ok_or(VaultError::Unavailable)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("vault"),
        Uuid::new_v4().simple()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = (|| {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)?;
        // The directory fsync makes the rename durable on Unix; Windows has
        // no equivalent and the rename is already committed there.
        #[cfg(unix)]
        {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok::<(), std::io::Error>(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(VaultError::Unavailable);
    }
    Ok(())
}

async fn run_blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, VaultError> + Send + 'static,
) -> Result<T, VaultError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| VaultError::Unavailable)?
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
    async fn file_vault_round_trips_secrets_owner_only_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let vault = FileVault::open(&root).await.unwrap();
        let owner = camera(40);
        let stream = StreamId::from_uuid(Uuid::from_u128(41));
        let credential = vault
            .put_credential(owner, SecretString::from("cam-pass"))
            .await
            .unwrap();
        let source = vault
            .put_stream_source(owner, stream, SecretString::from("rtsp://u:p@10.0.0.9/s"))
            .await
            .unwrap();
        assert_eq!(
            vault
                .get_credential(owner, &credential)
                .await
                .unwrap()
                .expose_secret(),
            "cam-pass"
        );

        // The container never holds the secret in the clear.
        let container = std::fs::read(root.join("vault.dat")).unwrap();
        assert!(container.starts_with(FILE_VAULT_MAGIC));
        assert!(!container.windows(8).any(|window| window == b"cam-pass"));
        assert!(!container.windows(4).any(|window| window == b"rtsp"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&root), 0o700);
            assert_eq!(mode(&root.join("vault.key")), 0o600);
            assert_eq!(mode(&root.join("vault.dat")), 0o600);
        }

        // A second handle on the same directory reads what the first wrote.
        let reopened = FileVault::open(&root).await.unwrap();
        assert_eq!(
            reopened
                .get_stream_source(owner, stream, &source)
                .await
                .unwrap()
                .expose_secret(),
            "rtsp://u:p@10.0.0.9/s"
        );
        reopened
            .delete_camera_secrets(owner, Some(&credential), &[(stream, source.clone())])
            .await
            .unwrap();
        assert!(matches!(
            vault.get_credential(owner, &credential).await,
            Err(VaultError::NotFound)
        ));
        // Deleting what is already gone is idempotent, like the keyring.
        reopened
            .delete_camera_secrets(owner, Some(&credential), &[(stream, source)])
            .await
            .unwrap();
        // No temp files linger after atomic writes.
        let leftovers: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[tokio::test]
    async fn file_vault_fails_closed_on_a_wrong_key_or_torn_container() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let vault = FileVault::open(&root).await.unwrap();
        vault
            .put_credential(camera(50), SecretString::from("secret"))
            .await
            .unwrap();
        drop(vault);

        // A different key cannot open the container.
        let mut other = [0u8; FILE_VAULT_KEY_BYTES];
        other[0] = 0xff;
        let original = std::fs::read(root.join("vault.key")).unwrap();
        std::fs::write(root.join("vault.key"), other).unwrap();
        assert_eq!(
            FileVault::open(&root).await.map(|_| ()),
            Err(VaultError::Unavailable)
        );
        std::fs::write(root.join("vault.key"), original).unwrap();

        // A truncated container is refused rather than read as empty.
        let container = std::fs::read(root.join("vault.dat")).unwrap();
        std::fs::write(root.join("vault.dat"), &container[..container.len() / 2]).unwrap();
        assert_eq!(
            FileVault::open(&root).await.map(|_| ()),
            Err(VaultError::Unavailable)
        );
        // A short key file is refused too.
        std::fs::write(root.join("vault.dat"), &container).unwrap();
        std::fs::write(root.join("vault.key"), b"short").unwrap();
        assert_eq!(
            FileVault::open(&root).await.map(|_| ()),
            Err(VaultError::Unavailable)
        );
    }

    #[tokio::test]
    async fn file_vault_concurrent_puts_keep_every_slot() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(FileVault::open(dir.path().join("vault")).await.unwrap());
        let owner = camera(60);
        let puts: Vec<_> = (0..8)
            .map(|n| {
                let vault = Arc::clone(&vault);
                tokio::spawn(async move {
                    vault
                        .put_credential(owner, SecretString::from(format!("secret-{n}")))
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut references = Vec::new();
        for put in puts {
            references.push(put.await.unwrap());
        }
        for (n, reference) in references.iter().enumerate() {
            assert_eq!(
                vault
                    .get_credential(owner, reference)
                    .await
                    .unwrap()
                    .expose_secret(),
                format!("secret-{n}")
            );
        }
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
