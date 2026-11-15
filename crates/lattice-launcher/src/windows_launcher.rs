use crate::{
    mqtt, owner_token,
    platform::{self, ProcessStamp},
};
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::TcpListener,
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MARKER: &str = "NeonHearth private home hub state, format 1\n";

fn ensure_single_collector(legacy_active: bool) -> Result<()> {
    ensure!(
        !legacy_active,
        "The installed NeonHearth service is active. Make a backup and stop that service before starting the Home Hub. Existing device history will not be migrated or replaced automatically."
    );
    Ok(())
}

#[derive(Default)]
struct Options {
    state: Option<PathBuf>,
    port: Option<u16>,
    mqtt_port: Option<u16>,
    no_browser: bool,
    allow_elevated: bool,
    allow_shared_package: bool,
    status: bool,
    stop: bool,
    help: bool,
}
impl Options {
    fn parse(arguments: Vec<OsString>) -> Result<Self> {
        let mut out = Self::default();
        let mut args = arguments.into_iter();
        while let Some(arg) = args.next() {
            match arg.to_str().context("Arguments must be valid Unicode")? {
                "--state" => {
                    out.state = Some(PathBuf::from(
                        args.next().context("--state needs a directory")?,
                    ))
                }
                "--port" | "--mqtt-port" => {
                    let value = args.next().context("Port value missing")?;
                    let value: u16 = value
                        .to_str()
                        .context("Invalid port")?
                        .parse()
                        .context("Invalid port")?;
                    ensure!(value >= 1024, "Ports must be between 1024 and 65535");
                    if arg == "--port" {
                        out.port = Some(value);
                    } else {
                        out.mqtt_port = Some(value);
                    }
                }
                "--no-browser" => out.no_browser = true,
                "--allow-elevated" => out.allow_elevated = true,
                "--allow-shared-package" => out.allow_shared_package = true,
                "--status" => out.status = true,
                "--stop" => out.stop = true,
                "--help" | "-h" => out.help = true,
                _ => bail!("Unknown option. Use --help to see supported options."),
            }
        }
        ensure!(
            !(out.status && out.stop),
            "Choose either --status or --stop"
        );
        Ok(out)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    version: u32,
    port: u16,
    mqtt_port: u16,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    service: Option<ProcessStamp>,
    broker: Option<ProcessStamp>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_version: u32,
    files: Vec<ManifestFile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    path: String,
    bytes: u64,
    sha256: String,
}

pub(super) fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    platform::reject_reparse(path)?;
    let file = File::open(path)?;
    ensure!(file.metadata()?.is_file(), "Expected a regular file");
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= max,
        "Local configuration exceeds its supported size"
    );
    Ok(bytes)
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_bounded(path, 16384)?).context("Local configuration is invalid")
}
pub(super) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        platform::reject_reparse(path)?;
    }
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().context("Invalid output path")?)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|_| anyhow::anyhow!("Could not save private configuration"))?;
    Ok(())
}
pub(super) fn random_secret() -> Result<String> {
    let mut bytes = Zeroizing::new([0u8; 48]);
    getrandom::fill(&mut *bytes)
        .map_err(|_| anyhow::anyhow!("Windows secure random generation failed"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn prepare_state(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let marker = path.join(".neonhearth-data");
    if path.exists() {
        platform::reject_reparse(&path)?;
        if fs::read_dir(&path)?.next().transpose()?.is_some() {
            ensure!(
                marker.is_file() && read_bounded(&marker, 128)? == MARKER.as_bytes(),
                "Select an empty data folder or an existing NeonHearth Home Hub folder. Existing unrelated data will not be changed."
            );
        }
    }
    platform::private_directory(&path)?;
    if !marker.exists() {
        write_atomic(&marker, MARKER.as_bytes())?;
    }
    Ok(path.canonicalize()?)
}
fn lock_state(path: &Path) -> Result<File> {
    let lock_path = path.join("startup.lock");
    if lock_path.exists() {
        platform::reject_reparse(&lock_path)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if file.try_lock_exclusive().is_ok() {
            return Ok(file);
        }
        ensure!(
            Instant::now() < deadline,
            "Another NeonHearth launch is still in progress"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn validate_package(root: &Path) -> Result<()> {
    let manifest: Manifest = serde_json::from_slice(&read_bounded(
        &root.join("PACKAGE-MANIFEST.json"),
        2 * 1024 * 1024,
    )?)
    .context("The package manifest is invalid")?;
    ensure!(
        manifest.format_version == 1 && !manifest.files.is_empty() && manifest.files.len() <= 4096,
        "Unsupported package manifest"
    );
    let mut seen = std::collections::BTreeSet::new();
    for entry in manifest.files {
        let relative = Path::new(&entry.path);
        ensure!(
            relative
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
                && !entry.path.contains('\\')
                && !entry.path.is_empty()
                && seen.insert(entry.path.clone()),
            "Invalid package path"
        );
        ensure!(
            entry.bytes <= 128 * 1024 * 1024
                && entry.sha256.len() == 64
                && entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Invalid package file description"
        );
        let path = root.join(relative);
        // Check every component so a nested junction cannot redirect package reads.
        let mut current = root.to_path_buf();
        for component in relative.components() {
            current.push(component);
            platform::reject_reparse(&current)?;
        }
        let mut file = File::open(&path)
            .with_context(|| format!("The package is incomplete: {}", entry.path))?;
        ensure!(
            file.metadata()?.len() == entry.bytes,
            "Package file changed: {}. Extract a complete package again.",
            entry.path
        );
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        ensure!(
            format!("{:x}", hash.finalize()) == entry.sha256.to_ascii_lowercase(),
            "Package checksum mismatch: {}. Extract a complete package again.",
            entry.path
        );
    }
    reject_unlisted_files(root, &seen)?;
    for required in [
        "bin/lattice-service.exe",
        "mqtt/mosquitto.exe",
        "mqtt/mosquitto_passwd.exe",
        "ui/index.html",
    ] {
        ensure!(
            seen.contains(required),
            "Required package component is absent from the manifest: {required}"
        );
    }
    Ok(())
}

/// Every file under the package root must be in the manifest. A DLL dropped
/// next to mosquitto.exe or lattice-service.exe would otherwise be loaded by
/// Windows (application directory first) without ever being hashed.
fn reject_unlisted_files(root: &Path, listed: &std::collections::BTreeSet<String>) -> Result<()> {
    let listed: std::collections::BTreeSet<String> =
        listed.iter().map(|name| name.to_lowercase()).collect();
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            platform::reject_reparse(&path)?;
            visited += 1;
            ensure!(visited <= 16384, "The package contains too many entries");
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .context("Package entry is outside the package")?
                .components()
                .map(|part| part.as_os_str().to_string_lossy().to_lowercase())
                .collect::<Vec<_>>()
                .join("/");
            ensure!(
                relative == "package-manifest.json" || listed.contains(&relative),
                "The package folder contains a file that is not part of the package: {relative}. Extract a complete package again into a new empty folder."
            );
        }
    }
    Ok(())
}

/// Packaged programs must not be replaceable by other accounts. Checked on the
/// package root, every directory, and every program or library.
fn verify_package_permissions(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        if let Some(writer) = platform::untrusted_writer(&directory)? {
            bail!(
                "The package folder {} can be changed by {writer}. Extract NeonHearth into a folder only you (and administrators) can write, such as a new folder under your profile. Use --allow-shared-package only if you accept this risk.",
                directory.display()
            );
        }
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| {
                let extension = extension.to_string_lossy().to_lowercase();
                extension == "exe" || extension == "dll"
            }) && let Some(writer) = platform::untrusted_writer(&path)?
            {
                bail!(
                    "The package file {} can be changed by {writer}. Extract NeonHearth again into a private folder.",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// When the launcher itself carries a valid signature, the collector (which
/// receives the owner credential) must be signed by the same publisher. An
/// unsigned launcher (development build) leaves nothing to compare with.
fn verify_collector_signature(launcher: &Path, collector: &Path) -> Result<()> {
    let platform::Signature::Valid { signer } = platform::authenticode(launcher)? else {
        return Ok(());
    };
    match platform::authenticode(collector)? {
        platform::Signature::Valid { signer: other } if other == signer => Ok(()),
        platform::Signature::Valid { signer: other } => bail!(
            "The collector is signed by {other}, not {signer}. Extract a complete package again."
        ),
        platform::Signature::Unsigned => bail!(
            "The launcher is signed by {signer} but the collector is not signed. Extract a complete package again."
        ),
    }
}

/// Known cloud-sync locations for the private state folder, if the chosen path is inside one.
fn sync_folder_warning(path: &Path) -> Option<String> {
    let lowered = path.to_string_lossy().to_lowercase().replace('/', "\\");
    let by_name = [
        "\\onedrive",
        "\\dropbox",
        "\\google drive",
        "\\googledrive",
        "\\icloud",
        "\\box sync",
        "\\nextcloud",
        "\\pcloud",
        "\\mega",
    ]
    .iter()
    .any(|marker| lowered.contains(marker));
    let by_environment = ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]
        .iter()
        .filter_map(std::env::var_os)
        .any(|root| {
            let root = PathBuf::from(root).to_string_lossy().to_lowercase();
            !root.is_empty() && lowered.starts_with(&root)
        });
    (by_name || by_environment).then(|| {
        "The data folder looks like it is inside a cloud-sync folder. It holds your device history and MQTT passwords in plain files; choose a folder that is not synced.".to_owned()
    })
}

fn load_owner(state: &Path) -> Result<SecretString> {
    let path = state.join("owner.dpapi");
    if !path.exists() {
        let secret = Zeroizing::new(random_secret()?);
        write_atomic(
            &path,
            &platform::protect(secret.as_bytes(), false, Some(platform::OWNER_ENTROPY))?,
        )?;
    }
    let blob = read_bounded(&path, 16384)?;
    // Format 2 carries application entropy; format 1 files (no entropy) from
    // earlier builds must still open, and are re-sealed in place afterwards.
    let (decrypted, legacy) = match platform::protect(&blob, true, Some(platform::OWNER_ENTROPY)) {
        Ok(value) => (Zeroizing::new(value), false),
        Err(_) => (Zeroizing::new(platform::protect(&blob, true, None)?), true),
    };
    ensure!(
        decrypted.len() == 96 && decrypted.iter().all(u8::is_ascii_hexdigit),
        "The saved owner credential is invalid"
    );
    if legacy {
        write_atomic(
            &path,
            &platform::protect(&decrypted, false, Some(platform::OWNER_ENTROPY))?,
        )?;
    }
    Ok(SecretString::from(String::from_utf8(decrypted.to_vec())?))
}

fn authenticated(
    client: &reqwest::blocking::Client,
    port: u16,
    owner: &SecretString,
    stamp: &ProcessStamp,
) -> Result<bool> {
    ensure!(
        platform::process_matches(stamp),
        "The saved service process identity changed"
    );
    if platform::listener_pid(port)? != Some(stamp.pid) {
        return Ok(false);
    }
    Ok(client
        .get(format!("http://127.0.0.1:{port}/api/v1/state"))
        .bearer_auth(owner.expose_secret())
        .send()
        .is_ok_and(|response| response.status() == 200))
}
pub(super) fn clean_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    command.current_dir(binary.parent().expect("absolute packaged binary"));
    for (name, _) in std::env::vars_os() {
        let upper = name.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("LATTICE_")
            || upper.starts_with("RUST_LOG")
            || upper.starts_with("MOSQUITTO_")
        {
            command.env_remove(name);
        }
    }
    command.stdin(Stdio::null());
    platform::hide(&mut command);
    command
}
pub(super) struct StartedChildren {
    pub children: Vec<Child>,
    pub keep: bool,
}
impl Drop for StartedChildren {
    fn drop(&mut self) {
        if !self.keep {
            for child in self.children.iter_mut().rev() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

pub(super) fn run(arguments: Vec<OsString>) -> Result<()> {
    platform::restrict_dll_search();
    platform::prevent_stdio_inheritance()?;
    let options = Options::parse(arguments)?;
    if options.help {
        println!(
            "NeonHearth.exe [--no-browser] [--state DIRECTORY] [--port PORT] [--mqtt-port PORT]\nNeonHearth.exe --status [--state DIRECTORY]\nNeonHearth.exe --stop [--state DIRECTORY]\nLocal data is preserved when stopping. No administrator rights, Python, Node, or packet driver are required."
        );
        return Ok(());
    }
    ensure!(
        options.allow_elevated || !platform::is_elevated()?,
        "NeonHearth must not run as administrator: the collector and broker would start with administrator rights and the private data folder would belong to the elevated account. Open NeonHearth.exe normally (not \"Run as administrator\"). Use --allow-elevated only for automated testing."
    );
    if !options.status && !options.stop {
        ensure_single_collector(platform::legacy_collector_active()?)?;
    }
    let selected = options
        .state
        .clone()
        .map(Ok)
        .unwrap_or_else(platform::default_state)?;
    if (options.status || options.stop) && !selected.exists() {
        println!("{{\"status\":\"not_started\"}}");
        return Ok(());
    }
    let state = prepare_state(&selected)?;
    let warning = sync_folder_warning(&state);
    if let Some(text) = &warning {
        eprintln!("{text}");
    }
    let _lock = lock_state(&state)?;
    let config_path = state.join("config.json");
    let config: Configuration = if config_path.exists() {
        read_json(&config_path)?
    } else {
        let value = Configuration {
            version: 1,
            port: options.port.unwrap_or(58121),
            mqtt_port: options.mqtt_port.unwrap_or(58183),
        };
        ensure!(
            value.port != value.mqtt_port,
            "The dashboard and MQTT need different ports"
        );
        write_atomic(&config_path, &serde_json::to_vec_pretty(&value)?)?;
        value
    };
    ensure!(
        config.version == 1
            && config.port >= 1024
            && config.mqtt_port >= 1024
            && config.port != config.mqtt_port,
        "Saved ports or configuration version are invalid"
    );
    ensure!(
        options.port.is_none_or(|value| value == config.port)
            && options
                .mqtt_port
                .is_none_or(|value| value == config.mqtt_port),
        "This data folder already uses different ports. Use its saved ports or a new empty data folder."
    );
    let runtime_path = state.join("runtime.json");
    let mut runtime: Runtime = if runtime_path.exists() {
        read_json(&runtime_path)?
    } else {
        Runtime::default()
    };
    if options.stop {
        for (stamp, expected) in [
            (&runtime.service, "lattice-service.exe"),
            (&runtime.broker, "mosquitto.exe"),
        ] {
            if let Some(stamp) = stamp {
                ensure!(
                    stamp
                        .binary
                        .file_name()
                        .is_some_and(|name| name == expected),
                    "Saved process is not a NeonHearth component"
                );
                platform::stop(stamp)?;
            }
        }
        write_atomic(&runtime_path, &serde_json::to_vec(&Runtime::default())?)?;
        println!("{{\"status\":\"stopped\",\"data_preserved\":true}}");
        return Ok(());
    }
    // The service's rotated `owner-token` file wins over the sealed credential
    // (the service applies the same precedence to the token it is given), so
    // a rotation survives a restart. Read at every launch: the launcher is a
    // one-shot process, so there is no long-lived session to refresh.
    let (owner, owner_source) = owner_token::resolve_owner_token(
        &owner_token::portable_token_file(&state),
        || load_owner(&state),
    )?;
    if owner_source == owner_token::TokenSource::FallbackUnreadable {
        eprintln!(
            "The collector's owner-token file exists but cannot be read by this account; using the saved launcher credential. If sign-in fails after a token rotation, check the data folder permissions."
        );
    }
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()?;
    let service_ready = runtime
        .service
        .as_ref()
        .is_some_and(|stamp| authenticated(&client, config.port, &owner, stamp).unwrap_or(false));
    if options.status {
        println!(
            "{}",
            serde_json::json!({"status":if service_ready {"ready"} else {"not_running"},"url":format!("http://127.0.0.1:{}",config.port),"service_pid":runtime.service.as_ref().filter(|_| service_ready).map(|stamp|stamp.pid),"mqtt_running":runtime.broker.as_ref().is_some_and(|stamp|platform::process_matches(stamp) && platform::listener_pid(config.mqtt_port).ok().flatten()==Some(stamp.pid))})
        );
        return Ok(());
    }
    let executable = std::env::current_exe()?.canonicalize()?;
    let root = executable
        .parent()
        .context("The executable has no package directory")?;
    validate_package(root)?;
    if !options.allow_shared_package {
        verify_package_permissions(root)?;
    }
    verify_collector_signature(&executable, &root.join("bin/lattice-service.exe"))?;
    let mut started = StartedChildren {
        children: vec![],
        keep: false,
    };
    let broker = mqtt::ensure(
        root,
        &state,
        config.mqtt_port,
        runtime.broker.as_ref(),
        &mut started,
    )?;
    runtime.broker = Some(broker);
    if !service_ready {
        ensure!(
            platform::listener_pid(config.port)?.is_none(),
            "Dashboard port {} is already in use. Existing listeners will not be replaced.",
            config.port
        );
        let reservation = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, config.port))
            .context("The dashboard port is unavailable")?;
        let binary = root.join("bin/lattice-service.exe").canonicalize()?;
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(state.join("service.log"))?;
        let mut command = clean_command(&binary);
        command
            .env("LATTICE_BIND", format!("127.0.0.1:{}", config.port))
            .env("LATTICE_SERVICE_TOKEN", owner.expose_secret())
            .env("LATTICE_STATE_BASE", state.join("data"))
            .env("LATTICE_UI_DIR", root.join("ui"))
            .env(
                "LATTICE_MQTT_CREDENTIAL_FILE",
                state.join("mqtt/client.json"),
            )
            .env("RUST_LOG", "lattice_service=warn,lattice_sensor=warn")
            .stdout(log.try_clone()?)
            .stderr(log);
        drop(reservation);
        let child = command
            .spawn()
            .context("Could not start the packaged collector")?;
        let child_id = child.id();
        started.children.push(child);
        let stamp = platform::process_stamp(child_id, &binary)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            ensure!(
                started.children.last_mut().unwrap().try_wait()?.is_none(),
                "The collector exited. Inspect the private service.log for details."
            );
            if authenticated(&client, config.port, &owner, &stamp)? {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "The collector did not become ready. Inspect the private service.log."
            );
            thread::sleep(Duration::from_millis(200));
        }
        runtime.service = Some(stamp);
    }
    write_atomic(&runtime_path, &serde_json::to_vec_pretty(&runtime)?)?;
    started.keep = true;
    if !options.no_browser {
        platform::open_browser(&format!(
            "http://127.0.0.1:{}/#token={}",
            config.port,
            owner.expose_secret()
        ))?;
    }
    println!(
        "{}",
        serde_json::json!({"status":"ready","url":format!("http://127.0.0.1:{}",config.port),"service_pid":runtime.service.map(|stamp|stamp.pid),"mqtt_pid":runtime.broker.map(|stamp|stamp.pid),"warnings":warning.into_iter().collect::<Vec<_>>()})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn starting_a_second_collector_requires_stopping_the_legacy_service_first() {
        let error = ensure_single_collector(true).unwrap_err().to_string();
        assert!(error.contains("installed NeonHearth service"));
        assert!(error.contains("backup"));
        assert!(ensure_single_collector(false).is_ok());
    }
    #[test]
    fn state_setup_refuses_unrelated_nonempty_directories() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("important.txt");
        fs::write(&file, "preserve this").unwrap();
        assert!(prepare_state(directory.path()).is_err());
        assert_eq!(fs::read_to_string(file).unwrap(), "preserve this");
    }
    #[test]
    fn owner_credential_is_encrypted_and_stable_across_launches() {
        let parent = tempfile::tempdir().unwrap();
        let state = prepare_state(&parent.path().join("private")).unwrap();
        let first = load_owner(&state).unwrap();
        let second = load_owner(&state).unwrap();
        assert_eq!(first.expose_secret(), second.expose_secret());
        assert!(
            !fs::read(state.join("owner.dpapi"))
                .unwrap()
                .windows(first.expose_secret().len())
                .any(|bytes| bytes == first.expose_secret().as_bytes())
        );
    }
    #[test]
    fn a_rotated_service_token_file_wins_over_the_sealed_credential() {
        let parent = tempfile::tempdir().unwrap();
        let state = prepare_state(&parent.path().join("private")).unwrap();
        let file = owner_token::portable_token_file(&state);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "fake-rotated-token-0123456789-ABCDEFGHIJ\n").unwrap();
        let (owner, source) =
            owner_token::resolve_owner_token(&file, || load_owner(&state)).unwrap();
        assert_eq!(
            owner.expose_secret(),
            "fake-rotated-token-0123456789-ABCDEFGHIJ"
        );
        assert_eq!(source, owner_token::TokenSource::File);
        // The sealed credential was not consulted, so it was not created.
        assert!(!state.join("owner.dpapi").exists());
        // Deleting the file returns to the sealed credential.
        fs::remove_file(&file).unwrap();
        let (fallback, source) =
            owner_token::resolve_owner_token(&file, || load_owner(&state)).unwrap();
        assert_eq!(source, owner_token::TokenSource::Fallback);
        assert_eq!(
            fallback.expose_secret(),
            load_owner(&state).unwrap().expose_secret()
        );
    }
    fn sample_package(root: &Path) {
        let mut files = Vec::new();
        for name in [
            "bin/lattice-service.exe",
            "mqtt/mosquitto.exe",
            "mqtt/mosquitto_passwd.exe",
            "ui/index.html",
        ] {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, name.as_bytes()).unwrap();
            files.push(serde_json::json!({
                "path": name,
                "bytes": name.len(),
                "sha256": format!("{:x}", Sha256::digest(name.as_bytes())),
            }));
        }
        fs::write(
            root.join("PACKAGE-MANIFEST.json"),
            serde_json::to_vec(&serde_json::json!({"format_version": 1, "files": files})).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn a_complete_package_validates_and_an_unlisted_file_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        sample_package(directory.path());
        validate_package(directory.path()).unwrap();
        fs::write(directory.path().join("mqtt/vcruntime140.dll"), b"planted").unwrap();
        let error = validate_package(directory.path()).unwrap_err().to_string();
        assert!(error.contains("not part of the package"), "{error}");
        assert!(error.contains("mqtt/vcruntime140.dll"));
    }
    #[test]
    fn an_unlisted_file_in_a_new_folder_is_rejected_case_insensitively() {
        let directory = tempfile::tempdir().unwrap();
        sample_package(directory.path());
        fs::create_dir(directory.path().join("extra")).unwrap();
        fs::write(directory.path().join("extra/Readme.TXT"), b"x").unwrap();
        assert!(validate_package(directory.path()).is_err());
        // Differences in case from the manifest are the same Windows file.
        let other = tempfile::tempdir().unwrap();
        sample_package(other.path());
        assert!(
            reject_unlisted_files(
                other.path(),
                &[
                    "BIN/Lattice-Service.exe",
                    "mqtt/mosquitto.exe",
                    "mqtt/mosquitto_passwd.exe",
                    "ui/index.html"
                ]
                .iter()
                .map(|name| name.to_string())
                .collect()
            )
            .is_ok()
        );
    }
    #[test]
    fn existing_format_one_credentials_still_open_and_are_resealed() {
        let parent = tempfile::tempdir().unwrap();
        let state = prepare_state(&parent.path().join("private")).unwrap();
        let secret = random_secret().unwrap();
        // Exactly what earlier builds wrote: DPAPI without entropy.
        let legacy = platform::protect(secret.as_bytes(), false, None).unwrap();
        fs::write(state.join("owner.dpapi"), &legacy).unwrap();
        let opened = load_owner(&state).unwrap();
        assert_eq!(opened.expose_secret(), secret);
        let resealed = fs::read(state.join("owner.dpapi")).unwrap();
        assert_ne!(resealed, legacy);
        assert!(platform::protect(&resealed, true, None).is_err());
        assert_eq!(
            platform::protect(&resealed, true, Some(platform::OWNER_ENTROPY)).unwrap(),
            secret.as_bytes()
        );
        assert_eq!(load_owner(&state).unwrap().expose_secret(), secret);
    }
    #[test]
    fn a_new_credential_is_sealed_with_entropy() {
        let parent = tempfile::tempdir().unwrap();
        let state = prepare_state(&parent.path().join("private")).unwrap();
        load_owner(&state).unwrap();
        let blob = fs::read(state.join("owner.dpapi")).unwrap();
        assert!(platform::protect(&blob, true, None).is_err());
    }
    #[test]
    fn an_unsigned_launcher_does_not_demand_a_collector_signature() {
        let exe = std::env::current_exe().unwrap();
        assert!(verify_collector_signature(&exe, &exe).is_ok());
    }
    #[test]
    fn sync_folders_are_recognised() {
        assert!(sync_folder_warning(Path::new(r"C:\Users\p\OneDrive\NeonHearth")).is_some());
        assert!(sync_folder_warning(Path::new(r"D:\Dropbox\hub")).is_some());
        assert!(
            sync_folder_warning(Path::new(r"C:\Users\p\AppData\Local\NeonHearthHomeHub")).is_none()
        );
    }
    #[test]
    fn administrator_and_shared_package_flags_parse() {
        let options = Options::parse(vec![
            "--allow-elevated".into(),
            "--allow-shared-package".into(),
        ])
        .unwrap();
        assert!(options.allow_elevated && options.allow_shared_package);
        assert!(!Options::parse(vec![]).unwrap().allow_elevated);
    }
    #[test]
    fn an_unrelated_listener_never_receives_the_owner_credential() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut stamp =
            platform::process_stamp(std::process::id(), &std::env::current_exe().unwrap()).unwrap();
        stamp.created += 1;
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        assert!(
            authenticated(
                &client,
                listener.local_addr().unwrap().port(),
                &SecretString::from("private test owner"),
                &stamp
            )
            .is_err()
        );
        assert!(listener.accept().is_err());
    }
}
