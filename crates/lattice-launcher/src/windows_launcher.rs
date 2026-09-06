use crate::{
    mqtt,
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

#[derive(Default)]
struct Options {
    state: Option<PathBuf>,
    port: Option<u16>,
    mqtt_port: Option<u16>,
    no_browser: bool,
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

fn load_owner(state: &Path) -> Result<SecretString> {
    let path = state.join("owner.dpapi");
    if !path.exists() {
        let secret = Zeroizing::new(random_secret()?);
        write_atomic(&path, &platform::protect(secret.as_bytes(), false)?)?;
    }
    let decrypted = Zeroizing::new(platform::protect(&read_bounded(&path, 16384)?, true)?);
    ensure!(
        decrypted.len() == 96 && decrypted.iter().all(u8::is_ascii_hexdigit),
        "The saved owner credential is invalid"
    );
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
    let options = Options::parse(arguments)?;
    if options.help {
        println!(
            "NeonHearth.exe [--no-browser] [--state DIRECTORY] [--port PORT] [--mqtt-port PORT]\nNeonHearth.exe --status [--state DIRECTORY]\nNeonHearth.exe --stop [--state DIRECTORY]\nLocal data is preserved when stopping. No administrator rights, Python, Node, or packet driver are required."
        );
        return Ok(());
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
    let owner = load_owner(&state)?;
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
        serde_json::json!({"status":"ready","url":format!("http://127.0.0.1:{}",config.port),"service_pid":runtime.service.map(|stamp|stamp.pid),"mqtt_pid":runtime.broker.map(|stamp|stamp.pid)})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
