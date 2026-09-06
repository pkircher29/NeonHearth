use crate::{
    platform::{self, ProcessStamp},
    windows_launcher::{StartedChildren, clean_command, random_secret, read_bounded, write_atomic},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::Stdio,
    thread,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    port: u16,
    username: String,
    password: String,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

fn config_path(path: &Path) -> Result<String> {
    let value = path.to_str().context("MQTT paths must be valid Unicode")?;
    ensure!(
        !value.contains(['\r', '\n', '\0']),
        "MQTT paths must not contain control characters"
    );
    Ok(value
        .strip_prefix(r"\\?\")
        .unwrap_or(value)
        .replace('\\', "/"))
}

fn provision(root: &Path, state: &Path, port: u16) -> Result<()> {
    let directory = state.join("mqtt");
    if directory.exists() {
        platform::reject_reparse(&directory)?;
        ensure!(
            directory.join("client.json").is_file(),
            "MQTT configuration is incomplete. Existing data will not be overwritten."
        );
        return Ok(());
    }
    let stage = tempfile::Builder::new()
        .prefix("mqtt-setup-")
        .tempdir_in(state)?;
    platform::private_directory(stage.path())?;
    let password = Zeroizing::new(random_secret()?);
    let ha_password = Zeroizing::new(random_secret()?);
    write_atomic(
        &stage.path().join("passwords"),
        Zeroizing::new(format!(
            "neonhearth:{}\nhomeassistant:{}\n",
            *password, *ha_password
        ))
        .as_bytes(),
    )?;
    let mut hash = clean_command(&root.join("mqtt/mosquitto_passwd.exe"));
    hash.arg("-U")
        .arg(stage.path().join("passwords"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    ensure!(hash.status()?.success(), "MQTT password hashing failed");
    let hashed = Zeroizing::new(read_bounded(&stage.path().join("passwords"), 8192)?);
    ensure!(
        !hashed
            .windows(password.len())
            .any(|bytes| bytes == password.as_bytes()),
        "MQTT password file was not hashed"
    );
    write_atomic(&stage.path().join("acl"), b"user neonhearth\ntopic write neonhearth/automation/#\ntopic write neonhearth/network/#\ntopic write neonhearth/status\nuser homeassistant\ntopic read neonhearth/#\ntopic readwrite homeassistant/#\npattern write neonhearth/devices/%u/state\npattern write neonhearth/devices/%u/availability\npattern read neonhearth/devices/%u/set\n")?;
    let config = format!(
        "listener {port} 127.0.0.1\nallow_anonymous false\npassword_file {}\nacl_file {}\npersistence false\nmax_connections 64\nmax_packet_size 4194304\nmax_queued_messages 100\nmax_queued_bytes 4194304\nmemory_limit 67108864\nlog_dest stdout\nlog_type error\nlog_type warning\nconnection_messages false\n",
        config_path(&directory.join("passwords"))?,
        config_path(&directory.join("acl"))?
    );
    write_atomic(&stage.path().join("mosquitto.conf"), config.as_bytes())?;
    let accounts = Zeroizing::new(serde_json::to_vec_pretty(
        &serde_json::json!({"neonhearth":password.as_str(),"homeassistant":ha_password.as_str()}),
    )?);
    write_atomic(&stage.path().join("accounts.json"), &accounts)?;
    let credentials = Credentials {
        port,
        username: "neonhearth".into(),
        password: password.to_string(),
    };
    write_atomic(
        &stage.path().join("client.json"),
        &Zeroizing::new(serde_json::to_vec(&credentials)?),
    )?;
    fs::rename(stage.path(), &directory).context("Could not finish private MQTT setup")?;
    Ok(())
}

fn authenticated(credentials: &Credentials, stamp: &ProcessStamp) -> Result<bool> {
    ensure!(
        platform::process_matches(stamp),
        "The MQTT process identity changed"
    );
    if platform::listener_pid(credentials.port)? != Some(stamp.pid) {
        return Ok(false);
    }
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, credentials.port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_secs(1)) else {
        return Ok(false);
    };
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let mut body = Zeroizing::new(Vec::from(b"\x00\x04MQTT\x04\xc2\x00\x0a"));
    let id = format!("neonhearth-check-{}", std::process::id());
    for value in [
        id.as_str(),
        credentials.username.as_str(),
        credentials.password.as_str(),
    ] {
        ensure!(
            value.len() <= 256,
            "MQTT credential exceeds its supported size"
        );
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value.as_bytes());
    }
    let mut packet = Zeroizing::new(vec![0x10]);
    let mut remaining = body.len();
    loop {
        let byte = (remaining % 128) as u8;
        remaining /= 128;
        packet.push(byte | if remaining > 0 { 128 } else { 0 });
        if remaining == 0 {
            break;
        }
    }
    packet.extend_from_slice(&body);
    stream.write_all(&packet)?;
    let mut reply = [0u8; 4];
    if stream.read_exact(&mut reply).is_err() || reply != [0x20, 0x02, 0, 0] {
        return Ok(false);
    }
    stream.write_all(&[0xe0, 0])?;
    Ok(true)
}

pub(super) fn ensure(
    root: &Path,
    state: &Path,
    port: u16,
    existing: Option<&ProcessStamp>,
    started: &mut StartedChildren,
) -> Result<ProcessStamp> {
    provision(root, state, port)?;
    let credentials: Credentials =
        serde_json::from_slice(&read_bounded(&state.join("mqtt/client.json"), 4096)?)
            .context("Private MQTT configuration is invalid")?;
    ensure!(
        credentials.port == port
            && credentials.username == "neonhearth"
            && (32..=256).contains(&credentials.password.len())
            && credentials.password.is_ascii(),
        "Private MQTT configuration does not match this hub"
    );
    if let Some(stamp) = existing.filter(|stamp| platform::process_matches(stamp)) {
        ensure!(
            authenticated(&credentials, stamp)?,
            "The saved MQTT process is not accepting this hub's credentials"
        );
        return Ok(stamp.clone());
    }
    ensure!(
        platform::listener_pid(port)?.is_none(),
        "MQTT port {port} is already in use. Existing listeners will not be replaced."
    );
    let reservation =
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).context("MQTT port unavailable")?;
    let binary = root.join("mqtt/mosquitto.exe").canonicalize()?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(state.join("mqtt/broker.log"))?;
    let mut command = clean_command(&binary);
    command
        .arg("-c")
        .arg(state.join("mqtt/mosquitto.conf"))
        .stdout(log.try_clone()?)
        .stderr(log);
    drop(reservation);
    let child = command
        .spawn()
        .context("Could not start the packaged MQTT hub")?;
    let child_id = child.id();
    started.children.push(child);
    let stamp = platform::process_stamp(child_id, &binary)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        ensure!(
            started.children.last_mut().unwrap().try_wait()?.is_none(),
            "MQTT exited. Inspect its private broker.log"
        );
        if authenticated(&credentials, &stamp)? {
            return Ok(stamp);
        }
        ensure!(Instant::now() < deadline, "MQTT did not become ready");
        thread::sleep(Duration::from_millis(200));
    }
}
