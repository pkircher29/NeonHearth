#![cfg(unix)]
use std::{
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};
use tempfile::tempdir;
use tokio::net::TcpStream;
const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
struct ChildGuard(Option<Child>);
static LIFECYCLE_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
impl ChildGuard {
    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }
    fn id(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }
    fn disarm(&mut self) {
        self.0.take();
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
#[tokio::test]
async fn sigterm_exits_cleanly() {
    let _lock = LIFECYCLE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let base = tempdir().unwrap();
    let mut child = ChildGuard(Some(
        Command::new(env!("CARGO_BIN_EXE_lattice-service"))
            .env("LATTICE_SERVICE_TOKEN", TOKEN)
            .env("LATTICE_STATE_BASE", base.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    ));
    let pid = child.id();
    let mut ready = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if TcpStream::connect("127.0.0.1:58120").await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(ready);
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.child_mut().try_wait().unwrap() {
            assert!(status.success());
            child.disarm();
            break;
        }
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn daemon_restart_preserves_install_state() {
    let _lock = LIFECYCLE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let base = tempdir().unwrap();
    let token = "owner-token-0123456789abcdefghijkl";
    let mut first = ChildGuard(Some(
        Command::new(env!("CARGO_BIN_EXE_lattice-service"))
            .env("LATTICE_SERVICE_TOKEN", token)
            .env("LATTICE_STATE_BASE", base.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    ));
    wait_ready(first.child_mut()).await;
    stop(&mut first).await;
    let state_dir = base.path().join("neonhearth");
    let db = base.path().join("neonhearth/lattice.db");
    assert!(state_dir.is_dir());
    assert!(state_dir.join("backups").is_dir());
    assert!(db.is_file());
    assert!(state_dir.join("lattice.db.migrate.lock").is_file());
    let pool = lattice_store::connect_path(&db).await.unwrap();
    let before = lattice_store::InstallRepository::new(pool)
        .load()
        .await
        .unwrap()
        .expect("daemon must seed install state");

    let mut second = ChildGuard(Some(
        Command::new(env!("CARGO_BIN_EXE_lattice-service"))
            .env("LATTICE_SERVICE_TOKEN", token)
            .env("LATTICE_STATE_BASE", base.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    ));
    wait_ready(second.child_mut()).await;
    stop(&mut second).await;
    let pool = lattice_store::connect_path(&db).await.unwrap();
    let after = lattice_store::InstallRepository::new(pool)
        .load()
        .await
        .unwrap()
        .expect("install state must persist");
    assert_eq!(before.install_id, after.install_id);
    assert_eq!(before.first_run_at, after.first_run_at);
    assert_eq!(before.schema_version, after.schema_version);
}

async fn wait_ready(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect("127.0.0.1:58120").await.is_ok() {
            return;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("service did not become ready");
}

async fn stop(child: &mut ChildGuard) {
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = child.child_mut().try_wait().unwrap() {
            assert!(status.success());
            child.disarm();
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("service did not stop");
}
