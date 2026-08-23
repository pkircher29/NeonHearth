#![cfg(unix)]
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use tokio::net::TcpStream;
const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
#[tokio::test]
async fn sigterm_exits_cleanly() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lattice-service"))
        .env("LATTICE_SERVICE_TOKEN", TOKEN)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && TcpStream::connect("127.0.0.1:58120").await.is_err() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
