#![cfg(unix)]
use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::net::TcpStream;
const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
struct ChildGuard(Option<Child>);
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
    let mut child = ChildGuard(Some(
        Command::new(env!("CARGO_BIN_EXE_lattice-service"))
            .env("LATTICE_SERVICE_TOKEN", TOKEN)
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
