// Pin the launcher's own load-time DLL imports to System32 (Windows 10 1607+):
// a DLL planted beside NeonHearth.exe can then not shadow kernel32, crypt32,
// shell32 and the other system libraries the launcher imports.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "msvc");
    if windows && msvc {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
