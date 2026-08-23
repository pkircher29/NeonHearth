use std::path::PathBuf;

use lattice_service::{Platform, platform_paths};

#[test]
fn linux_paths_are_service_owned() {
    let paths = platform_paths(Platform::Linux, "/var/lib");

    assert_eq!(paths.state_dir, PathBuf::from("/var/lib/neonhearth"));
    assert_eq!(
        paths.database,
        PathBuf::from("/var/lib/neonhearth/lattice.db")
    );
    assert_eq!(paths.backups, PathBuf::from("/var/lib/neonhearth/backups"));
}

#[test]
fn windows_paths_use_neonhearth_product_directory() {
    let paths = platform_paths(Platform::Windows, r"C:\ProgramData");

    assert!(paths.state_dir.ends_with("NeonHearth"));
    assert!(
        paths
            .database
            .ends_with(PathBuf::from("NeonHearth").join("lattice.db"))
    );
    assert!(
        paths
            .backups
            .ends_with(PathBuf::from("NeonHearth").join("backups"))
    );
}

#[test]
fn paths_are_not_user_or_repository_owned() {
    for platform in [Platform::Linux, Platform::Windows] {
        let paths = platform_paths(platform, "/var/lib");
        for path in [&paths.state_dir, &paths.database, &paths.backups] {
            let rendered = path.to_string_lossy();
            assert!(!rendered.contains("apps/desktop"));
            assert!(!rendered.contains("/home/"));
            assert!(!rendered.contains("/repo/"));
        }
    }
}
