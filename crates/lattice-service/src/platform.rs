use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    Windows,
    Linux,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformPaths {
    pub state_dir: PathBuf,
    pub database: PathBuf,
    pub backups: PathBuf,
}

pub fn platform_paths(platform: Platform, base: impl AsRef<Path>) -> PlatformPaths {
    let product_dir = match platform {
        Platform::Windows => "NeonHearth",
        Platform::Linux => "neonhearth",
    };
    let state_dir = base.as_ref().join(product_dir);
    PlatformPaths {
        database: state_dir.join("lattice.db"),
        backups: state_dir.join("backups"),
        state_dir,
    }
}
