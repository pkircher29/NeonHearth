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
    let state_dir = match platform {
        Platform::Windows => {
            let base = base.as_ref().to_string_lossy().replace('/', "\\");
            PathBuf::from(format!(r"{}\NeonHearth", base.trim_end_matches('\\')))
        }
        Platform::Linux => base.as_ref().join("neonhearth"),
    };
    let (database, backups) = match platform {
        Platform::Windows => (
            PathBuf::from(format!(r"{}\lattice.db", state_dir.display())),
            PathBuf::from(format!(r"{}\backups", state_dir.display())),
        ),
        Platform::Linux => (state_dir.join("lattice.db"), state_dir.join("backups")),
    };
    PlatformPaths {
        database,
        backups,
        state_dir,
    }
}
