#[cfg(windows)]
mod mqtt;
#[cfg(windows)]
mod platform;
#[cfg(windows)]
mod windows_launcher;

pub fn run(arguments: Vec<std::ffi::OsString>) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows_launcher::run(arguments)
    }
    #[cfg(not(windows))]
    {
        let _ = arguments;
        anyhow::bail!(
            "This portable launcher currently supports Windows. Use the platform service launcher on Linux."
        )
    }
}
pub fn show_error(message: &str) {
    #[cfg(windows)]
    platform::show_error(message);
    #[cfg(not(windows))]
    eprintln!("{message}");
}
