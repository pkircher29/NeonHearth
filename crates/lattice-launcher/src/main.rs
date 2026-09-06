#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let interactive = arguments.is_empty();
    if let Err(error) = lattice_launcher::run(arguments) {
        let message = format!("NeonHearth could not start.\n\n{error:#}");
        eprintln!("{message}");
        if interactive {
            lattice_launcher::show_error(&message);
        }
        std::process::exit(1);
    }
}
