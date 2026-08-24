use anyhow::{Context, Result, bail};
use std::{env, fs, path::PathBuf};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(2);
    }
}
fn run() -> Result<()> {
    let a: Vec<String> = env::args().collect();
    if a.iter().any(|x| x == "--help" || x == "-h") {
        println!(
            "w6-fixture-recorder\nSafely sanitize an owner-exported HAR/offline HTTP trace.\n\nUsage: w6-fixture-recorder --owner-authorized-home-router --input TRACE.har --output FIXTURE.json --fingerprint FIRMWARE\n\nExport the HAR from your home router's admin UI or browser tools while offline. The export may contain secrets; inspect and protect it, then this tool strips credentials, bodies, query values, identifiers, and network details. This tool never captures traffic or makes router requests."
        );
        return Ok(());
    }
    let val = |name: &str| {
        a.windows(2)
            .find(|w| w[0] == name)
            .map(|w| w[1].clone())
            .with_context(|| format!("missing {name}"))
    };
    if !a.iter().any(|x| x == "--owner-authorized-home-router") {
        bail!("refusing: --owner-authorized-home-router is required")
    }
    let input: PathBuf = val("--input")?.into();
    let output: PathBuf = val("--output")?.into();
    let fp = val("--fingerprint")?;
    let bytes = fs::read(&input).context("cannot read input trace")?;
    let result = w6_fixture_recorder::record(&bytes, &fp, true)?;
    if output.exists() {
        bail!("refusing to overwrite existing output")
    };
    let tmp = output.with_extension("tmp");
    fs::write(&tmp, &result).context("cannot write output")?;
    fs::rename(tmp, output).context("cannot finalize output")?;
    Ok(())
}
