use anyhow::{Context, Result, bail};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

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
    let bytes = read_bounded(&input)?;
    let result = w6_fixture_recorder::record(&bytes, &fp, true)?;
    write_new_atomic(&output, &result)?;
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).context("cannot read input trace")?;
    let mut bytes = Vec::new();
    file.take((w6_fixture_recorder::MAX_INPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .context("cannot read input trace")?;
    if bytes.len() > w6_fixture_recorder::MAX_INPUT {
        bail!("input exceeds safety limit");
    }
    Ok(bytes)
}

fn write_new_atomic(output: &Path, result: &[u8]) -> Result<()> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let stem = output
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("fixture");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = parent.join(format!(".{stem}.tmp-{}-{nonce}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .context("cannot create temporary output")?;
    if let Err(error) = file.write_all(result).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(error).context("cannot write output");
    }
    drop(file);
    let linked = fs::hard_link(&tmp, output).map_err(|error| {
        let _ = fs::remove_file(&tmp);
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!("refusing to overwrite existing output")
        } else {
            error.into()
        }
    });
    let _ = fs::remove_file(&tmp);
    linked.context("cannot finalize output")
}
