# Generate CycloneDX SBOMs for the Rust workspace and the desktop app.
# Thin wrapper: see docs/build/supply-chain.md for context and prerequisites
# (cargo install cargo-cyclonedx --locked; Node 22 with npm).
# SBOM files (*.cdx.json) are build artifacts — do not commit them.
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

# Windows dev-box quirk: keep msys64 gcc ahead of GStreamer's shadowing DLLs
# and let anything that links pcap find Npcap.
$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH
if (-not $env:RUSTFLAGS) { $env:RUSTFLAGS = "-L C:\Windows\System32\Npcap" }

Push-Location $repoRoot
try {
    cargo cyclonedx --format json
    if ($LASTEXITCODE -ne 0) { throw "cargo cyclonedx failed ($LASTEXITCODE)" }

    Push-Location (Join-Path $repoRoot "apps\desktop")
    try {
        npm sbom --sbom-format cyclonedx --package-lock-only | Out-File -Encoding utf8 desktop.cdx.json
        if ($LASTEXITCODE -ne 0) { throw "npm sbom failed ($LASTEXITCODE)" }
    } finally { Pop-Location }

    Get-ChildItem -Recurse -Filter *.cdx.json $repoRoot |
        Where-Object { $_.FullName -notmatch '\\node_modules\\|\\target\\' } |
        ForEach-Object { Write-Host "SBOM: $($_.FullName)" }
} finally { Pop-Location }
