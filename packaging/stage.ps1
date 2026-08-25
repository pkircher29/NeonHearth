# Stage the NeonHearth Windows release layout.
#
# Builds the release service binary and the desktop UI bundle, then stages
# them (plus installer scripts) into packaging\dist\windows\ so the WiX
# installer definition in packaging\windows\NeonHearth.wxs has a real input.
#
# Usage (from anywhere):
#   pwsh -File packaging\stage.ps1 [-SkipRust] [-SkipUi]
#
# Windows build environment quirks handled here (see docs/build/installers.md):
#   - On the dev machine the stable channel resolves to the windows-gnu
#     toolchain, so mingw64 gcc must be first on PATH (prepended only when
#     C:\msys64 exists; hosted CI runners use the MSVC toolchain and have no
#     msys64).
#   - Linking needs Npcap's Packet.lib import library. If the caller already
#     set RUSTFLAGS (CI points it at an extracted Npcap SDK Lib\x64), it is
#     respected; otherwise the dev-machine default (installed Npcap's
#     System32\Npcap directory) is used.

[CmdletBinding()]
param(
    [switch]$SkipRust,
    [switch]$SkipUi
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PackagingRoot = $PSScriptRoot
$RepoRoot = Split-Path -Parent $PackagingRoot
$DistRoot = Join-Path $PackagingRoot 'dist\windows'
$Desktop = Join-Path $RepoRoot 'apps\desktop'

if (Test-Path 'C:\msys64\mingw64\bin') {
    $env:PATH = 'C:\msys64\mingw64\bin;' + $env:PATH
}
if (-not $env:RUSTFLAGS) {
    $env:RUSTFLAGS = '-L C:\Windows\System32\Npcap'
}
Write-Host "RUSTFLAGS: $env:RUSTFLAGS"

if (-not $SkipRust) {
    Write-Host '== cargo build --release -p lattice-service =='
    Push-Location $RepoRoot
    try {
        cargo build --release -p lattice-service
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    } finally { Pop-Location }
}

if (-not $SkipUi) {
    Write-Host '== npm build apps/desktop =='
    if (-not (Test-Path (Join-Path $Desktop 'node_modules'))) {
        npm --prefix $Desktop ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed with exit code $LASTEXITCODE" }
    }
    npm --prefix $Desktop run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed with exit code $LASTEXITCODE" }
}

$exe = Join-Path $RepoRoot 'target\release\lattice-service.exe'
$uiDist = Join-Path $Desktop 'dist'
if (-not (Test-Path $exe)) { throw "Missing $exe - run without -SkipRust first" }
if (-not (Test-Path (Join-Path $uiDist 'index.html'))) { throw "Missing $uiDist\index.html - run without -SkipUi first" }

Write-Host "== staging into $DistRoot =="
if (Test-Path $DistRoot) { Remove-Item -Recurse -Force $DistRoot }
New-Item -ItemType Directory -Force -Path (Join-Path $DistRoot 'bin') | Out-Null
Copy-Item $exe (Join-Path $DistRoot 'bin\lattice-service.exe')
Copy-Item -Recurse $uiDist (Join-Path $DistRoot 'ui')
New-Item -ItemType Directory -Force -Path (Join-Path $DistRoot 'scripts') | Out-Null
Copy-Item (Join-Path $PackagingRoot 'windows\scripts\*.ps1') (Join-Path $DistRoot 'scripts')

# Deterministic manifest so installer inputs are auditable.
$manifestPath = Join-Path $DistRoot 'STAGING-MANIFEST.txt'
$lines = Get-ChildItem -Recurse -File $DistRoot |
    Where-Object { $_.FullName -ne $manifestPath } |
    Sort-Object FullName |
    ForEach-Object {
        $rel = $_.FullName.Substring($DistRoot.Length + 1)
        '{0}  {1}  {2}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash, $_.Length, $rel
    }
Set-Content -Path $manifestPath -Value $lines

$count = @(Get-ChildItem -Recurse -File $DistRoot).Count
Write-Host "Staged $count files into $DistRoot"
Write-Host "Manifest: $manifestPath"
