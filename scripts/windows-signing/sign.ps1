# Signs one file with Azure Artifact Signing. setup.ps1 must have run first in
# the same job; its `dlib` and `metadata` step outputs are passed to this script
# through the signing step's own environment (ARTIFACT_SIGNING_DLIB and
# ARTIFACT_SIGNING_METADATA), never through GITHUB_ENV.
param(
    [Parameter(Mandatory, Position = 0)][string]$File
)

$ErrorActionPreference = 'Stop'

foreach ($name in 'ARTIFACT_SIGNING_DLIB', 'ARTIFACT_SIGNING_METADATA') {
    $value = [Environment]::GetEnvironmentVariable($name)
    if (-not $value -or -not (Test-Path $value)) {
        throw "$name is not set or the file is missing. Run setup.ps1 first."
    }
}
if (-not (Test-Path $File)) { throw "File to sign not found: $File" }

$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$signtool = Get-ChildItem -Path (Join-Path $kits '10.*\x64\signtool.exe') -ErrorAction SilentlyContinue |
    Sort-Object { [version]$_.Directory.Parent.Name } |
    Select-Object -Last 1
if (-not $signtool) { throw "signtool.exe not found under $kits" }

# The signing service and timestamp server are remote, so allow brief retries.
$attempts = 4
for ($attempt = 1; $attempt -le $attempts; $attempt++) {
    & $signtool.FullName sign /v /fd SHA256 `
        /tr 'http://timestamp.acs.microsoft.com' /td SHA256 `
        /dlib $env:ARTIFACT_SIGNING_DLIB /dmdf $env:ARTIFACT_SIGNING_METADATA `
        $File
    if ($LASTEXITCODE -eq 0) { exit 0 }
    Write-Warning "Signing $File failed (attempt $attempt of $attempts, exit code $LASTEXITCODE)"
    if ($attempt -lt $attempts) { Start-Sleep -Seconds (10 * $attempt) }
}
exit 1
