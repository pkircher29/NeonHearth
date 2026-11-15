# Prepares a GitHub Actions Windows runner to sign with Azure Artifact Signing.
#
# Run it after azure/login, in a job that runs nothing but signing. It
# downloads Microsoft's signing client (SHA-256 pinned), writes the signing
# metadata, and fetches the signing token while the sign-in is still fresh.
# The two paths sign.ps1 needs are written as STEP OUTPUTS (dlib, metadata);
# the signing step passes them to sign.ps1 as step-local environment. They are
# deliberately NOT exported through GITHUB_ENV, which would hand them to every
# later step in the job.
param(
    [Parameter(Mandatory)][string]$Endpoint,
    [Parameter(Mandatory)][string]$Account,
    [Parameter(Mandatory)][string]$CertificateProfile
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Pinned so a changed package cannot slip into a release build unnoticed.
$clientVersion = '1.0.151'
$clientSha256 = '35375a4bc4e1102da729fc3d8d9925f774c3baae6b8b7ff6398d948ca9ab0d8a'

$workDir = Join-Path $env:RUNNER_TEMP 'artifact-signing'
New-Item -ItemType Directory -Force $workDir | Out-Null

$package = Join-Path $workDir 'client.zip'
$url = "https://api.nuget.org/v3-flatcontainer/microsoft.artifactsigning.client/$clientVersion/microsoft.artifactsigning.client.$clientVersion.nupkg"
Invoke-WebRequest -Uri $url -OutFile $package
$actual = (Get-FileHash -Algorithm SHA256 $package).Hash.ToLowerInvariant()
if ($actual -ne $clientSha256) {
    throw "Signing client checksum mismatch: expected $clientSha256, got $actual"
}
$clientDir = Join-Path $workDir 'client'
Expand-Archive -Path $package -DestinationPath $clientDir -Force

# signtool on the runners is x64 (also on Arm64, under emulation), so the x64
# client is the right one everywhere.
$dlib = Join-Path $clientDir 'bin\x64\Azure.CodeSigning.Dlib.dll'
if (-not (Test-Path $dlib)) { throw "Signing client not found at $dlib" }

# Only the Azure CLI sign-in from azure/login may be used.
$metadata = Join-Path $workDir 'metadata.json'
[ordered]@{
    Endpoint               = $Endpoint
    CodeSigningAccountName = $Account
    CertificateProfileName = $CertificateProfile
    ExcludeCredentials     = @(
        'ManagedIdentityCredential',
        'WorkloadIdentityCredential',
        'EnvironmentCredential',
        'SharedTokenCacheCredential',
        'VisualStudioCredential',
        'VisualStudioCodeCredential',
        'AzurePowerShellCredential',
        'AzureDeveloperCliCredential',
        'InteractiveBrowserCredential'
    )
} | ConvertTo-Json | Set-Content -Path $metadata -Encoding utf8

# The GitHub sign-in proof expires minutes after azure/login, so the signing
# token has to be fetched now. The Azure CLI caches it for the build.
$expires = az account get-access-token --scope 'https://codesigning.azure.net/.default' --query expiresOn -o tsv
if ($LASTEXITCODE -ne 0) { throw 'Could not get an Azure Artifact Signing token' }
Write-Host "Signing token is valid until $expires"

if ($env:GITHUB_OUTPUT) {
    "dlib=$dlib" | Add-Content -Path $env:GITHUB_OUTPUT -Encoding utf8
    "metadata=$metadata" | Add-Content -Path $env:GITHUB_OUTPUT -Encoding utf8
}
Write-Host "Code signing is ready (account $Account, profile $CertificateProfile)"
