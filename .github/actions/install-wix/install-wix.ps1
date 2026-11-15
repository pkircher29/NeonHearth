# Installs the WiX toolset from SHA-256 pinned NuGet packages.
#
# `dotnet tool install --version` and `wix extension add` trust whatever the
# feed returns for that version. This script downloads the three exact .nupkg
# files, verifies each against the hash recorded here, and only then installs
# the tool from a local folder and unpacks the extensions. Bump all three
# versions and hashes together, after fetching the new packages and
# comparing them with nuget.org's published hashes.
#
# Outputs (GITHUB_OUTPUT): tool_dir, util_ext, bal_ext.
# Run it in jobs that hold NO signing identity: it executes third-party code.
param(
    [Parameter(Mandatory)][string]$WorkDir
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$version = '5.0.2'
$packages = [ordered]@{
    'wix'                                         = 'f30ef0c74e2a986126539c5780be93ac24e8136eaf723b1937b26272703ae173'
    'wixtoolset.util.wixext'                      = 'dda1cc1b4d3b2305b1246f167c6af6fcded5000be84b3bbff3dda4f442bf4740'
    'wixtoolset.bootstrapperapplications.wixext'  = '29c693cee4862760281c06858cc14c4aaaf077bd38df13d0652468af4492d644'
}

$feed = Join-Path $WorkDir 'feed'
New-Item -ItemType Directory -Force $feed | Out-Null
foreach ($id in $packages.Keys) {
    $file = Join-Path $feed "$id.$version.nupkg"
    if (-not (Test-Path -LiteralPath $file)) {
        Invoke-WebRequest -Uri "https://api.nuget.org/v3-flatcontainer/$id/$version/$id.$version.nupkg" -OutFile $file
    }
    $actual = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLowerInvariant()
    if ($actual -ne $packages[$id]) {
        throw "$id $version checksum mismatch: expected $($packages[$id]), got $actual"
    }
}

$toolDir = Join-Path $WorkDir 'tool'
dotnet tool install wix --version $version --tool-path $toolDir --add-source $feed --ignore-failed-sources
if ($LASTEXITCODE -ne 0) { throw 'wix tool installation failed' }

function Expand-Extension([string]$Id, [string]$Dll) {
    $target = Join-Path $WorkDir "ext-$Id"
    Expand-Archive -Path (Join-Path $feed "$Id.$version.nupkg") -DestinationPath $target -Force
    $path = Join-Path $target "wixext5\$Dll"
    if (-not (Test-Path -LiteralPath $path)) { throw "$Dll not found in $Id" }
    return $path
}
$utilExt = Expand-Extension 'wixtoolset.util.wixext' 'WixToolset.Util.wixext.dll'
$balExt = Expand-Extension 'wixtoolset.bootstrapperapplications.wixext' 'WixToolset.BootstrapperApplications.wixext.dll'

& (Join-Path $toolDir 'wix.exe') --version
if ($LASTEXITCODE -ne 0) { throw 'wix does not start' }

if ($env:GITHUB_OUTPUT) {
    "tool_dir=$toolDir" | Add-Content -Path $env:GITHUB_OUTPUT -Encoding utf8
    "util_ext=$utilExt" | Add-Content -Path $env:GITHUB_OUTPUT -Encoding utf8
    "bal_ext=$balExt" | Add-Content -Path $env:GITHUB_OUTPUT -Encoding utf8
}
