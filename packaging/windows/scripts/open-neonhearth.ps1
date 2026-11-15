# NeonHearth launcher: open the dashboard in the default browser, pre-paired.
#
# Invoked by the Start-menu "NeonHearth" shortcut (powershell.exe
# -WindowStyle Hidden ... -File this-script). What it does:
#   1. Reads the owner token the way the service resolves it: the
#      %ProgramData%\NeonHearth\owner-token file first (written by
#      configure-service.ps1 and rewritten when the owner rotates the token),
#      then, for installs that predate that file, LATTICE_SERVICE_TOKEN from
#      the service-private Environment registry value. LATTICE_BIND (the
#      port) always comes from the registry value.
#   2. Opens http://127.0.0.1:<port>/#token=<token> in the default browser.
#      The token travels in the URL FRAGMENT: fragments are never sent over
#      the network, and the service listens on loopback only anyway. The UI
#      parses the fragment on load, stores the token in sessionStorage, and
#      immediately strips it from the address bar (apps/desktop pairing.ts).
#
# Reading the service Environment value or the token file requires
# administrator rights (both are ACL'd to SYSTEM/Administrators/service), so
# this script self-elevates (one UAC prompt) when the read is denied. The
# browser itself is launched through the non-elevated shell (explorer.exe)
# so the elevated context does not leak into the browser process.

[CmdletBinding()]
param(
    [string]$ServiceName = 'NeonHearth'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Failure {
    param([string]$Message)
    # The shortcut runs with -WindowStyle Hidden, so console output is
    # invisible; use a plain popup for the failure path.
    try {
        (New-Object -ComObject WScript.Shell).Popup($Message, 0, 'NeonHearth', 48) | Out-Null
    } catch {
        Write-Host $Message
    }
    exit 1
}

$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

$entries = $null
try {
    $prop = Get-ItemProperty -Path $serviceKey -Name 'Environment' -ErrorAction Stop
    $entries = @($prop.Environment)
} catch [System.Security.SecurityException] {
    $entries = $null
} catch [System.UnauthorizedAccessException] {
    $entries = $null
} catch [System.Management.Automation.ItemNotFoundException] {
    Show-Failure "The $ServiceName service is not installed. Run the NeonHearth installer first."
} catch {
    $entries = $null
}

if ($null -eq $entries) {
    # Access denied: relaunch elevated (single UAC prompt) and let that
    # instance do the read + launch, then exit this one.
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Show-Failure "Could not read the $ServiceName pairing token from the service configuration. Re-run the installer or configure-service.ps1."
    }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
            '-ExecutionPolicy', 'Bypass',
            '-File', "`"$PSCommandPath`"",
            '-ServiceName', "`"$ServiceName`""
        )
    } catch {
        # User declined the UAC prompt: nothing to do.
        exit 1
    }
    exit 0
}

$token = $null
$port = 58120
foreach ($entry in $entries) {
    if ($entry -like 'LATTICE_SERVICE_TOKEN=*') {
        $token = $entry.Substring('LATTICE_SERVICE_TOKEN='.Length)
    } elseif ($entry -like 'LATTICE_BIND=*') {
        $bind = $entry.Substring('LATTICE_BIND='.Length)
        if ($bind -match ':(\d+)$') { $port = [int]$Matches[1] }
    }
}

# The token file wins over the registry value, as in the service. It is read
# at every launch, so a rotation is picked up without reinstalling. Only
# administrators can read it; this point is reached elevated (a standard user
# is denied the registry read above and relaunched elevated).
$tokenFile = Join-Path $env:ProgramData 'NeonHearth\owner-token'
try {
    if (Test-Path -LiteralPath $tokenFile -PathType Leaf) {
        $fromFile = ([System.IO.File]::ReadAllText($tokenFile)).Trim()
        if ($fromFile) { $token = $fromFile }
    }
} catch {
    # Unreadable: keep the registry value, if any.
}

if (-not $token) {
    Show-Failure "No pairing token is configured for the $ServiceName service. Re-run the installer or configure-service.ps1."
}
if ($token -notmatch '^[A-Za-z0-9._-]{32,}\z') {
    Show-Failure 'The stored pairing token is malformed. Re-run configure-service.ps1 to regenerate it.'
}

$url = "http://127.0.0.1:$port/#token=$token"

# Launch through the (non-elevated) shell so the default browser does not
# inherit administrator rights when this script had to elevate.
try {
    Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList $url
} catch {
    Start-Process $url
}
