# NeonHearth service post-install configuration.
#
# Run elevated. Invoked by the installer after the service is registered, and
# safe to re-run manually (for example after installing Npcap later).
#
# What this script does (and why it is a script, not installer authoring):
#   1. Generates the LATTICE_SERVICE_TOKEN pairing secret on first install and
#      stores it in the service-private Environment registry value. The service
#      binary refuses to start without it (see crates/lattice-service/src/main.rs)
#      and MSI authoring cannot generate per-machine random secrets.
#   2. Creates %ProgramData%\NeonHearth and grants the service's virtual account
#      (NT SERVICE\NeonHearth) modify rights on it.
#   3. Detects Npcap. The service executable is linked against Npcap's
#      Packet.dll (via pnet_datalink), so:
#        - Npcap present in WinPcap-compatible mode (System32\Packet.dll):
#          nothing extra needed.
#        - Npcap present only under System32\Npcap: a PATH entry pointing at
#          that directory is added to the service's private environment so the
#          loader can resolve Packet.dll.
#        - Npcap absent: the executable CANNOT load at all (load-time DLL
#          import), so "limited mode" on Windows means: the service is left
#          registered with start type Manual and a clear notice is written to
#          the state directory. Re-run this script after installing Npcap to
#          switch the service to Automatic and start it. The in-process
#          Degraded mode (runtime.rs) only covers failures after the process
#          has loaded.
#   4. Applies restart-on-failure recovery settings via sc.exe (belt and
#      braces with the installer's ServiceConfig authoring).
#   5. Writes README-UNINSTALL.txt into the state directory explaining that
#      uninstall leaves collected data in place.
#
# NO FIREWALL RULE is created anywhere in this installer: the service binds
# 127.0.0.1:58120 only (loopback), which Windows Firewall does not filter.

[CmdletBinding()]
param(
    [string]$ServiceName = 'NeonHearth',
    [switch]$Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateDir = Join-Path $env:ProgramData 'NeonHearth'
$logPath = Join-Path $stateDir 'install-configure.log'
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

function Write-Log {
    param([string]$Message)
    $line = '{0:yyyy-MM-ddTHH:mm:ssK} {1}' -f (Get-Date), $Message
    Write-Host $line
    try { Add-Content -Path $logPath -Value $line } catch {}
}

if (-not (Test-Path $serviceKey)) {
    throw "Service '$ServiceName' is not registered; run the installer first."
}

# --- 1. State directory + ACL for the virtual service account -------------
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$account = "NT SERVICE\$ServiceName"
$acl = Get-Acl $stateDir
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $account, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -Path $stateDir -AclObject $acl
Write-Log "Granted Modify on $stateDir to $account"

# --- 2. Npcap detection ----------------------------------------------------
$npcapDir = Join-Path $env:SystemRoot 'System32\Npcap'
$compatDll = Join-Path $env:SystemRoot 'System32\Packet.dll'
$npcapCompat = Test-Path $compatDll
$npcapDirPresent = Test-Path (Join-Path $npcapDir 'Packet.dll')
$npcapUsable = $npcapCompat -or $npcapDirPresent
Write-Log "Npcap: WinPcap-compat Packet.dll=$npcapCompat, System32\Npcap\Packet.dll=$npcapDirPresent"

# --- 3. Service-private environment (token + optional Npcap PATH) ----------
$existing = @()
$existingProp = Get-ItemProperty -Path $serviceKey -Name 'Environment' -ErrorAction SilentlyContinue
if ($null -ne $existingProp) { $existing = @($existingProp.Environment) }

$entries = [System.Collections.Generic.List[string]]::new()
foreach ($e in $existing) { if ($e) { $entries.Add($e) } }

if (-not ($entries | Where-Object { $_ -like 'LATTICE_SERVICE_TOKEN=*' })) {
    $bytes = [byte[]]::new(48)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $token = [Convert]::ToBase64String($bytes)   # 64 chars, > 32-char minimum
    $entries.Add("LATTICE_SERVICE_TOKEN=$token")
    Write-Log 'Generated new LATTICE_SERVICE_TOKEN (stored only in the service Environment registry value).'
} else {
    Write-Log 'LATTICE_SERVICE_TOKEN already present; preserved.'
}

if ($npcapDirPresent -and -not $npcapCompat) {
    # The loader resolves the Packet.dll load-time import through the service's
    # PATH; System32\Npcap is not on the default search path.
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $pathEntry = "PATH=$npcapDir;$machinePath"
    $idx = -1
    for ($i = 0; $i -lt $entries.Count; $i++) { if ($entries[$i] -like 'PATH=*') { $idx = $i } }
    if ($idx -ge 0) { $entries[$idx] = $pathEntry } else { $entries.Add($pathEntry) }
    Write-Log "Service PATH prefixed with $npcapDir for Packet.dll resolution."
}

Set-ItemProperty -Path $serviceKey -Name 'Environment' `
    -Value ([string[]]$entries) -Type MultiString
Write-Log 'Service Environment registry value written.'

# --- 4. Recovery settings --------------------------------------------------
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null
Write-Log 'Recovery: restart after 5s/5s/30s, counter reset after 24h, apply on non-crash failures too.'

# --- 5. Start type: Automatic with Npcap, Manual (limited mode) without ----
if ($npcapUsable) {
    & sc.exe config $ServiceName start= auto | Out-Null
    Write-Log 'Npcap present: service start type set to Automatic.'
    if ($Start) {
        Start-Service -Name $ServiceName
        Write-Log 'Service started.'
    }
} else {
    & sc.exe config $ServiceName start= demand | Out-Null
    $notice = @"
NeonHearth is installed but Npcap was not found, so the collector service is
registered with start type Manual and has NOT been started. The service
executable links against Npcap's Packet.dll and cannot load without it.

To enable NeonHearth:
  1. Install Npcap from https://npcap.com/ (WinPcap-compatible mode is fine).
  2. Re-run (elevated):
     powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\configure-service.ps1" -Start
"@
    Set-Content -Path (Join-Path $stateDir 'NPCAP-REQUIRED.txt') -Value $notice
    Write-Log 'Npcap absent: limited mode - service left Manual/stopped; NPCAP-REQUIRED.txt written.'
}

# --- 6. Uninstall data note ------------------------------------------------
$uninstallNote = @"
This directory (%ProgramData%\NeonHearth) holds NeonHearth's collected state:
the SQLite database (lattice.db), backups, and logs.

Uninstalling NeonHearth stops and removes the service and deletes the program
files, but deliberately leaves this directory in place so your device history,
baseline cohort, and approvals survive a reinstall.

To remove all NeonHearth data after uninstalling, delete this folder.
"@
Set-Content -Path (Join-Path $stateDir 'README-UNINSTALL.txt') -Value $uninstallNote
Write-Log 'Configuration complete.'
