# NeonHearth service post-install configuration.
#
# Run elevated. Invoked by the installer after the service is registered, and
# safe to re-run manually (for example after installing Npcap later). Every
# step is idempotent: ACLs are rebuilt from scratch each run, the token is
# generated once and preserved thereafter.
#
# What this script does (and why it is a script, not installer authoring):
#   1. Creates %ProgramData%\NeonHearth with an EXPLICIT, non-inherited ACL:
#      SYSTEM and Administrators full control, the service's virtual account
#      (NT SERVICE\NeonHearth) modify, nobody else. ProgramData's inherited
#      default grants BUILTIN\Users read on everything below it, which would
#      expose lattice.db, backups and logs to every local account (audit H-2).
#   2. Generates the LATTICE_SERVICE_TOKEN pairing secret on first install and
#      stores it in the service-private Environment registry value. The service
#      binary refuses to start without it (see crates/lattice-service/src/main.rs)
#      and MSI authoring cannot generate per-machine random secrets.
#      The service registry key is then given the same explicit ACL as the
#      state directory (SYSTEM / Administrators / service account only).
#      Service keys inherit BUILTIN\Users read by default, which would let any
#      local account read the token that is the API's entire authorization
#      boundary (audit H-1). See docs/build/installers.md for the DPAPI
#      file-backed follow-up that needs a service-side change.
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
#   4. Detects a bundled ffmpeg.exe next to the service executable (opt-in
#      MSI component, see NeonHearth.wxs) and, when present, points the
#      service at it via NEONHEARTH_FFMPEG so camera media does not depend
#      on a guessed path (audit M-18).
#   5. Applies restart-on-failure recovery settings via sc.exe (belt and
#      braces with the installer's ServiceConfig authoring).
#   6. Writes README-UNINSTALL.txt into the state directory explaining that
#      uninstall leaves collected data in place.
#
# NO FIREWALL RULE is created anywhere in this installer: the service binds
# 127.0.0.1:58120 only (loopback), which Windows Firewall does not filter.
#
# STATUS / HONESTY: authored and parser-checked only. No Windows machine was
# available in the session that added the ACL hardening, so the registry-key
# Set-Acl path, the virtual-account SID resolution, and service start under
# the tightened key ACL are unproven until the next real install run.

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
# scripts\ sits directly under the install folder (NeonHearth.wxs SCRIPTSFOLDER).
$installDir = Split-Path -Parent $PSScriptRoot

function Write-Log {
    param([string]$Message)
    $line = '{0:yyyy-MM-ddTHH:mm:ssK} {1}' -f (Get-Date), $Message
    Write-Host $line
    try { Add-Content -Path $logPath -Value $line } catch {}
}

if (-not (Test-Path $serviceKey)) {
    throw "Service '$ServiceName' is not registered; run the installer first."
}

# Well-known principals by SID so the ACL is locale-independent. The service
# virtual account has no fixed SID; it resolves by name once the service is
# registered (checked above).
$sidSystem = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$sidAdmins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$serviceAccount = [System.Security.Principal.NTAccount]::new("NT SERVICE\$ServiceName")
$serviceSid = $serviceAccount.Translate([System.Security.Principal.SecurityIdentifier])

# --- 1. State directory with an explicit, non-inherited ACL (H-2) ----------
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$dirInherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$noProp = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow

$dirAcl = Get-Acl -Path $stateDir
# Cut inheritance and DROP the inherited rules (second arg $false) so the
# ProgramData default (BUILTIN\Users read) does not survive as explicit rules.
$dirAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($dirAcl.Access | Where-Object { -not $_.IsInherited })) {
    [void]$dirAcl.RemoveAccessRuleSpecific($rule)
}
$dirAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
    $sidSystem, 'FullControl', $dirInherit, $noProp, $allow))
$dirAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
    $sidAdmins, 'FullControl', $dirInherit, $noProp, $allow))
$dirAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
    $serviceSid, 'Modify', $dirInherit, $noProp, $allow))
Set-Acl -Path $stateDir -AclObject $dirAcl
Write-Log "State directory ACL set explicitly: SYSTEM/Administrators full, NT SERVICE\$ServiceName modify, inheritance off."

# --- 2. Npcap detection ----------------------------------------------------
$npcapDir = Join-Path $env:SystemRoot 'System32\Npcap'
$compatDll = Join-Path $env:SystemRoot 'System32\Packet.dll'
$npcapCompat = Test-Path $compatDll
$npcapDirPresent = Test-Path (Join-Path $npcapDir 'Packet.dll')
$npcapUsable = $npcapCompat -or $npcapDirPresent
Write-Log "Npcap: WinPcap-compat Packet.dll=$npcapCompat, System32\Npcap\Packet.dll=$npcapDirPresent"

# --- 3. Service-private environment (token, ffmpeg, optional Npcap PATH) ---
$existing = @()
$existingProp = Get-ItemProperty -Path $serviceKey -Name 'Environment' -ErrorAction SilentlyContinue
if ($null -ne $existingProp) { $existing = @($existingProp.Environment) }

$entries = [System.Collections.Generic.List[string]]::new()
foreach ($e in $existing) { if ($e) { $entries.Add($e) } }

function Set-EnvEntry {
    param([System.Collections.Generic.List[string]]$List, [string]$Name, [string]$Value)
    $idx = -1
    for ($i = 0; $i -lt $List.Count; $i++) { if ($List[$i] -like "$Name=*") { $idx = $i } }
    if ($idx -ge 0) { $List[$idx] = "$Name=$Value" } else { $List.Add("$Name=$Value") }
}

if (-not ($entries | Where-Object { $_ -like 'LATTICE_SERVICE_TOKEN=*' })) {
    $bytes = [byte[]]::new(48)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $token = [Convert]::ToBase64String($bytes)   # 64 chars, > 32-char minimum
    $entries.Add("LATTICE_SERVICE_TOKEN=$token")
    Write-Log 'Generated new LATTICE_SERVICE_TOKEN (stored only in the service Environment registry value).'
} else {
    Write-Log 'LATTICE_SERVICE_TOKEN already present; preserved.'
}

# Bundled ffmpeg (opt-in MSI component; flat in the install folder).
$ffmpegPath = Join-Path $installDir 'ffmpeg.exe'
if (Test-Path $ffmpegPath) {
    Set-EnvEntry -List $entries -Name 'NEONHEARTH_FFMPEG' -Value $ffmpegPath
    Write-Log "Bundled ffmpeg found; NEONHEARTH_FFMPEG=$ffmpegPath"
} else {
    Write-Log 'No bundled ffmpeg.exe in the install folder; camera media will use the service default lookup.'
}

if ($npcapDirPresent -and -not $npcapCompat) {
    # The loader resolves the Packet.dll load-time import through the service's
    # PATH; System32\Npcap is not on the default search path.
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    Set-EnvEntry -List $entries -Name 'PATH' -Value "$npcapDir;$machinePath"
    Write-Log "Service PATH prefixed with $npcapDir for Packet.dll resolution."
}

Set-ItemProperty -Path $serviceKey -Name 'Environment' `
    -Value ([string[]]$entries) -Type MultiString
Write-Log 'Service Environment registry value written.'

# --- 3b. Service registry key ACL (H-1) ------------------------------------
# The Environment value now holds the pairing token, so the key must not keep
# the default inherited BUILTIN\Users read. The Service Control Manager runs
# as SYSTEM and reads the key on its behalf; the service account itself only
# needs read so its own config queries keep working.
$keyInherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
$keyAcl = Get-Acl -Path $serviceKey
$keyAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($keyAcl.Access | Where-Object { -not $_.IsInherited })) {
    [void]$keyAcl.RemoveAccessRuleSpecific($rule)
}
$keyAcl.AddAccessRule([System.Security.AccessControl.RegistryAccessRule]::new(
    $sidSystem, 'FullControl', $keyInherit, $noProp, $allow))
$keyAcl.AddAccessRule([System.Security.AccessControl.RegistryAccessRule]::new(
    $sidAdmins, 'FullControl', $keyInherit, $noProp, $allow))
$keyAcl.AddAccessRule([System.Security.AccessControl.RegistryAccessRule]::new(
    $serviceSid, 'ReadKey', $keyInherit, $noProp, $allow))
Set-Acl -Path $serviceKey -AclObject $keyAcl
Write-Log "Service registry key ACL set explicitly: SYSTEM/Administrators full, NT SERVICE\$ServiceName read, inheritance off (BUILTIN\Users removed)."

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
