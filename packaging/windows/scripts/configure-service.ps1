# NeonHearth service post-install configuration.
#
# Run elevated. Invoked by the installer after the service is registered, and
# safe to re-run manually. Every
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
#   3. Uses native Windows discovery; no packet-capture driver is needed.
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
    try { Add-Content -LiteralPath $logPath -Value $line } catch {}
}

if (-not (Test-Path -LiteralPath $serviceKey)) {
    throw "Service '$ServiceName' is not registered; run the installer first."
}

# Well-known principals by SID so the ACL is locale-independent. The service
# virtual account has no fixed SID; it resolves by name once the service is
# registered (checked above).
$sidSystem = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$sidAdmins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$serviceAccount = [System.Security.Principal.NTAccount]::new("NT SERVICE\$ServiceName")
$serviceSid = $serviceAccount.Translate([System.Security.Principal.SecurityIdentifier])

# --- 1. State directory, created with its final protected descriptor ------
# %ProgramData% lets ANY standard user create subfolders, and this script runs
# as SYSTEM. A pre-created C:\ProgramData\NeonHearth could therefore be (a) a
# junction, making Set-Acl rewrite some other directory, or (b) owned by the
# user, who would keep implicit WRITE_DAC over the "protected" state. So:
#   - a reparse point is refused outright;
#   - a directory not owned by SYSTEM / Administrators is moved aside (data is
#     preserved, never read or reused) and a fresh one is created;
#   - the new directory is created already carrying the final protected DACL.
$dirInherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$noProp = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$trustedOwners = @($sidSystem.Value, $sidAdmins.Value)

function New-StateSecurity {
    $sec = [System.Security.AccessControl.DirectorySecurity]::new()
    $sec.SetAccessRuleProtection($true, $false)
    foreach ($pair in @(@($sidSystem, 'FullControl'), @($sidAdmins, 'FullControl'), @($serviceSid, 'Modify'))) {
        $sec.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $pair[0], $pair[1], $dirInherit, $noProp, $allow))
    }
    return $sec
}
function Get-OwnerSid([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    return $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
}

if (Test-Path -LiteralPath $stateDir) {
    $item = Get-Item -LiteralPath $stateDir -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Refusing to use ${stateDir}: it is a junction or symbolic link. Remove it (not its target) and run the installer again."
    }
    if (-not $item.PSIsContainer) {
        throw "Refusing to use ${stateDir}: it is a file."
    }
    if ($trustedOwners -notcontains (Get-OwnerSid $stateDir)) {
        $aside = "$stateDir.untrusted-" + [guid]::NewGuid().ToString('N')
        Move-Item -LiteralPath $stateDir -Destination $aside -ErrorAction Stop
        Write-Host "Existing $stateDir was not owned by SYSTEM or Administrators; moved to $aside and NOT used."
    }
}
if (-not (Test-Path -LiteralPath $stateDir)) {
    $creationSecurity = New-StateSecurity
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [void][System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($stateDir), $creationSecurity)
    } else {
        [void][System.IO.Directory]::CreateDirectory($stateDir, $creationSecurity)
    }
}
# Re-apply (idempotent repair of a hand-edited trusted directory) and make the
# owner explicit: Administrators, never a standard user.
$dirAcl = New-StateSecurity
$dirAcl.SetOwner($sidAdmins)
Set-Acl -LiteralPath $stateDir -AclObject $dirAcl
if ($trustedOwners -notcontains (Get-OwnerSid $stateDir)) {
    throw "State directory owner is not SYSTEM or Administrators after hardening."
}
Write-Log "State directory ACL set explicitly: SYSTEM/Administrators full, NT SERVICE\$ServiceName modify, inheritance off, owner verified."

# --- 2. Service registry key ACL FIRST, then the service-private environment -
# The key inherits BUILTIN\Users read by default (audit H-1), so the ACL is
# applied and verified BEFORE any token is written, and a failure removes the
# Environment value again (fail closed: the service refuses to start without a
# token, and re-running this script generates one).
$keyInherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
$keyAcl = Get-Acl -LiteralPath $serviceKey
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
Set-Acl -LiteralPath $serviceKey -AclObject $keyAcl
$permitted = @($sidSystem.Value, $sidAdmins.Value, $serviceSid.Value)
$applied = Get-Acl -LiteralPath $serviceKey
$stray = @($applied.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    ($permitted -notcontains $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
})
if ($stray.Count -gt 0 -or -not $applied.AreAccessRulesProtected) {
    throw "Service registry key ACL verification failed; the token was not written."
}
Write-Log "Service registry key ACL set and verified: SYSTEM/Administrators full, NT SERVICE\$ServiceName read, inheritance off (BUILTIN\Users removed)."

# Token generations: earlier installers wrote the token BEFORE tightening the
# key ACL, so a token created by them may have been readable by local users
# for a moment. Generation 2 = written only after hardening. A token without
# generation 2 is rotated exactly once (a restart is forced below). Pairing is
# re-established by the Start-menu shortcut, which always reads the current
# value; only an already-open dashboard tab needs to be reopened.
$generationKey = 'HKLM:\SOFTWARE\NeonHearth'
$generation = 0
try {
    $generation = [int](Get-ItemProperty -LiteralPath $generationKey -Name 'TokenGeneration' -ErrorAction Stop).TokenGeneration
} catch { $generation = 0 }

$existing = @()
$existingProp = Get-ItemProperty -LiteralPath $serviceKey -Name 'Environment' -ErrorAction SilentlyContinue
if ($null -ne $existingProp) { $existing = @($existingProp.Environment) }

$entries = [System.Collections.Generic.List[string]]::new()
foreach ($e in $existing) { if ($e) { $entries.Add($e) } }

function Set-EnvEntry {
    param([System.Collections.Generic.List[string]]$List, [string]$Name, [string]$Value)
    $idx = -1
    for ($i = 0; $i -lt $List.Count; $i++) { if ($List[$i] -like "$Name=*") { $idx = $i } }
    if ($idx -ge 0) { $List[$idx] = "$Name=$Value" } else { $List.Add("$Name=$Value") }
}

$tokenRotated = $false
$hasToken = [bool]($entries | Where-Object { $_ -like 'LATTICE_SERVICE_TOKEN=*' })
if ($hasToken -and $generation -lt 2) {
    $kept = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $entries) { if ($e -notlike 'LATTICE_SERVICE_TOKEN=*') { $kept.Add($e) } }
    $entries = $kept
    $hasToken = $false
    $tokenRotated = $true
    Write-Log 'Rotating the pairing token once: it predates the hardened install order.'
}
if (-not $hasToken) {
    # Windows PowerShell 5.1 (.NET Framework) has no static RandomNumberGenerator.Fill().
    $bytes = New-Object byte[] 48
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    # URL-safe alphabet: AppState::new (state.rs) only accepts [A-Za-z0-9._-].
    # 48 bytes -> exactly 64 chars, no '=' padding.
    $token = [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_')
    $entries.Add("LATTICE_SERVICE_TOKEN=$token")
    Write-Log 'Generated new LATTICE_SERVICE_TOKEN (stored only in the service Environment registry value).'
} else {
    Write-Log 'LATTICE_SERVICE_TOKEN already present; preserved.'
}

# Bundled ffmpeg (opt-in MSI component; flat in the install folder).
$ffmpegPath = Join-Path $installDir 'ffmpeg.exe'
if (Test-Path -LiteralPath $ffmpegPath) {
    Set-EnvEntry -List $entries -Name 'NEONHEARTH_FFMPEG' -Value $ffmpegPath
    Write-Log "Bundled ffmpeg found; NEONHEARTH_FFMPEG=$ffmpegPath"
} else {
    Write-Log 'No bundled ffmpeg.exe in the install folder; camera media will use the service default lookup.'
}
# The service hosts the installed UI bundle when LATTICE_UI_DIR points at it.
# Derived from $PSScriptRoot so custom install locations keep working.
$uiDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'ui'
Set-EnvEntry -List $entries -Name 'LATTICE_UI_DIR' -Value $uiDir
Write-Log "Service will serve the dashboard UI from $uiDir on http://127.0.0.1:58120/."

try {
    Set-ItemProperty -LiteralPath $serviceKey -Name 'Environment' `
        -Value ([string[]]$entries) -Type MultiString
    # Read back: the ACL must still be the hardened one when the secret lands.
    $after = Get-Acl -LiteralPath $serviceKey
    if (-not $after.AreAccessRulesProtected) { throw 'Service key ACL is no longer protected.' }
    New-Item -Path $generationKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $generationKey -Name 'TokenGeneration' -Value 2 -Type DWord
} catch {
    # Fail closed: never leave a token behind a key we could not verify.
    Remove-ItemProperty -LiteralPath $serviceKey -Name 'Environment' -ErrorAction SilentlyContinue
    throw
}
Write-Log 'Service Environment registry value written.'

# --- 4. Recovery settings --------------------------------------------------
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null
Write-Log 'Recovery: restart after 5s/5s/30s, counter reset after 24h, apply on non-crash failures too.'

# --- 5. Start the native collector without a packet driver ----------------
& sc.exe config $ServiceName start= auto | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not configure service startup" }
Write-Log 'Native Windows collector configured for Automatic startup; no Npcap required.'
$obsoleteNotice = Join-Path $stateDir 'NPCAP-REQUIRED.txt'
if (Test-Path -LiteralPath $obsoleteNotice) { Remove-Item -LiteralPath $obsoleteNotice }
if ($Start) {
    $svc = Get-Service -Name $ServiceName
    if ($tokenRotated -and $svc.Status -ne 'Stopped') {
        # The running service still holds the old token in memory.
        Restart-Service -Name $ServiceName -Force
        Write-Log 'Service restarted to load the rotated pairing token. Reopen NeonHearth from the Start menu.'
    } elseif ($svc.Status -eq 'Stopped') {
        Start-Service -Name $ServiceName
        Write-Log 'Service started.'
    } else {
        Write-Log 'Service already running.'
    }
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
Set-Content -LiteralPath (Join-Path $stateDir 'README-UNINSTALL.txt') -Value $uninstallNote

# --- 7. Open through the protected pairing shortcut ------------------------
# WiX QuietExec can copy custom-action stdout into the Windows Installer log.
# Never print the owner token or a paired URL here. The Start-menu shortcut
# reads the protected registry value on demand and opens the paired dashboard.
Write-Log 'Use the NeonHearth Start-menu shortcut to open the paired dashboard.'
Write-Log 'Configuration complete.'
