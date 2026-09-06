$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$group = 'NeonHearth managed application rules'
if ($request.operation -eq 'list') {
    $rules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Group -eq $group} | ForEach-Object {
        $filter = $_ | Get-NetFirewallApplicationFilter
        [pscustomobject]@{name=$_.Name;direction=[string]$_.Direction;enabled=[string]$_.Enabled;action=[string]$_.Action;program=$filter.Program}
    })
    ConvertTo-Json -Depth 4 -Compress -InputObject $rules
    exit 0
}
if ($request.app_id -notmatch '^[a-f0-9]{64}$' -or $request.direction -notin @('inbound','outbound') -or $request.operation -notin @('block','release')) { throw 'Invalid request' }
$name = 'NeonHearth-App-' + $request.app_id + '-' + $request.direction
$direction = if ($request.direction -eq 'inbound') {'Inbound'} else {'Outbound'}
$program = [string]$request.executable
if (-not [IO.Path]::IsPathRooted($program) -or $program.IndexOfAny([char[]]'*?') -ge 0) { throw 'Invalid program' }
$existing = Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Name -eq $name}
if ($existing) {
    $filter = $existing | Get-NetFirewallApplicationFilter
    if ($existing.Group -ne $group -or $existing.Direction -ne $direction -or -not [string]::Equals($filter.Program,$program,[StringComparison]::OrdinalIgnoreCase)) {throw 'Existing rule does not match this application'}
}
$currentlyBlocked = [bool]($existing -and $existing.Enabled -eq 'True' -and $existing.Action -eq 'Block')
if ($currentlyBlocked -ne [bool]$request.expected_blocked) {throw 'The firewall rule changed; refresh and review it'}
if ($request.operation -eq 'block') {
    if (-not (Test-Path -LiteralPath $program -PathType Leaf)) {throw 'Program no longer exists'}
    if ($existing) { $existing | Set-NetFirewallRule -Action Block -Enabled True | Out-Null }
    else { New-NetFirewallRule -Name $name -DisplayName ('NeonHearth: ' + [IO.Path]::GetFileName($program) + ' ' + $direction) -Group $group -Direction $direction -Program $program -Action Block -Enabled True -Profile Any | Out-Null }
} elseif ($existing) {
    # Release only this exact, ownership-checked rule. Other firewall rules stay in force.
    $existing | Remove-NetFirewallRule
}
$after = Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Name -eq $name}
$blocked = [bool]($after -and $after.Enabled -eq 'True' -and $after.Action -eq 'Block')
if ($blocked -ne ($request.operation -eq 'block')) {throw 'Windows did not confirm the requested rule state'}
if ($blocked) {
    $filter = $after | Get-NetFirewallApplicationFilter
    if (-not [string]::Equals($filter.Program,$program,[StringComparison]::OrdinalIgnoreCase)) {throw 'Rule target verification failed'}
}
$profilesEnabled = @((Get-NetFirewallProfile).Enabled | Where-Object {$_ -ne 'True'}).Count -eq 0
[pscustomobject]@{blocked=$blocked;rule_verified=$true;all_profiles_enabled=$profilesEnabled} | ConvertTo-Json -Compress
