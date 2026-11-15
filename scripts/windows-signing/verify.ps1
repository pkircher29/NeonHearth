# Fails unless every given file carries a valid, timestamped signature from
# the expected publisher. Wildcards are allowed.
param(
    [Parameter(Mandatory)][string]$Publisher,
    [Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Path
)

$ErrorActionPreference = 'Stop'

$files = @(Get-Item -Path $Path)
if ($files.Count -eq 0) { throw "No files matched: $Path" }

$failed = $false
foreach ($file in $files) {
    $signature = Get-AuthenticodeSignature -FilePath $file.FullName
    $subject = $signature.SignerCertificate.Subject
    $problem = $null
    if ($signature.Status -ne 'Valid') {
        $problem = "status is $($signature.Status): $($signature.StatusMessage)"
    } elseif ($subject -notmatch "(^|,\s*)CN=$([regex]::Escape($Publisher))(,|$)") {
        $problem = "signed by an unexpected publisher: $subject"
    } elseif (-not $signature.TimeStamperCertificate) {
        $problem = 'signature has no timestamp'
    }
    if ($problem) {
        Write-Host "::error::$($file.Name): $problem"
        $failed = $true
    } else {
        Write-Host "OK  $($file.Name)  [$subject]"
    }
}
if ($failed) { exit 1 }
# Explicit, so callers that test $LASTEXITCODE never read a stale or empty value.
exit 0
