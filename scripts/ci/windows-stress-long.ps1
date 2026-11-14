# Weekly Windows long stress (review 2026-11-14 V14). The weekly
# stress-long.sh only exercises the Linux transport; the longest Windows
# recording in CI was 30 s, so problems that grow with recording time (the
# index, loss records, open calls, Host memory) had nowhere to show up. This
# injects the real Agent and records for 10 minutes per run through
# sustained-load.ps1 -Length long, which reads every trace back and applies
# the same silent-loss, accounting and memory-growth gates as CI.
param(
    [ValidateSet("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")][string]$Target = "x86_64-pc-windows-msvc"
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
Set-Location (Join-Path $PSScriptRoot "..\..")
# The job allows 150 minutes; stop with time left for dumps and the upload.
Start-CiDeadline -Seconds 8400
$env:SHIRUSU_DIAGNOSTIC_DIR = Join-Path (Get-Location) "target\ci-diagnostics"
New-Item -ItemType Directory -Force -Path $env:SHIRUSU_DIAGNOSTIC_DIR | Out-Null
if ($Target -eq "i686-pc-windows-msvc") {
    Invoke-NativeWithTimeout -What "rustup target add i686" -TimeoutSeconds 300 -FilePath rustup -ArgumentList @("target", "add", "i686-pc-windows-msvc")
}
Invoke-NativeWithTimeout -What "sustained load, long run ($Target)" -TimeoutSeconds 8400 -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "sustained-load.ps1"), "-Target", $Target, "-Length", "long")
