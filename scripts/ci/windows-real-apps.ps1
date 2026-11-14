# Windows CI job: record applications that ship with Windows (real-apps.ps1)
# on x64 and, through WOW64, on x86. Runs on its own runner so the main
# Windows suites keep their time budget.
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
Set-Location (Join-Path $PSScriptRoot "..\..")
Start-CiDeadline -Seconds 2520
$diagnostics = Join-Path (Get-Location) "target\ci-diagnostics"
New-Item -ItemType Directory -Force -Path $diagnostics | Out-Null
$env:SHIRUSU_DIAGNOSTIC_DIR = $diagnostics
$failures = [System.Collections.Generic.List[string]]::new()
Invoke-NativeWithTimeout -What "build cli, agent dll and compare (x64)" -TimeoutSeconds 1200 -FilePath cargo -ArgumentList @("build", "-p", "shirusu-cli", "-p", "shirusu-agent-dll", "-p", "shirusu-compare", "--target", "x86_64-pc-windows-msvc")
try { Invoke-Native { pwsh -NoProfile -File (Join-Path $PSScriptRoot "real-apps.ps1") -Target x86_64-pc-windows-msvc } "real applications (x64)" }
catch { $failures.Add("$_") }
Invoke-NativeWithTimeout -What "build cli and agent dll (i686)" -TimeoutSeconds 1200 -FilePath cargo -ArgumentList @("build", "-p", "shirusu-cli", "-p", "shirusu-agent-dll", "--target", "i686-pc-windows-msvc")
try { Invoke-Native { pwsh -NoProfile -File (Join-Path $PSScriptRoot "real-apps.ps1") -Target i686-pc-windows-msvc } "real applications (x86)" }
catch { $failures.Add("$_") }
if ($failures.Count -gt 0) { throw ("real application suites failed:`n" + ($failures -join "`n")) }
