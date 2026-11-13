param([ValidateSet("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")][string]$Target = "x86_64-pc-windows-msvc")
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo
$arch = if ($Target -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
$bin = Join-Path $repo "target\$Target\debug"
$cli = Join-Path $bin "shirusu.exe"
$dll = Join-Path $bin "shirusu_agent_dll.dll"
Invoke-Native { cargo build -p shirusu-e2e --target $Target --bin shirusu-capture-drop-e2e } "capture abandonment helper ($arch)"
$dropHelper = Join-Path $bin "shirusu-capture-drop-e2e.exe"
$work = Join-Path $repo ("target\attach-rollback-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "MSVC compiler not found" }
$dev = Join-Path $vs "Common7\Tools\VsDevCmd.bat"
$source = Join-Path $repo "e2e\native\attach-rollback.cpp"
$exe = Join-Path $work "attach-rollback.exe"
$compile = "`"$dev`" -arch=$arch && cl /nologo /W4 /WX /O2 /GS- /Fe:`"$exe`" /Fo:`"$work\fixture.obj`" `"$source`" /link /ENTRY:entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib"
$buildScript = Join-Path $work "build.cmd"
@("@echo off", "call $compile") | Set-Content -Encoding ascii $buildScript
Invoke-Native { cmd /d /c $buildScript } "attach rollback fixture ($arch)"
$targetProcess = $null
$recorderProcess = $null
function Wait-Marker([string]$name) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path (Join-Path $work $name))) {
        if ($targetProcess.HasExited) { throw "attach target exited early: $($targetProcess.ExitCode)" }
        if ([DateTime]::UtcNow -ge $deadline) { throw "timed out waiting for $name" }
        Start-Sleep -Milliseconds 20
    }
}
try {
    $targetProcess = Start-Process -FilePath $exe -WorkingDirectory $work -PassThru
    Wait-Marker "ready"
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        # A directory cannot be opened as a Trace file. This fails after init.
        $failure = & $cli attach $targetProcess.Id --dll $dll --output $work 2>&1
        $exitCode = $LASTEXITCODE
        $failure | Set-Content (Join-Path $work "failure-$attempt.txt")
        if ($exitCode -ne 1 -or ($failure -join "
") -notmatch 'rollback: Confirmed') {
            throw "attach failure did not confirm rollback: $failure"
        }
        if ($targetProcess.HasExited) { throw "failed attach terminated the application" }
    }
    foreach ($mode in @("drop", "unwind")) {
        $discarded = Join-Path $work "abandoned-$mode.trace"
        Invoke-NativeWithTimeout -FilePath $dropHelper -ArgumentList @($dll, "$($targetProcess.Id)", $discarded, $mode)
        if ($targetProcess.HasExited) { throw "abandoned attach terminated the application" }
    }
    New-Item -ItemType File (Join-Path $work "check-rollback") | Out-Null
    Wait-Marker "rollback-checked"

    $trace = Join-Path $work "reattach.trace"
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $cli
    $start.WorkingDirectory = $work
    $start.UseShellExecute = $false
    foreach ($argument in @("attach", "$($targetProcess.Id)", "--dll", $dll, "--output", $trace)) {
        $start.ArgumentList.Add($argument)
    }
    $recorderProcess = [System.Diagnostics.Process]::Start($start)
    Wait-Marker "reattach.trace"
    New-Item -ItemType File (Join-Path $work "exercise") | Out-Null
    Wait-Marker "exercise-done"
    New-Item -ItemType File (Join-Path $work "stop") | Out-Null
    if (-not $recorderProcess.WaitForExit(30000)) { throw "reattach recorder did not finish" }
    if ($recorderProcess.ExitCode -notin @(0,2)) { throw "reattach failed: $($recorderProcess.ExitCode)" }
    if (-not $targetProcess.WaitForExit(10000) -or $targetProcess.ExitCode -ne 0) {
        throw "application result changed by failed attach"
    }
    $raw = & $cli inspect $trace --json
    if ($LASTEXITCODE -notin @(0,1)) { throw "reattach trace could not be inspected" }
    $summary = ($raw -join "
") | ConvertFrom-Json
    $api = @($summary.api_stats | Where-Object { $_.api -eq "kernel32!GetCurrentProcessId" })
    if ($api.Count -ne 1 -or $api[0].enter -lt 100 -or $api[0].leave -lt 100) {
        throw "reattach did not record the requested API exercise"
    }
    $coverageRaw = & $cli coverage $trace --json
    if ($LASTEXITCODE -notin @(0,1)) { throw "coverage ledger failed" }
    $coverage = ($coverageRaw -join [Environment]::NewLine) | ConvertFrom-Json
    $pidApi = @($coverage.apis | Where-Object { $_.api -eq "kernel32!GetCurrentProcessId" })
    if ($pidApi.Count -ne 1 -or $pidApi[0].enter -lt 100) { throw "coverage observation count missing" }
    $iat = @($pidApi[0].hook_evidence | Where-Object { $_.method -eq "iat" -and $_.reason -eq "noncanonical-import-preserved" })
    $inline = @($pidApi[0].hook_evidence | Where-Object { $_.method -eq "inline" })
    if ($iat.Count -ne 1 -or $inline.Count -ne 1 -or -not $inline[0].reason) { throw "native per-API hook evidence missing" }
    Write-Host "API coverage ledger passed ($arch)"
    Write-Host "Attach rollback, abandonment, unwind, IAT wrapper preservation and reattach passed ($arch)"
} finally {
    foreach ($process in @($recorderProcess, $targetProcess)) {
        if ($null -ne $process) {
            if (-not $process.HasExited) { $process.Kill($true); $null = $process.WaitForExit(10000) }
            $process.Dispose()
        }
    }
    if ($env:SHIRUSU_DIAGNOSTIC_DIR) {
        Get-ChildItem $work -File | Where-Object { $_.Extension -in @(".trace", ".txt") } |
            Copy-Item -Destination $env:SHIRUSU_DIAGNOSTIC_DIR
    }
}
