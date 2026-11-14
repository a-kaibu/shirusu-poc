param([ValidateSet("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")][string]$Target = "x86_64-pc-windows-msvc")
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$arch = if ($Target -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
$bin = Join-Path $repo "target\$Target\debug"
$cli = Join-Path $bin "shirusu.exe"
$dll = Join-Path $bin "shirusu_agent_dll.dll"
$work = Join-Path $repo ("target\terminate-writer-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "MSVC compiler not found" }
$dev = Join-Path $vs "Common7\Tools\VsDevCmd.bat"
$source = Join-Path $repo "e2e\native\terminate-writer.cpp"
$exe = Join-Path $work "terminate-writer.exe"
$compile = "`"$dev`" -arch=$arch && cl /nologo /W4 /WX /O2 /GS- /Fe:`"$exe`" /Fo:`"$work\fixture.obj`" `"$source`" /link /ENTRY:entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib dbghelp.lib"
$buildScript = Join-Path $work "build.cmd"
@("@echo off", "call $compile") | Set-Content -Encoding ascii $buildScript
Invoke-Native { cmd /d /c $buildScript } "terminate writer fixture ($arch)"
$targetProcess = $null
$recorderProcess = $null
# Diagnostics for a hang: every thread's stack of the live target, read by a
# noninvasive cdb attach (symbols from the debug build next to the DLL).
function Write-TargetStacks {
    $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\$arch\cdb.exe"
    if (-not (Test-Path $kits) -or $null -eq $targetProcess -or $targetProcess.HasExited) {
        Write-Host "target stacks: unavailable (cdb: $(Test-Path $kits))"
        return
    }
    Write-Host "target stacks:"
    $out = Join-Path $work "stacks.txt"
    $cdb = Start-Process -FilePath $kits -NoNewWindow -PassThru -RedirectStandardOutput $out `
        -ArgumentList @("-pv", "-p", "$($targetProcess.Id)", "-y", "`"$bin;$work`"", "-c", "`"~*kn 40;qd`"")
    if (-not $cdb.WaitForExit(120000)) { $cdb.Kill(); Write-Host "cdb timed out" }
    if (Test-Path $out) { Get-Content $out | Write-Host }
}
function Wait-Marker([string]$name) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path (Join-Path $work $name))) {
        if ($targetProcess.HasExited) {
            $crash = Join-Path $work "crash.txt"
            if (Test-Path $crash) { Write-Host "target crash report:"; Get-Content $crash | Write-Host }
            throw "attach target exited early: $($targetProcess.ExitCode)"
        }
        if ([DateTime]::UtcNow -ge $deadline) { Write-TargetStacks; throw "timed out waiting for $name" }
        Start-Sleep -Milliseconds 20
    }
}
try {
    $targetProcess = Start-Process -FilePath $exe -WorkingDirectory $work -PassThru
    Wait-Marker "ready"
    $trace = Join-Path $work "terminate.trace"
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $cli
    $start.WorkingDirectory = $work
    $start.UseShellExecute = $false
    foreach ($argument in @("attach", "$($targetProcess.Id)", "--dll", $dll, "--output", $trace)) {
        $start.ArgumentList.Add($argument)
    }
    $recorderProcess = [System.Diagnostics.Process]::Start($start)
    Wait-Marker "terminate.trace"
    New-Item -ItemType File (Join-Path $work "go") | Out-Null
    # Watchdog: before the fix a thread reusing a terminated writer's ID
    # waited for its ownership flag forever, so the rounds never finished.
    Wait-Marker "done"
    New-Item -ItemType File (Join-Path $work "stop") | Out-Null
    if (-not $recorderProcess.WaitForExit(30000)) { throw "recorder did not finish after terminated writers" }
    if ($recorderProcess.ExitCode -notin @(0,2)) { throw "capture with terminated writers failed: $($recorderProcess.ExitCode)" }
    if (-not $targetProcess.WaitForExit(10000) -or $targetProcess.ExitCode -ne 0) {
        throw "terminate writer application failed under capture: $($targetProcess.ExitCode)"
    }
    $raw = & $cli inspect $trace --json
    $inspectExit = $LASTEXITCODE
    if ($inspectExit -notin @(0,1)) { throw "terminate writer trace could not be inspected" }
    $summary = ($raw -join [Environment]::NewLine) | ConvertFrom-Json
    $api = @($summary.api_stats | Where-Object { $_.api -eq "kernel32!GetCurrentProcessId" })
    if ($api.Count -ne 1 -or $api[0].enter -lt 1 -or $api[0].leave -lt 1) {
        throw "capture did not observe GetCurrentProcessId around terminated writers"
    }
    # An event cut off inside a terminated writer is counted as lost, so the
    # Trace must not claim completeness while losses are recorded.
    $status = $summary.integrity.status
    if ($summary.integrity.total_loss_count -gt 0 -and $status -eq "complete") {
        throw "trace with losses was finalized as complete"
    }
    $lossKinds = @($summary.integrity.loss_records | ForEach-Object { "$($_.kind):$($_.records)" }) -join ","
    Write-Host ("Terminated writers passed ({0}): events={1} integrity={2} losses={3} kinds=[{4}] GetCurrentProcessId={5}/{6}" -f $arch, $summary.events, $status, $summary.integrity.total_loss_count, $lossKinds, $api[0].enter, $api[0].leave)
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
