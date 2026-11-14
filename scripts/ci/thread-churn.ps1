param([ValidateSet("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")][string]$Target = "x86_64-pc-windows-msvc")
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$arch = if ($Target -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
$bin = Join-Path $repo "target\$Target\debug"
$cli = Join-Path $bin "shirusu.exe"
$dll = Join-Path $bin "shirusu_agent_dll.dll"
$work = Join-Path $repo ("target\thread-churn-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "MSVC compiler not found" }
$dev = Join-Path $vs "Common7\Tools\VsDevCmd.bat"
$source = Join-Path $repo "e2e\native\thread-churn.cpp"
$exe = Join-Path $work "thread-churn.exe"
$compile = "`"$dev`" -arch=$arch && cl /nologo /W4 /WX /O2 /GS- /Fe:`"$exe`" /Fo:`"$work\fixture.obj`" `"$source`" /link /ENTRY:entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib"
$buildScript = Join-Path $work "build.cmd"
@("@echo off", "call $compile") | Set-Content -Encoding ascii $buildScript
Invoke-Native { cmd /d /c $buildScript } "thread churn fixture ($arch)"
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
    $trace = Join-Path $work "churn.trace"
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $cli
    $start.WorkingDirectory = $work
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    foreach ($argument in @("attach", "$($targetProcess.Id)", "--dll", $dll, "--output", $trace)) {
        $start.ArgumentList.Add($argument)
    }
    $recorderProcess = [System.Diagnostics.Process]::Start($start)
    $recorderOutput = $recorderProcess.StandardOutput.ReadToEndAsync()
    Wait-Marker "churn.trace"
    # Keep creating threads after initialization as well as during patching.
    # V8: from here the target counts the threads it starts; a second of
    # churn starts far more threads than there are Slots, so every one is
    # recorded only if Slots are reclaimed.
    New-Item -ItemType File (Join-Path $work "count") | Out-Null
    Start-Sleep -Milliseconds 1000
    New-Item -ItemType File (Join-Path $work "stop") | Out-Null
    if (-not $recorderProcess.WaitForExit(30000)) { throw "churn recorder did not finish" }
    $recorderProcess.WaitForExit()
    $recorderText = $recorderOutput.GetAwaiter().GetResult()
    Write-Host $recorderText
    if ($recorderProcess.ExitCode -notin @(0,2)) { throw "churn capture failed: $($recorderProcess.ExitCode)" }
    if (-not $targetProcess.WaitForExit(10000) -or $targetProcess.ExitCode -ne 0) {
        throw "thread churn application failed under capture"
    }
    $raw = & $cli inspect $trace --json
    if ($LASTEXITCODE -notin @(0,1)) { throw "churn trace could not be inspected" }
    $summary = ($raw -join [Environment]::NewLine) | ConvertFrom-Json
    $api = @($summary.api_stats | Where-Object { $_.api -eq "kernel32!GetCurrentProcessId" })
    if ($api.Count -ne 1 -or $api[0].enter -lt 1 -or $api[0].leave -lt 1) {
        throw "thread churn capture did not observe GetCurrentProcessId"
    }
    # V8: each counted thread calls GetCurrentProcessId 32 times.
    $counted = [double](Get-Content (Join-Path $work "counted.txt") -Raw)
    $expected = 32 * $counted
    if ($counted -lt 16) { throw "thread churn counted only $counted threads while recording" }
    # A thread that starts while every Slot still awaits reclamation is not
    # recorded and is counted as Capture Coverage loss (`--rings`), so not
    # every counted thread has to be in the Trace. What must hold:
    #  - Slots are reclaimed: far more threads are recorded than there are
    #    Slots (32), which a never-reclaimed Slot would prevent;
    #  - nothing is lost silently: a shortfall comes with loss records or a
    #    slot/coverage missing-call count.
    $missingCalls = 0
    if ($recorderText -match 'slot/coverage missing calls: (\d+)') { $missingCalls = [double]$Matches[1] }
    $lossRecords = [double]$summary.integrity.total_loss_count
    $recorded = [Math]::Min([double]$api[0].enter, [double]$api[0].leave)
    $recordedThreads = [Math]::Floor($recorded / 32)
    if ($recordedThreads -lt 128) {
        throw "thread churn recorded only $recorded GetCurrentProcessId calls (~$recordedThreads threads of $counted): Slots are not reclaimed"
    }
    if ($recorded -lt $expected -and $missingCalls -eq 0 -and $lossRecords -eq 0) {
        throw "thread churn recorded $recorded of $expected GetCurrentProcessId calls with no loss record and no missing-call count (silent loss)"
    }
    if (($recorded + $missingCalls) -lt $expected -and $lossRecords -eq 0) {
        throw "thread churn: $recorded recorded + $missingCalls counted missing < $expected expected, with no loss record"
    }
    Write-Host ("Thread churn: {0} threads while recording, {1} calls recorded of {2} ({3:P1}), slot/coverage missing calls {4}, loss records {5}" -f $counted, $recorded, $expected, ($recorded / $expected), $missingCalls, $lossRecords)
    Write-Host "Thread creation during attach passed ($arch)"
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
