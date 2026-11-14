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
# Control variants (interim review 2026-11-14 P0). The same 48-round fixture
# runs under each, so a hang can be attributed:
#   no-hook     no Agent at all: does the application stall on its own?
#   pid-only    Capture Policy records only GetCurrentProcessId (every other
#               detour passes through without registering or allocating)
#   pid-heap    also records HeapAlloc (registration from the heap calls a
#               thread makes while it starts, inside Loader Lock)
#   full        every API (the original scenario)
#   writer-stall full, and a debug-Agent test point holds one spinner inside
#               the Writer's owner fast path until it is terminated there
$variants = @(
    @{ name = "no-hook"; capture = $null; stall = 0 },
    @{ name = "pid-only"; capture = @("--mode", "filtered", "--api", "kernel32!GetCurrentProcessId"); stall = 0 },
    @{ name = "pid-heap"; capture = @("--mode", "filtered", "--api", "kernel32!GetCurrentProcessId", "--api", "kernel32!HeapAlloc"); stall = 0 },
    @{ name = "full"; capture = @(); stall = 0 },
    @{ name = "writer-stall"; capture = @(); stall = 50000 }
)
$targetProcess = $null
$recorderProcess = $null
$variantDir = $null
# Diagnostics for a hang: whether the target and recorder are alive, every
# thread's state and CPU time, every thread's stack (noninvasive cdb attach,
# symbols from the debug build), and the recorder's own summary (Ring and Slot
# states, losses) after it is asked to stop.
function Write-HangDiagnostics {
    $targetAlive = $null -ne $targetProcess -and -not $targetProcess.HasExited
    $recorderAlive = $null -ne $recorderProcess -and -not $recorderProcess.HasExited
    Write-Host "diagnostics: target alive=$targetAlive recorder alive=$recorderAlive"
    if ($targetAlive) {
        $targetProcess.Refresh()
        foreach ($t in $targetProcess.Threads) {
            $reason = if ($t.ThreadState -eq "Wait") { $t.WaitReason } else { "" }
            Write-Host ("  thread {0}: {1} {2} cpu={3:N0}ms" -f $t.Id, $t.ThreadState, $reason, $t.TotalProcessorTime.TotalMilliseconds)
        }
        $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\$arch\cdb.exe"
        if (Test-Path $kits) {
            Write-Host "target stacks:"
            $out = Join-Path $variantDir "stacks.txt"
            $cdb = Start-Process -FilePath $kits -NoNewWindow -PassThru -RedirectStandardOutput $out `
                -ArgumentList @("-pv", "-p", "$($targetProcess.Id)", "-y", "`"$bin;$work`"", "-c", "`"~*kn 40;!runaway 7;qd`"")
            if (-not $cdb.WaitForExit(120000)) { $cdb.Kill(); Write-Host "cdb timed out" }
            if (Test-Path $out) { Get-Content $out | Write-Host }
        } else {
            Write-Host "target stacks: unavailable (no cdb)"
        }
    }
    if ($recorderAlive) {
        New-Item -ItemType File (Join-Path $variantDir "stop") -Force | Out-Null
        Write-Host "recorder summary after stop:"
        if (-not $recorderProcess.WaitForExit(30000)) { Write-Host "  recorder did not finish within 30s" }
    }
}
function Wait-Marker([string]$name) {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path (Join-Path $variantDir $name))) {
        if ($targetProcess.HasExited) {
            $crash = Join-Path $variantDir "crash.txt"
            if (Test-Path $crash) { Write-Host "target crash report:"; Get-Content $crash | Write-Host }
            throw "$($script:variant.name): target exited early: $($targetProcess.ExitCode)"
        }
        if ([DateTime]::UtcNow -ge $deadline) { Write-HangDiagnostics; throw "$($script:variant.name): timed out waiting for $name" }
        Start-Sleep -Milliseconds 20
    }
}
function Stop-Processes {
    foreach ($process in @($script:recorderProcess, $script:targetProcess)) {
        if ($null -ne $process) {
            if (-not $process.HasExited) { $process.Kill($true); $null = $process.WaitForExit(10000) }
            $process.Dispose()
        }
    }
    $script:recorderProcess = $null
    $script:targetProcess = $null
}
$summaries = @()
try {
    foreach ($variant in $variants) {
        $script:variant = $variant
        $variantDir = Join-Path $work $variant.name
        New-Item -ItemType Directory $variantDir | Out-Null
        $start = [System.Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $exe
        $start.WorkingDirectory = $variantDir
        $start.UseShellExecute = $false
        if ($variant.stall -gt 0) { $start.Environment["SHIRUSU_TEST_WRITER_STALL_AFTER"] = "$($variant.stall)" }
        $targetProcess = [System.Diagnostics.Process]::Start($start)
        Wait-Marker "ready"
        $trace = Join-Path $variantDir "terminate.trace"
        if ($null -ne $variant.capture) {
            $start = [System.Diagnostics.ProcessStartInfo]::new()
            $start.FileName = $cli
            $start.WorkingDirectory = $variantDir
            $start.UseShellExecute = $false
            foreach ($argument in (@("attach", "$($targetProcess.Id)", "--dll", $dll, "--output", $trace) + $variant.capture)) {
                $start.ArgumentList.Add($argument)
            }
            $recorderProcess = [System.Diagnostics.Process]::Start($start)
            Wait-Marker "terminate.trace"
        }
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        New-Item -ItemType File (Join-Path $variantDir "go") | Out-Null
        if ($variant.stall -gt 0) { Wait-Marker "stalled" }
        # Watchdog: before the fix a thread reusing a terminated writer's ID
        # waited for its ownership flag forever, so the rounds never finished.
        Wait-Marker "done"
        $roundsMs = $watch.Elapsed.TotalMilliseconds
        New-Item -ItemType File (Join-Path $variantDir "stop") | Out-Null
        if ($null -ne $recorderProcess) {
            if (-not $recorderProcess.WaitForExit(30000)) { throw "$($variant.name): recorder did not finish after terminated writers" }
            if ($recorderProcess.ExitCode -notin @(0,2)) { throw "$($variant.name): capture with terminated writers failed: $($recorderProcess.ExitCode)" }
        }
        if (-not $targetProcess.WaitForExit(10000) -or $targetProcess.ExitCode -ne 0) {
            throw "$($variant.name): terminate writer application failed: $($targetProcess.ExitCode)"
        }
        if ($null -eq $variant.capture) {
            Write-Host ("Terminated writers {0} ({1}): rounds {2:N0}ms" -f $variant.name, $arch, $roundsMs)
            $summaries += "$($variant.name)=$([int]$roundsMs)ms"
            Stop-Processes
            continue
        }
        $raw = & $cli inspect $trace --json
        $inspectExit = $LASTEXITCODE
        if ($inspectExit -notin @(0,1)) { throw "$($variant.name): trace could not be inspected" }
        $summary = ($raw -join [Environment]::NewLine) | ConvertFrom-Json
        $api = @($summary.api_stats | Where-Object { $_.api -eq "kernel32!GetCurrentProcessId" })
        if ($api.Count -ne 1 -or $api[0].enter -lt 1 -or $api[0].leave -lt 1) {
            throw "$($variant.name): capture did not observe GetCurrentProcessId around terminated writers"
        }
        # V8: the threads started after each termination round must all be
        # recorded (48 rounds x 8 threads x 32 calls in terminate-writer.cpp).
        # A Slot left owned by a terminated writer would leave them unrecorded.
        $expected = 48 * 8 * 32
        if ($api[0].enter -lt $expected -or $api[0].leave -lt $expected) {
            throw "$($variant.name): recorded $($api[0].enter) enters / $($api[0].leave) leaves, at least $expected expected from the threads started after terminations"
        }
        if ($variant.name -like "pid-*") {
            $others = @($summary.api_stats | Where-Object { $_.api -ne "kernel32!GetCurrentProcessId" -and $_.api -ne "kernel32!HeapAlloc" -and $_.enter -gt 0 })
            if ($variant.name -eq "pid-only") { $others += @($summary.api_stats | Where-Object { $_.api -eq "kernel32!HeapAlloc" -and $_.enter -gt 0 }) }
            if ($others.Count -gt 0) { throw "$($variant.name): APIs outside the Capture Policy were recorded: $(($others | ForEach-Object { $_.api }) -join ', ')" }
        }
        # An event cut off inside a terminated writer is counted as lost, so the
        # Trace must not claim completeness while losses are recorded.
        $status = $summary.integrity.status
        if ($summary.integrity.total_loss_count -gt 0 -and $status -eq "complete") {
            throw "$($variant.name): trace with losses was finalized as complete"
        }
        # The fixed kill point cuts a writer off before its event is written:
        # the Ring is isolated and the cut-off event counted as lost.
        if ($variant.stall -gt 0 -and $summary.integrity.total_loss_count -lt 1) {
            throw "$($variant.name): the writer terminated at the test point left no loss record"
        }
        $lossKinds = @($summary.integrity.loss_records | ForEach-Object { "$($_.kind):$($_.records)" }) -join ","
        Write-Host ("Terminated writers {0} ({1}): rounds {2:N0}ms events={3} integrity={4} losses={5} kinds=[{6}] GetCurrentProcessId={7}/{8}" -f $variant.name, $arch, $roundsMs, $summary.events, $status, $summary.integrity.total_loss_count, $lossKinds, $api[0].enter, $api[0].leave)
        $summaries += "$($variant.name)=$([int]$roundsMs)ms"
        Stop-Processes
    }
    Write-Host "Terminated writers passed ($arch): $($summaries -join ' ')"
} finally {
    Stop-Processes
    if ($env:SHIRUSU_DIAGNOSTIC_DIR) {
        Get-ChildItem $work -File -Recurse | Where-Object { $_.Extension -in @(".trace", ".txt") } |
            ForEach-Object { Copy-Item $_.FullName -Destination (Join-Path $env:SHIRUSU_DIAGNOSTIC_DIR ("terminate-" + $_.Directory.Name + "-" + $_.Name)) }
    }
}
