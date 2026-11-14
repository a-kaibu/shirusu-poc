# Sustained high-frequency capture (review P1). The native high-load
# benchmark is a finite burst: the Host may keep converting after the target
# exits, so "no loss" there says nothing about continuous recording. This runs
# the same calls for 10-30 s, paced and unpaced, and reports per run:
#   - application throughput per second (does capture slow it down over time?)
#   - events captured and the Host's received/converted rate
#   - loss rate (dropped / produced) and the integrity verdict
#   - Host queue peak, queue-full waits, and the backlog left at target exit
#     (Host wall time after the application's own measured interval)
# A measurement, not a gate: failures to run or observe the workload and a
# Trace with losses finalized as complete are fatal; loss itself is reported.
#
# Review 2026-11-14 gates:
#   V1: fewer events than the workload produced, with no loss record, fails.
#   V2: every Trace is read back with `shirusu inspect` before it is deleted;
#       it must finalize cleanly, without recovery issues, with the captured
#       event count.
#   V3: Host and target peak memory are recorded; the Host's peak private
#       memory must not grow with the recording length (10 s vs 30 s).
#   V4: each capture has its own deadline, dumps the Host when it hangs, and
#       the report is rewritten after every run so a later hang keeps it.
#   V5: one run records four threads at once (several Rings).
#   V7: the backlog is the Host's time after it saw the target exit.
# Interim review P1 (event accounting): the workload counts each API call
# itself as it returns (measurement.json "calls"). Each counted API's enter
# events in the Trace are compared with that count, and every difference is
# classified: lost (covered by loss records), not hooked (no event for an
# API the workload called), or extra (calls outside the loop, from the CRT
# or startup; allowed only for APIs the runtime also calls).
param(
    [ValidateSet("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")][string]$Target = "x86_64-pc-windows-msvc"
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo
$arch = if ($Target -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
Invoke-Native { cargo build -p shirusu-cli -p shirusu-agent-dll --release --target $Target } "sustained load release binaries"
$bin = Join-Path $repo "target\$Target\release"
$cli = Join-Path $bin "shirusu.exe"
$dll = Join-Path $bin "shirusu_agent_dll.dll"
$work = Join-Path $repo ("target\sustained-load-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "MSVC compiler not found" }
$dev = Join-Path $vs "Common7\Tools\VsDevCmd.bat"
$source = Join-Path $repo "e2e\native\sustained-load.cpp"
$exe = Join-Path $work "sustained-load.exe"
$compile = "`"$dev`" -arch=$arch && cl /nologo /W4 /WX /O2 /Fe:`"$exe`" /Fo:`"$work\fixture.obj`" `"$source`" /link kernel32.lib"
$buildScript = Join-Path $work "build.cmd"
@("@echo off", "call $compile") | Set-Content -Encoding ascii $buildScript
Invoke-Native { cmd /d /c $buildScript } "sustained load fixture ($arch)"

function Get-ConfigValue([string]$config, [string]$key) {
    if ($config -match "(?:^|; )$key=(\d+)") { return [double]$Matches[1] }
    return $null
}
# (seconds, rate): paced runs at two rates and two durations, one unpaced run
# with an uncaptured baseline for the throughput ratio.
$runs = @(
    @{ seconds = 10; rate = "50000"; threads = 1 },
    @{ seconds = 30; rate = "50000"; threads = 1 },
    @{ seconds = 10; rate = "200000"; threads = 1 },
    @{ seconds = 10; rate = "200000"; threads = 4 },
    @{ seconds = 10; rate = "max"; threads = 1 }
)
$results = @()
$complete = $false
$diagnostics = if ($env:SHIRUSU_DIAGNOSTIC_DIR) { $env:SHIRUSU_DIAGNOSTIC_DIR } else { Join-Path $work "diagnostics" }
$reportPath = Join-Path $work "sustained-load-$arch.json"
function Write-Report([bool]$done) {
    $report = [ordered]@{
        benchmark = "native-sustained-load"; target = $Target; measurement_complete = $done
        os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        commit = (git rev-parse HEAD); agent_configuration = "release, full, default ring sizes"
        scope = "GetCurrentProcessId + HeapAlloc + HeapFree in a loop for a fixed duration, paced (sleeping when ahead) or unpaced, on one or more threads. Expected counts the loop and its Sleep calls; startup/shutdown add a few hundred events."
        results = $script:results
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content $reportPath
    if ($env:SHIRUSU_DIAGNOSTIC_DIR) { Copy-Item $reportPath $env:SHIRUSU_DIAGNOSTIC_DIR -Force }
}
function Get-SummaryNumber([string]$text, [string]$pattern) {
    if ($text -match $pattern) { return [double]$Matches[1] }
    return $null
}
try {
    foreach ($run in $runs) {
        $name = "$($run.seconds)s-$($run.rate)-t$($run.threads)"
        $modes = if ($run.rate -eq "max") { @("baseline", "capture") } else { @("capture") }
        $baselineRate = $null
        foreach ($mode in $modes) {
            $dir = Join-Path $work "$name-$mode"
            New-Item -ItemType Directory $dir | Out-Null
            $trace = Join-Path $dir "capture.trace"
            Push-Location $dir
            try {
                $arguments = @("$($run.seconds)", $run.rate, "$($run.threads)")
                $wall = [System.Diagnostics.Stopwatch]::StartNew()
                if ($mode -eq "baseline") {
                    Invoke-NativeWithTimeout -FilePath $exe -ArgumentList $arguments -TimeoutSeconds 120
                } else {
                    $captureArgs = @("capture", "--dll", $dll, "--mode", "full", "--output", $trace, "--", $exe) + $arguments
                    $captured = Invoke-NativeCaptured -FilePath $cli -ArgumentList $captureArgs -TimeoutSeconds (6 * $run.seconds + 120) -DumpDirectory $diagnostics
                    $captureOutput = $captured.Output -split "`r?`n"
                    $captureExit = $captured.ExitCode
                    $captureOutput | Out-Host
                    if ($captureExit -notin @(0,2)) { throw "sustained capture failed: $captureExit" }
                }
                $wall.Stop()
                $m = Get-Content "measurement.json" -Raw | ConvertFrom-Json
                $appSeconds = $m.ticks / $m.qpc_frequency
                $itersPerSecond = $m.iterations / $appSeconds
                if ($mode -eq "baseline") { $baselineRate = $itersPerSecond; continue }
                # Read the capture summary instead of `shirusu inspect`: an
                # unpaced run records tens of millions of events, and inspect
                # loads every event into memory.
                $text = $captureOutput -join "`n"
                if ($text -notmatch 'events: (\d+) \(loss records: (\d+)\)') { throw "capture summary missing events" }
                $events = [double]$Matches[1]; $lossRecords = [double]$Matches[2]
                if ($text -notmatch 'queue full (\d+), drain wait ([\d.]+)ms, conversion wall ([\d.]+)ms, queue peak (\d+) bytes') { throw "capture summary missing host pipeline" }
                $queueFull = [double]$Matches[1]; $drainWaitMs = [double]$Matches[2]; $conversionMs = [double]$Matches[3]; $queuePeak = [double]$Matches[4]
                if ($text -notmatch 'event_integrity=(\w+)') { throw "capture summary missing integrity" }
                $integrity = $Matches[1]
                $hostPeakWs = Get-SummaryNumber $text 'host memory: peak working set (\d+) bytes'
                $hostPeakPrivate = Get-SummaryNumber $text 'host memory: peak working set \d+ bytes, peak private (\d+) bytes'
                $targetPeakWs = Get-SummaryNumber $text 'target memory: peak working set (\d+) bytes'
                $targetPeakPrivate = Get-SummaryNumber $text 'target memory: peak working set \d+ bytes, peak private (\d+) bytes'
                $afterExitMs = Get-SummaryNumber $text 'host after target exit: ([\d.]+)ms'
                $traceBytes = (Get-Item $trace).Length
                # V2: read the Trace back with the product's own Reader before
                # deleting it (unpaced traces reach gigabytes).
                $inspected = Invoke-NativeCaptured -FilePath $cli -ArgumentList @("inspect", "--json", $trace) -TimeoutSeconds 900 -DumpDirectory $diagnostics
                if ($inspected.ExitCode -ne 0) { throw "inspect could not read the sustained trace ($($inspected.ExitCode))" }
                $inspect = $inspected.Output | ConvertFrom-Json
                Remove-Item $trace
                if ($inspect.events -ne $events) { throw "trace holds $($inspect.events) events, the capture reported $events" }
                if (-not $inspect.integrity.finalized_cleanly) { throw "sustained trace did not finalize cleanly" }
                if ($inspect.integrity.recovery_issues.Count -gt 0) { throw "sustained trace has recovery issues: $($inspect.integrity.recovery_issues -join '; ')" }
                if ($lossRecords -gt 0 -and $integrity -eq "Complete") { throw "sustained trace with losses finalized as complete" }
                # Two events per call, three calls per iteration, plus each
                # pacing Sleep; startup and shutdown add a few hundred more.
                $sleeps = if ($null -ne $m.sleeps) { [double]$m.sleeps } else { 0.0 }
                $expected = 6.0 * $m.iterations + 2.0 * $sleeps
                # V1: missing events with no loss record are a silent loss.
                if ($lossRecords -eq 0 -and $events -lt $expected) { throw "silent loss: $events events, at least $expected expected, no loss record" }
                # Independent accounting: workload's own per-API counts
                # against the Trace's per-API enter counts.
                $accounting = @()
                if ($null -ne $m.calls) {
                    foreach ($prop in $m.calls.PSObject.Properties) {
                        $api = $prop.Name; $called = [double]$prop.Value
                        $stat = @($inspect.api_stats | Where-Object { $_.api -match "(^|[!.:])$api$" })
                        $entered = [double](($stat | Measure-Object -Property enter -Sum).Sum)
                        $left = [double](($stat | Measure-Object -Property leave -Sum).Sum)
                        $class = if ($stat.Count -eq 0 -or $entered -eq 0) { "not_hooked" }
                            elseif ($entered -lt $called) { "lost" }
                            elseif ($entered -gt $called) { "extra" }
                            else { "exact" }
                        # The CRT and startup also call the heap; nothing else
                        # outside the loop calls GetCurrentProcessId or Sleep.
                        $extraAllowed = if ($api -in @("HeapAlloc", "HeapFree")) { 100000 } else { 16 }
                        $accounting += [ordered]@{ api = $api; called = $called; enter = $entered; leave = $left; class = $class; difference = $entered - $called }
                        if ($class -eq "not_hooked") { throw "$name`: the workload called $api $called times but the trace has no event for it" }
                        if ($class -eq "lost" -and $lossRecords -eq 0) { throw "$name`: silent loss on $api ($entered of $called calls recorded, no loss record)" }
                        if ($class -eq "extra" -and ($entered - $called) -gt $extraAllowed) { throw "$name`: $api has $($entered - $called) more enter events than calls" }
                        if ($lossRecords -eq 0 -and $left -ne $entered) { throw "$name`: $api enter/leave mismatch ($entered/$left) without loss" }
                    }
                } else {
                    throw "measurement.json has no per-API call counts"
                }
                $result = [ordered]@{
                    run = $name; seconds = $run.seconds; rate = $run.rate
                    threads = $run.threads
                    app_seconds = $appSeconds; iterations = $m.iterations; pacing_sleeps = $sleeps
                    app_iterations_per_second = $itersPerSecond
                    app_iterations_per_second_by_second = $m.per_second
                    baseline_iterations_per_second = $baselineRate
                    throughput_ratio = $(if ($baselineRate) { $baselineRate / $itersPerSecond } else { $null })
                    trace_events = $events
                    application_events_expected = $expected
                    missing_events_estimate = [Math]::Max(0, $expected - $events)
                    loss_records = $lossRecords; trace_bytes = $traceBytes
                    api_accounting = $accounting
                    event_integrity = $integrity
                    host_events_per_second = $(if ($appSeconds -gt 0) { $events / $appSeconds } else { $null })
                    host_queue_peak_bytes = $queuePeak
                    host_queue_full = $queueFull
                    host_drain_wait_ms = $drainWaitMs
                    host_conversion_wall_ms = $conversionMs
                    # V7: Host time after it saw the target exit. The old wall
                    # time estimate included launch, injection and signature
                    # checks, and is kept only for comparison.
                    backlog_after_exit_ms = $afterExitMs
                    wall_minus_app_ms = $wall.Elapsed.TotalMilliseconds - 1000.0 * $appSeconds
                    host_peak_working_set_bytes = $hostPeakWs
                    host_peak_private_bytes = $hostPeakPrivate
                    target_peak_working_set_bytes = $targetPeakWs
                    target_peak_private_bytes = $targetPeakPrivate
                }
                $results += $result
                Write-Report $false
                $perSecond = ($m.per_second | ForEach-Object { "{0:N0}" -f $_ }) -join " "
                Write-Host ("Sustained {0} ({1}): app {2:N0} it/s, events={3:N0} expected~{4:N0} missing~{5:N0} loss records={6} integrity={7}, queue peak={8:N0}B full={9} drain wait={10:N1}ms, backlog after exit={11:N0}ms, host peak private={12:N0}B, ratio={13}" -f $name, $arch, $itersPerSecond, $events, $expected, $result.missing_events_estimate, $lossRecords, $integrity, $queuePeak, $queueFull, $drainWaitMs, $result.backlog_after_exit_ms, $hostPeakPrivate, $(if ($result.throughput_ratio) { "{0:N2}x" -f $result.throughput_ratio } else { "n/a" }))
                Write-Host "  per-second iterations: $perSecond"
            } finally { Pop-Location }
        }
    }
    # V3: the Host's memory must not grow with the recording length.
    $short = $results | Where-Object { $_.run -eq "10s-50000-t1" }
    $long = $results | Where-Object { $_.run -eq "30s-50000-t1" }
    if ($short -and $long -and $short.host_peak_private_bytes -and $long.host_peak_private_bytes) {
        $limit = 2.0 * $short.host_peak_private_bytes + 64MB
        if ($long.host_peak_private_bytes -gt $limit) {
            throw ("host peak private memory grows with recording length: 10s {0:N0}B, 30s {1:N0}B" -f $short.host_peak_private_bytes, $long.host_peak_private_bytes)
        }
    }
    $complete = $true
} finally {
    Write-Report $complete
    Write-Host "Sustained load report: $reportPath"
}
