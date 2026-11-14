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
    @{ seconds = 10; rate = "50000" },
    @{ seconds = 30; rate = "50000" },
    @{ seconds = 10; rate = "200000" },
    @{ seconds = 10; rate = "max" }
)
$results = @()
$complete = $false
try {
    foreach ($run in $runs) {
        $name = "$($run.seconds)s-$($run.rate)"
        $modes = if ($run.rate -eq "max") { @("baseline", "capture") } else { @("capture") }
        $baselineRate = $null
        foreach ($mode in $modes) {
            $dir = Join-Path $work "$name-$mode"
            New-Item -ItemType Directory $dir | Out-Null
            $trace = Join-Path $dir "capture.trace"
            Push-Location $dir
            try {
                $arguments = @("$($run.seconds)", $run.rate)
                $wall = [System.Diagnostics.Stopwatch]::StartNew()
                if ($mode -eq "baseline") {
                    Invoke-NativeWithTimeout -FilePath $exe -ArgumentList $arguments -TimeoutSeconds 120
                } else {
                    & $cli capture --dll $dll --mode full --output $trace -- $exe @arguments | Out-Host
                    if ($LASTEXITCODE -notin @(0,2)) { throw "sustained capture failed: $LASTEXITCODE" }
                }
                $wall.Stop()
                $m = Get-Content "measurement.json" -Raw | ConvertFrom-Json
                $appSeconds = $m.ticks / $m.qpc_frequency
                $itersPerSecond = $m.iterations / $appSeconds
                if ($mode -eq "baseline") { $baselineRate = $itersPerSecond; continue }
                $raw = & $cli inspect $trace --json
                if ($LASTEXITCODE -notin @(0,1)) { throw "sustained trace inspection failed" }
                $summary = ($raw -join "`n") | ConvertFrom-Json
                $api = @($summary.api_stats | Where-Object { $_.api -eq "kernel32!HeapAlloc" -and $_.enter -gt 0 })
                if ($api.Count -ne 1) { throw "sustained run did not capture HeapAlloc" }
                $lossKinds = @($summary.integrity.loss_records | ForEach-Object { "$($_.kind):$($_.records)" }) -join ","
                $losses = [double]$summary.integrity.total_loss_count
                if ($losses -gt 0 -and $summary.integrity.status -eq "complete") { throw "sustained trace with losses finalized as complete" }
                $config = $summary.environment.capture_config
                # Expected events: two per call, three calls per iteration.
                $expected = 6.0 * $m.iterations
                $result = [ordered]@{
                    run = $name; seconds = $run.seconds; rate = $run.rate
                    app_seconds = $appSeconds; iterations = $m.iterations
                    app_iterations_per_second = $itersPerSecond
                    app_iterations_per_second_by_second = $m.per_second
                    baseline_iterations_per_second = $baselineRate
                    throughput_ratio = $(if ($baselineRate) { $baselineRate / $itersPerSecond } else { $null })
                    trace_events = $summary.events
                    application_events_expected = $expected
                    captured_fraction = $(if ($expected -gt 0) { [Math]::Min($summary.events, $expected) / $expected } else { $null })
                    loss_count = $losses; loss_kinds = $lossKinds
                    loss_rate = $(if ($expected -gt 0) { $losses / $expected } else { $null })
                    integrity = $summary.integrity.status
                    host_events_received = Get-ConfigValue $config "host_events_received"
                    host_events_per_second = $(if ($appSeconds -gt 0) { (Get-ConfigValue $config "host_events_received") / $appSeconds } else { $null })
                    host_queue_peak_bytes = Get-ConfigValue $config "host_queue_peak_bytes"
                    host_queue_full = Get-ConfigValue $config "host_queue_full"
                    host_drain_wait_ms = (Get-ConfigValue $config "host_drain_wait_ns") / 1e6
                    host_conversion_wall_ms = (Get-ConfigValue $config "host_conversion_wall_ns") / 1e6
                    backlog_after_exit_ms = $wall.Elapsed.TotalMilliseconds - 1000.0 * $appSeconds
                }
                $results += $result
                $perSecond = ($m.per_second | ForEach-Object { "{0:N0}" -f $_ }) -join " "
                Write-Host ("Sustained {0} ({1}): app {2:N0} it/s, events={3} expected~{4:N0} losses={5} ({6:P4}) [{13}] integrity={7}, queue peak={8:N0}B full={9} drain wait={10:N1}ms, backlog after exit={11:N0}ms, ratio={12}" -f $name, $arch, $itersPerSecond, $summary.events, $expected, $losses, $result.loss_rate, $result.integrity, $result.host_queue_peak_bytes, $result.host_queue_full, $result.host_drain_wait_ms, $result.backlog_after_exit_ms, $(if ($result.throughput_ratio) { "{0:N2}x" -f $result.throughput_ratio } else { "n/a" }), $lossKinds)
                Write-Host "  per-second iterations: $perSecond"
            } finally { Pop-Location }
        }
    }
    $complete = $true
} finally {
    $report = [ordered]@{
        benchmark = "native-sustained-load"; target = $Target; measurement_complete = $complete
        os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        commit = (git rev-parse HEAD); agent_configuration = "release, full, default ring sizes"
        scope = "GetCurrentProcessId + HeapAlloc + HeapFree in a loop for a fixed duration, paced or unpaced. Trace events include startup/shutdown; expected counts only the loop."
        results = $results
    }
    $reportPath = Join-Path $work "sustained-load-$arch.json"
    $report | ConvertTo-Json -Depth 8 | Set-Content $reportPath
    if ($env:SHIRUSU_DIAGNOSTIC_DIR) { Copy-Item $reportPath $env:SHIRUSU_DIAGNOSTIC_DIR }
    Write-Host "Sustained load report: $reportPath"
}
