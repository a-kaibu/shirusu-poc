param(
    [ValidateSet("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")][string]$Target = "x86_64-pc-windows-msvc",
    [ValidateRange(1, 15)][int]$Rounds = 3
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo
$arch = if ($Target -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
Invoke-Native { cargo build -p shirusu-cli -p shirusu-agent-dll --release --target $Target } "native performance release binaries"
$bin = Join-Path $repo "target\$Target\release"
$cli = Join-Path $bin "shirusu.exe"
$dll = Join-Path $bin "shirusu_agent_dll.dll"
$work = Join-Path $repo ("target\native-performance-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "MSVC compiler not found" }
$dev = Join-Path $vs "Common7\Tools\VsDevCmd.bat"
$source = Join-Path $repo "e2e\native\performance.cpp"
$exe = Join-Path $work "performance.exe"
$compile = "`"$dev`" -arch=$arch && cl /nologo /W4 /WX /O2 /Fe:`"$exe`" /Fo:`"$work\fixture.obj`" `"$source`" /link kernel32.lib user32.lib gdi32.lib"
$buildScript = Join-Path $work "build.cmd"
@("@echo off", "call $compile") | Set-Content -Encoding ascii $buildScript
Invoke-Native { cmd /d /c $buildScript } "native performance fixture ($arch)"
function Median($values) {
    $sorted = @($values | Sort-Object)
    $middle = [int][Math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2) { return $sorted[$middle] }
    return ($sorted[$middle - 1] + $sorted[$middle]) / 2.0
}
$samples = @()
$results = @()
$measurementComplete = $false
try {
foreach ($workload in @("gui", "high-load")) {
    for ($round = 0; $round -lt $Rounds; $round++) {
        # Alternate order to reduce systematic warm-cache / load bias.
        $order = if ($round % 2) { @("capture", "baseline") } else { @("baseline", "capture") }
        foreach ($mode in $order) {
            $dir = Join-Path $work "$workload-$round-$mode"
            New-Item -ItemType Directory $dir | Out-Null
            $trace = Join-Path $dir "capture.trace"
            Push-Location $dir
            try {
                $wall = [System.Diagnostics.Stopwatch]::StartNew()
                if ($mode -eq "baseline") {
                    Invoke-NativeWithTimeout -FilePath $exe -ArgumentList @($workload)
                } else {
                    & $cli capture --dll $dll --mode full --output $trace -- $exe $workload | Tee-Object -Variable captureOutput
                    if ($LASTEXITCODE -notin @(0,2)) { throw "performance capture failed: $LASTEXITCODE" }
                    if (-not ($captureOutput -match '^target exit code: 0 \(0x00000000\)$')) { throw "native performance target did not exit successfully" }
                }
                $wall.Stop()
                $measurement = Get-Content "measurement.json" -Raw | ConvertFrom-Json
                if ($measurement.workload -ne $workload -or $measurement.ticks -le 0 -or $measurement.qpc_frequency -le 0) {
                    throw "invalid native timing result"
                }
                $summary = $null
                if ($mode -eq "capture") {
                    $raw = & $cli inspect $trace --json
                    $inspectExit = $LASTEXITCODE
                    if ($inspectExit -notin @(0,1)) { throw "performance trace inspection failed" }
                    $raw | Set-Content "trace-summary.json"
                    $summary = ($raw -join "`n") | ConvertFrom-Json
                    if ($null -eq $summary.integrity -or ($inspectExit -eq 1 -and $summary.integrity.status -ne "incomplete")) { throw "invalid performance inspection result" }
                    $requiredApi = if ($workload -eq "gui") { "user32!BeginPaint" } else { "kernel32!HeapAlloc" }
                    if (-not ($summary.api_stats | Where-Object { $_.api -eq $requiredApi -and $_.enter -gt 0 })) {
                        throw "performance run did not capture $requiredApi"
                    }
                }
                $samples += [ordered]@{
                    workload = $workload; round = $round; mode = $mode
                    iterations = $measurement.iterations
                    elapsed_ns = 1e9 * $measurement.ticks / $measurement.qpc_frequency
                    process_and_host_wall_ms = $wall.Elapsed.TotalMilliseconds
                    paint_count = $measurement.paint_count; checksum = $measurement.checksum
                    trace_bytes = $(if ($summary) { (Get-Item $trace).Length } else { $null })
                    trace_events = $(if ($summary) { $summary.events } else { $null })
                    integrity = $(if ($summary) { $summary.integrity } else { $null })
                    apis = $(if ($summary) { $summary.api_stats } else { $null })
                }
            } finally { Pop-Location }
        }
        $pair = @($samples | Where-Object { $_.workload -eq $workload -and $_.round -eq $round })
        if ($pair[0].paint_count -ne $pair[1].paint_count -or $pair[0].checksum -ne $pair[1].checksum -or $pair[0].iterations -ne $pair[1].iterations) {
            throw "native workload result changed under capture: $workload"
        }
    }
    $baseline = @($samples | Where-Object { $_.workload -eq $workload -and $_.mode -eq "baseline" })
    $captured = @($samples | Where-Object { $_.workload -eq $workload -and $_.mode -eq "capture" })
    $baselineNs = Median @($baseline | ForEach-Object { $_.elapsed_ns })
    $captureNs = Median @($captured | ForEach-Object { $_.elapsed_ns })
    $ratio = $captureNs / $baselineNs
    $limit = if ($workload -eq "gui") { 3.0 } else { 5.0 }
    $complete = @($captured | Where-Object { $_.integrity.status -ne "complete" -or -not $_.integrity.finalized_cleanly }).Count -eq 0
    $results += [ordered]@{
        workload = $workload; baseline_median_ns = $baselineNs; captured_median_ns = $captureNs
        ratio = $ratio; target_ratio = $limit; ratio_target_met = ($ratio -le $limit)
        all_event_integrity_complete = $complete
        target_met_without_event_loss = ($ratio -le $limit -and $complete)
        added_ns_per_iteration = ($captureNs - $baselineNs) / $baseline[0].iterations
    }
    Write-Host ("Native {0}: {1:N3}x (target {2}x), event integrity complete={3}" -f $workload, $ratio, $limit, $complete)
}
$measurementComplete = $true
} finally {
$report = [ordered]@{
    benchmark = "native-injected-application"; target = $Target; rounds = $Rounds
    measurement_complete = $measurementComplete
    os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    commit = (git rev-parse HEAD); agent_configuration = "release, full, default ring sizes"
    scope = "Application QPC interval excludes injection/startup/shutdown. GUI is a 300-frame GDI repaint/message workload; high-load is 50000 iterations of GetCurrentProcessId + HeapAlloc + HeapFree. Not a claim about all applications or all Windows APIs. Trace totals include startup/shutdown."
    results = $results; samples = $samples
}
$reportPath = Join-Path $work "native-performance-$arch.json"
$report | ConvertTo-Json -Depth 16 | Set-Content $reportPath
if ($env:SHIRUSU_DIAGNOSTIC_DIR) { Copy-Item $reportPath $env:SHIRUSU_DIAGNOSTIC_DIR }
Write-Host "Native performance report: $reportPath"
}
# Targets are development evaluation criteria, not correctness gates. Timing
# misses and real loss remain visible in the report; failures to run/observe
# the workload are fatal. The model benchmark measures buffer occupancy apart.
