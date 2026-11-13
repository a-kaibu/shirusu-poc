# Called after the unchanged default-capacity native performance run.
param(
    [string]$Target,
    [string]$Fixture,
    [string]$Dll,
    [string]$Cli,
    [string]$Work,
    [int]$Rounds = 3
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
Invoke-Native { cargo build -p shirusu-e2e --release --target $Target --bin shirusu-buffer-bench } "buffer capacity benchmark"
$helper = (Resolve-Path "target\$Target\release\shirusu-buffer-bench.exe").Path
$rows = @()
$complete = $false
try {
    for ($round = 0; $round -lt $Rounds; $round++) {
        $capacities = if ($round % 2) { @(65536, 16384, 4096) } else { @(4096, 16384, 65536) }
        foreach ($capacity in $capacities) {
            $dir = Join-Path $Work "buffer-$round-$capacity"
            New-Item -ItemType Directory $dir | Out-Null
            Push-Location $dir
            try {
                $trace = Join-Path $dir "capture.trace"
                Invoke-NativeWithTimeout -FilePath $helper -ArgumentList @($Dll, $Fixture, $trace, "$capacity")
                $measurement = Get-Content "measurement.json" -Raw | ConvertFrom-Json
                if ($measurement.workload -ne "high-load" -or $measurement.ticks -le 0 -or $measurement.qpc_frequency -le 0) { throw "invalid buffer benchmark timing" }
                $raw = & $Cli inspect $trace --json
                if ($LASTEXITCODE -notin @(0,1)) { throw "buffer benchmark trace inspection failed" }
                $summary = ($raw -join "`n") | ConvertFrom-Json
                $observed = @($summary.api_stats | Where-Object { $_.api -eq "kernel32!HeapAlloc" -and $_.enter -gt 0 }).Count -gt 0
                $rows += [ordered]@{
                    round = $round; descriptor_capacity = $capacity; payload_capacity = 1048576
                    measurement = $measurement; trace_bytes = (Get-Item $trace).Length
                    trace_summary = $summary; required_api_observed = $observed
                }
                Write-Host ("Buffer capacity {0}/{1}: {2:N3}ms events={3} losses={4}" -f $capacity, $round, (1000.0 * $measurement.ticks / $measurement.qpc_frequency), $summary.events, $summary.integrity.total_loss_count)
                if (-not $observed -or $null -eq $summary.integrity) { throw "buffer benchmark workload not observed" }
                if ($rows.Count -gt 1) {
                    $first = $rows[0].measurement
                    if ($measurement.iterations -ne $first.iterations -or $measurement.checksum -ne $first.checksum) { throw "buffer capacity changed workload result" }
                }
            } finally { Pop-Location }
        }
    }
    $complete = $true
} finally {
    $report = [ordered]@{
        benchmark = "native-buffer-capacity"; target = $Target; commit = (git rev-parse HEAD)
        measurement_complete = $complete; rounds = $Rounds
        scope = "Same 50000-iteration high-load workload; descriptor capacity varies, payload remains 1 MiB per ring. Separate from default-configuration acceptance results."
        samples = $rows
    }
    $path = Join-Path $Work "native-performance-buffer-$Target.json"
    $report | ConvertTo-Json -Depth 24 | Set-Content $path
    if ($env:SHIRUSU_DIAGNOSTIC_DIR) { Copy-Item $path $env:SHIRUSU_DIAGNOSTIC_DIR }
}
