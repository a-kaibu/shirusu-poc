# Real-application validation: record applications that ship with Windows,
# not fixtures written for shirusu.
#
# Every application is run once without shirusu (baseline) and twice under
# `shirusu capture --mode full`. A run fails the script when:
#   - the recorded application behaves differently from the baseline
#     (exit code, its own console output, or the files it writes);
#   - capture hangs (timed out) or does not exit 0/2;
#   - the Trace cannot be read back, did not finalize cleanly, has recovery
#     issues or an index that does not match the scan, or holds no events;
#   - shirusu-compare rejects the two recordings as input (exit 2).
# Loss, integrity level, the number of compare candidates between the two
# recordings and the wall-clock ratio are measurements, not gates: they go to
# target/ci-diagnostics/real-apps-<arch>.json and the log.
#
# GUI applications (notepad, charmap) are closed with WM_CLOSE through
# CloseMainWindow once their main window appears; time to the first window is
# measured with and without shirusu.
param(
    [ValidateSet("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")][string]$Target = "x86_64-pc-windows-msvc",
    [int]$Repeat = 2
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$arch = if ($Target -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
$bin = Join-Path $repo "target\$Target\debug"
$cli = Join-Path $bin "shirusu.exe"
$dll = Join-Path $bin "shirusu_agent_dll.dll"
# The compare tool reads traces only; build it for the host architecture.
$compare = Join-Path $repo "target\x86_64-pc-windows-msvc\debug\shirusu-compare.exe"
foreach ($path in @($cli, $dll, $compare)) {
    if (-not (Test-Path $path)) { throw "missing build output: $path" }
}
# 32-bit applications live in SysWOW64 on a 64-bit Windows.
$sys = if ($arch -eq "x86") { Join-Path $env:windir "SysWOW64" } else { Join-Path $env:windir "System32" }
$ps = Join-Path $sys "WindowsPowerShell\v1.0\powershell.exe"
$diagnostics = Join-Path $repo "target\ci-diagnostics"
New-Item -ItemType Directory -Force -Path $diagnostics | Out-Null
$work = Join-Path $repo ("target\real-apps-$arch-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null

# Shared, deterministic input for the file-reading applications.
$inputText = (1..400 | ForEach-Object { "line $_ Windows shirusu real application input $($_ * 7919 % 1000)" }) -join "`r`n"
$inputFile = Join-Path $work "input.txt"
[System.IO.File]::WriteAllText($inputFile, $inputText + "`r`n")
$tree = Join-Path $work "tree"
foreach ($d in 1..4) {
    $sub = Join-Path $tree "d$d"
    New-Item -ItemType Directory -Force $sub | Out-Null
    foreach ($f in 1..25) { [System.IO.File]::WriteAllText((Join-Path $sub "f$f.txt"), "file $d/$f`r`n" * (20 * $f)) }
}

# Each console application runs in its own empty directory. `Check` names the
# files whose contents must match the baseline afterwards.
$apps = @(
    @{ name = "cmd"; kind = "console"; exe = (Join-Path $sys "cmd.exe")
       args = @("/d", "/c", "echo shirusu> a.txt && copy /y a.txt b.txt >nul && type b.txt && dir /b *.txt && del a.txt"); check = @("b.txt") },
    @{ name = "findstr"; kind = "console"; exe = (Join-Path $sys "findstr.exe")
       args = @("/n", "/c:input 7", $inputFile); check = @() },
    @{ name = "certutil"; kind = "console"; exe = (Join-Path $sys "certutil.exe")
       args = @("-hashfile", $inputFile, "SHA256"); check = @() },
    @{ name = "reg"; kind = "console"; exe = (Join-Path $sys "reg.exe")
       args = @("query", "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "/v", "CurrentBuildNumber"); check = @() },
    @{ name = "robocopy"; kind = "console"; exe = (Join-Path $sys "robocopy.exe")
       # /MT:8 copies on eight threads; exit code 1 means files were copied.
       args = @($tree, "copy", "/E", "/MT:8", "/NP", "/NFL", "/NDL", "/NJH", "/NJS"); check = @("copy\d1\f25.txt", "copy\d4\f1.txt") },
    @{ name = "powershell"; kind = "console"; exe = $ps
       # Windows PowerShell 5.1: CLR start-up, JIT, many threads, a COM object.
       args = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                "`$fso = New-Object -ComObject Scripting.FileSystemObject; `$fso.FileExists('$inputFile'); [IO.File]::WriteAllText((Join-Path (Get-Location) 'ps.txt'), ((Get-Content '$inputFile' | Select-String 'input 3' | Measure-Object).Count).ToString()); Get-Content ps.txt; [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes('$inputFile'))); exit 0")
       check = @("ps.txt") },
    @{ name = "notepad"; kind = "gui"; exe = (Join-Path $sys "notepad.exe"); args = @($inputFile); check = @() },
    @{ name = "charmap"; kind = "gui"; exe = (Join-Path $sys "charmap.exe"); args = @(); check = @() }
)

function Wait-MainWindowAndClose {
    param([int]$ProcessId, [datetime]$Started, [int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $p) { throw "GUI process $ProcessId exited before it showed a window" }
        $p.Refresh()
        if ($p.MainWindowHandle -ne [IntPtr]::Zero) {
            $toWindow = ((Get-Date) - $Started).TotalMilliseconds
            # Let the window finish its first paint and message loop work.
            Start-Sleep -Milliseconds 1500
            if (-not $p.CloseMainWindow()) { throw "WM_CLOSE could not be posted to $ProcessId" }
            return $toWindow
        }
        Start-Sleep -Milliseconds 100
    }
    throw "GUI process $ProcessId showed no main window within ${TimeoutSeconds}s"
}

function Find-CaptureChild {
    param([int]$HostId, [string]$ImageName, [int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $child = Get-CimInstance Win32_Process -Filter "ParentProcessId = $HostId" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ieq $ImageName } | Select-Object -First 1
        if ($child) { return [int]$child.ProcessId }
        Start-Sleep -Milliseconds 100
    }
    throw "shirusu capture ($HostId) started no $ImageName within ${TimeoutSeconds}s"
}

function Get-FileState {
    param([string]$Dir, [string[]]$Names)
    foreach ($n in $Names) {
        $p = Join-Path $Dir $n
        if (-not (Test-Path $p)) { "${n}: missing" } else { "${n}: " + (Get-FileHash $p -Algorithm SHA256).Hash }
    }
}

# Console output of the target, without shirusu's own summary (printed after
# the target exits, starting with "captured: ").
function Get-TargetLines {
    param([string]$Text)
    $lines = @($Text -split "`r?`n")
    $end = [Array]::FindIndex($lines, [Predicate[string]] { param($l) $l.StartsWith("captured: ") })
    if ($end -lt 0) { $end = $lines.Count }
    # Trailing blank lines differ with buffering only.
    @($lines[0..([Math]::Max(0, $end - 1))] | Where-Object { $_ -ne $null }) -join "`n" -replace "\s+$", ""
}

function Invoke-App {
    param($App, [string]$Mode, [int]$Index)
    $dir = Join-Path $work "$($App.name)-$Mode-$Index"
    New-Item -ItemType Directory $dir | Out-Null
    $trace = Join-Path $dir "$($App.name).trace"
    $out = Join-Path $dir "stdout.txt"
    $err = Join-Path $dir "stderr.txt"
    if ($Mode -eq "baseline") {
        $file = $App.exe; $argv = $App.args
    } else {
        $file = $cli
        $argv = @("capture", "--dll", $dll, "--mode", "full", "--output", $trace, "--") + @($App.exe) + $App.args
    }
    $timeout = Get-StepTimeout -Requested 300 -What "$($App.name) $Mode"
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $file
    $start.WorkingDirectory = $dir
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($a in $argv) { $start.ArgumentList.Add($a) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    $started = Get-Date
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $process.Start()) { throw "could not start $file" }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $toWindow = $null
    try {
        if ($App.kind -eq "gui") {
            $targetId = if ($Mode -eq "baseline") { $process.Id } else { Find-CaptureChild -HostId $process.Id -ImageName ([IO.Path]::GetFileName($App.exe)) }
            $toWindow = Wait-MainWindowAndClose -ProcessId $targetId -Started $started
        }
        if (-not $process.WaitForExit($timeout * 1000)) {
            Save-ProcessTree -ProcessId $process.Id -Directory $diagnostics -Label "real-$($App.name)-$Mode"
            throw "$($App.name) ($Mode) timed out after ${timeout}s"
        }
        $process.WaitForExit()
    } catch {
        if (-not $process.HasExited) { $process.Kill($true); $null = $process.WaitForExit(10000) }
        throw
    }
    $watch.Stop()
    $text = $stdout.GetAwaiter().GetResult()
    $errText = $stderr.GetAwaiter().GetResult()
    Set-Content -Path $out -Value $text
    Set-Content -Path $err -Value $errText
    $exit = $process.ExitCode
    $process.Dispose()
    $result = [ordered]@{
        dir = $dir; trace = $trace; wall_ms = $watch.Elapsed.TotalMilliseconds; first_window_ms = $toWindow
        process_exit = $exit; target_exit = $null; output = $null; files = @(Get-FileState $dir $App.check); summary = $text
    }
    if ($Mode -eq "baseline") {
        $result.target_exit = $exit
        $result.output = Get-TargetLines $text
    } else {
        if ($exit -notin @(0, 2)) { throw "$($App.name): shirusu capture exited $exit`n$text`n$errText" }
        if ($text -notmatch '(?m)^target exit code: (-?\d+) ') { throw "$($App.name): capture printed no target exit code`n$text`n$errText" }
        $result.target_exit = [int64]$Matches[1]
        $result.output = Get-TargetLines $text
    }
    return [pscustomobject]$result
}

$results = [System.Collections.Generic.List[object]]::new()
$failures = [System.Collections.Generic.List[string]]::new()
try {
    foreach ($app in $apps) {
        if (-not (Test-Path $app.exe)) {
            Write-Warning "$($app.name): $($app.exe) is not on this image; skipped"
            $results.Add([pscustomobject]@{ app = $app.name; arch = $arch; skipped = "not installed" })
            continue
        }
        try {
            $base = Invoke-App $app "baseline" 0
            $runs = @()
            foreach ($i in 1..$Repeat) {
                $run = Invoke-App $app "capture" $i
                $problems = @()
                if ($run.target_exit -ne $base.target_exit) { $problems += "exit code $($run.target_exit), baseline $($base.target_exit)" }
                if ($app.kind -eq "console" -and $run.output -ne $base.output) {
                    $problems += "console output differs from the baseline:`n--- baseline`n$($base.output)`n--- recorded`n$($run.output)"
                }
                if (($run.files -join "|") -ne ($base.files -join "|")) { $problems += "written files differ: $($run.files -join ', ') vs $($base.files -join ', ')" }
                $inspected = Invoke-NativeCaptured -FilePath $cli -ArgumentList @("inspect", "--json", $run.trace) -TimeoutSeconds 600 -DumpDirectory $diagnostics
                # inspect exits 1 for a readable trace that lost events; the
                # loss is a measurement here, an unreadable trace is not.
                $inspect = $null
                if ($inspected.ExitCode -in @(0, 1)) { try { $inspect = $inspected.Output | ConvertFrom-Json } catch { } }
                if (-not $inspect -or ($inspected.ExitCode -eq 1 -and $inspect.integrity.status -ne "incomplete")) {
                    $problems += "inspect could not read the trace ($($inspected.ExitCode))"
                }
                else {
                    if ($inspect.events -le 0) { $problems += "trace holds no events" }
                    if (-not $inspect.integrity.finalized_cleanly) { $problems += "trace did not finalize cleanly" }
                    if ($inspect.integrity.recovery_issues.Count -gt 0) { $problems += "recovery issues: $($inspect.integrity.recovery_issues -join '; ')" }
                    if ($inspect.integrity.index -eq "mismatch") { $problems += "stored index does not match the scan" }
                    $run | Add-Member -NotePropertyName inspect -NotePropertyValue $inspect
                }
                if ($problems.Count -gt 0) {
                    Set-Content (Join-Path $diagnostics "real-$arch-$($app.name)-baseline-output.txt") $base.summary
                    Set-Content (Join-Path $diagnostics "real-$arch-$($app.name)-$i-output.txt") ($run.summary + "`n--- stderr`n" + (Get-Content (Join-Path $run.dir "stderr.txt") -Raw))
                    Copy-Item $run.trace -Destination (Join-Path $diagnostics "real-$arch-$($app.name)-$i.trace") -ErrorAction SilentlyContinue
                    throw ("$($app.name) ($arch) run ${i}: " + ($problems -join "; ") + "`n$($run.summary)")
                }
                $runs += $run
            }
            $candidates = $null
            if ($runs.Count -ge 2) {
                $report = Join-Path $work "$($app.name)-compare.json"
                $cmp = Invoke-NativeCaptured -FilePath $compare -ArgumentList @($runs[0].trace, $runs[1].trace, "--json", "--output", $report) -TimeoutSeconds 600 -DumpDirectory $diagnostics
                if ($cmp.ExitCode -notin @(0, 1)) { throw "$($app.name) ($arch): shirusu-compare rejected the recordings ($($cmp.ExitCode))" }
                $candidates = (Get-Content $report -Raw | ConvertFrom-Json).summary
                Copy-Item $report -Destination (Join-Path $diagnostics "real-$arch-$($app.name)-compare.json")
            }
            foreach ($run in $runs) {
                $i = $run.inspect
                $apisSeen = @($i.api_stats | Where-Object { $_.enter -gt 0 }).Count
                $entry = [ordered]@{
                    app = $app.name; arch = $arch; kind = $app.kind
                    baseline_ms = [Math]::Round($base.wall_ms, 1); recorded_ms = [Math]::Round($run.wall_ms, 1)
                    ratio = [Math]::Round($run.wall_ms / [Math]::Max(1.0, $base.wall_ms), 2)
                    baseline_first_window_ms = $base.first_window_ms; recorded_first_window_ms = $run.first_window_ms
                    events = $i.events; threads = $i.threads; apis_seen = $apisSeen
                    integrity = $i.integrity.status; event_integrity = $i.integrity.event_integrity
                    capture_coverage = $i.integrity.capture_coverage
                    loss_count = $i.integrity.total_loss_count
                    compare_candidates = if ($candidates) { $candidates.candidates } else { $null }
                    compare_high = if ($candidates) { $candidates.high } else { $null }
                }
                $results.Add([pscustomobject]$entry)
                Write-Host ("real app {0} ({1}): {2:N0} ms -> {3:N0} ms ({4}x), window {5} -> {6} ms, events={7:N0} threads={8} apis={9} integrity={10}/{11} coverage={12} loss={13} compare candidates={14} (high {15})" -f `
                    $entry.app, $arch, $entry.baseline_ms, $entry.recorded_ms, $entry.ratio,
                    $(if ($null -ne $entry.baseline_first_window_ms) { [Math]::Round($entry.baseline_first_window_ms) } else { "-" }),
                    $(if ($null -ne $entry.recorded_first_window_ms) { [Math]::Round($entry.recorded_first_window_ms) } else { "-" }),
                    $entry.events, $entry.threads, $entry.apis_seen, $entry.integrity, $entry.event_integrity,
                    $entry.capture_coverage, $entry.loss_count, $entry.compare_candidates, $entry.compare_high)
            }
        } catch {
            $failures.Add("$_")
            Write-Warning "real app failed: $_"
        }
    }
} finally {
    $results | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $diagnostics "real-apps-$arch.json")
}
if ($failures.Count -gt 0) {
    throw ("Real applications failed ($arch):`n" + ($failures -join "`n"))
}
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
