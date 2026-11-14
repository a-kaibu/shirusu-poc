# ネイティブコマンドの終了コード伝播ヘルパー (レビュー #4 の #3)。
#
# $ErrorActionPreference = "Stop" は PowerShell コマンドレットのエラー
# では止まるが、ネイティブコマンド (cargo / *.exe) が非ゼロで終了しても
# 止まらない。そのため、終了コードを見ずに後続コマンドを続けると、
# 途中のテスト失敗が最後のコマンドの成功で上書きされ、ジョブ全体が
# 成功扱いになる (run #4 の windows-x64 で実際に起きた)。
#
# CI スクリプトのネイティブコマンドは全て Invoke-Native 経由で実行し、
# $LASTEXITCODE をその場で検査する。失敗したら throw してスクリプトを
# 非ゼロで終わらせる (pwsh -File の終了コードがジョブの成否になる)。
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)] [scriptblock] $Command,
        [Parameter(Mandatory = $true)] [string] $What
    )
    & $Command
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "native step failed: $What (exit code $code)"
    }
}

# Suite deadline (review 2026-11-14 V11). GitHub Actions kills a job at its
# timeout-minutes without running the script's finally blocks, so nothing of
# a hang survives. A suite calls Start-CiDeadline with a budget below the job
# timeout; every timed step is clamped to the time left (minus a margin for
# diagnostics), so the suite fails by itself and its finally still runs.
# Child scripts inherit the suite's deadline through the environment.
$global:ShirusuCiDeadline = $null
if ($env:SHIRUSU_CI_DEADLINE) {
    $global:ShirusuCiDeadline = [DateTime]::Parse($env:SHIRUSU_CI_DEADLINE, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
}
function Start-CiDeadline {
    param([Parameter(Mandatory = $true)] [int] $Seconds)
    $global:ShirusuCiDeadline = (Get-Date).AddSeconds($Seconds)
    $env:SHIRUSU_CI_DEADLINE = $global:ShirusuCiDeadline.ToString("o")
    Write-Host ("CI deadline: {0:u} ({1}s)" -f $global:ShirusuCiDeadline.ToUniversalTime(), $Seconds)
}
function Get-StepTimeout {
    param([Parameter(Mandatory = $true)] [int] $Requested, [string] $What = "step")
    if (-not $global:ShirusuCiDeadline) { return $Requested }
    # Leave room for dumps, diagnostics and the artifact upload.
    $left = [int][Math]::Floor(($global:ShirusuCiDeadline - (Get-Date)).TotalSeconds) - 120
    if ($left -lt 30) { throw "CI deadline reached before: $What" }
    return [Math]::Min($Requested, $left)
}

# Dump a process and all its descendants (best effort). Children are found
# before anything is dumped, so a dump never races the tree's exit.
function Save-ProcessTree {
    param(
        [Parameter(Mandatory = $true)] [int] $ProcessId,
        [string] $Directory = $env:SHIRUSU_DIAGNOSTIC_DIR,
        [string] $Label = "process"
    )
    if (-not $Directory) { return }
    try {
        $all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $tree = [System.Collections.Generic.List[object]]::new()
        $tree.Add([pscustomobject]@{ Id = $ProcessId; Name = $Label })
        for ($i = 0; $i -lt $tree.Count; $i++) {
            $parent = $tree[$i].Id
            foreach ($child in $all | Where-Object { $_.ParentProcessId -eq $parent -and $_.ProcessId -ne $parent }) {
                $tree.Add([pscustomobject]@{ Id = [int]$child.ProcessId; Name = [System.IO.Path]::GetFileNameWithoutExtension($child.Name) })
            }
        }
        foreach ($entry in $tree) { Save-ProcessDump -ProcessId $entry.Id -Directory $Directory -Label $entry.Name }
    } catch {
        Write-Host "process tree dump failed for PID ${ProcessId}: $_"
    }
}

# Bound native fixtures so one hung target cannot suppress later scenarios.
# ArgumentList preserves paths with spaces without a second shell parse.
# On a timeout the whole tree is dumped (V11) before it is killed.
function Invoke-NativeWithTimeout {
    param(
        [Parameter(Mandatory = $true)] [string] $FilePath,
        [string[]] $ArgumentList = @(),
        [int] $TimeoutSeconds = 180,
        [string] $What = $null
    )
    if (-not $What) { $What = "$FilePath $ArgumentList" }
    $TimeoutSeconds = Get-StepTimeout -Requested $TimeoutSeconds -What $What
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Command $FilePath -ErrorAction Stop).Source
    $start.WorkingDirectory = (Get-Location).Path
    $start.UseShellExecute = $false
    foreach ($argument in $ArgumentList) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw "Could not start $FilePath" }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            Save-ProcessTree -ProcessId $process.Id -Label ([System.IO.Path]::GetFileNameWithoutExtension($start.FileName))
            $process.Kill($true)
            $null = $process.WaitForExit(10000)
            throw "Native step timed out after ${TimeoutSeconds}s: $What"
        }
        $global:LASTEXITCODE = $process.ExitCode
        if ($process.ExitCode -ne 0) {
            throw "native step failed: $What (exit code $($process.ExitCode))"
        }
    } finally { $process.Dispose() }
}

# Write a full minidump of a running process (best effort, review 2026-11-14
# V4/V11): a hang then leaves something to read instead of only a timeout.
function Save-ProcessDump {
    param(
        [Parameter(Mandatory = $true)] [int] $ProcessId,
        [Parameter(Mandatory = $true)] [string] $Directory,
        [string] $Label = "process"
    )
    try {
        New-Item -ItemType Directory -Force $Directory | Out-Null
        $file = Join-Path $Directory ("{0}-{1}.dmp" -f $Label, $ProcessId)
        $comsvcs = Join-Path $env:SystemRoot "System32\comsvcs.dll"
        & rundll32.exe $comsvcs, MiniDump $ProcessId $file full | Out-Null
        Start-Sleep -Milliseconds 500
        if (Test-Path $file) { Write-Host "dump written: $file" } else { Write-Host "dump not written for PID $ProcessId" }
    } catch {
        Write-Host "dump failed for PID ${ProcessId}: $_"
    }
}

# Run a native command with a deadline and return its standard output and
# exit code. On a timeout, dump the process and its children, kill the tree
# and throw, so the caller's finally blocks still run (V4).
function Invoke-NativeCaptured {
    param(
        [Parameter(Mandatory = $true)] [string] $FilePath,
        [string[]] $ArgumentList = @(),
        [int] $TimeoutSeconds = 300,
        [string] $DumpDirectory = $null
    )
    $TimeoutSeconds = Get-StepTimeout -Requested $TimeoutSeconds -What "$FilePath $ArgumentList"
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Command $FilePath -ErrorAction Stop).Source
    $start.WorkingDirectory = (Get-Location).Path
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    foreach ($argument in $ArgumentList) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw "Could not start $FilePath" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            if (-not $DumpDirectory) { $DumpDirectory = $env:SHIRUSU_DIAGNOSTIC_DIR }
            Save-ProcessTree -ProcessId $process.Id -Directory $DumpDirectory -Label "host"
            $process.Kill($true)
            $null = $process.WaitForExit(10000)
            throw "Native command timed out after ${TimeoutSeconds}s: $FilePath $ArgumentList"
        }
        $process.WaitForExit()
        $output = $stdout.GetAwaiter().GetResult()
        $global:LASTEXITCODE = $process.ExitCode
        return [pscustomobject]@{ Output = $output; ExitCode = $process.ExitCode }
    } finally { $process.Dispose() }
}
