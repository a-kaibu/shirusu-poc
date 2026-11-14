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

# Bound native fixtures so one hung target cannot suppress later scenarios.
# ArgumentList preserves paths with spaces without a second shell parse.
function Invoke-NativeWithTimeout {
    param(
        [Parameter(Mandatory = $true)] [string] $FilePath,
        [string[]] $ArgumentList = @(),
        [int] $TimeoutSeconds = 180
    )
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
            $process.Kill($true)
            $null = $process.WaitForExit(10000)
            throw "Native fixture timed out after ${TimeoutSeconds}s: $FilePath $ArgumentList"
        }
        $global:LASTEXITCODE = $process.ExitCode
        if ($process.ExitCode -ne 0) {
            throw "Native fixture failed with exit code $($process.ExitCode): $FilePath $ArgumentList"
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
            if ($DumpDirectory) {
                Save-ProcessDump -ProcessId $process.Id -Directory $DumpDirectory -Label "host"
                Get-CimInstance Win32_Process -Filter "ParentProcessId=$($process.Id)" -ErrorAction SilentlyContinue |
                    ForEach-Object { Save-ProcessDump -ProcessId $_.ProcessId -Directory $DumpDirectory -Label "child" }
            }
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
