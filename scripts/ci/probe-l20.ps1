# L20: Probe exe 生成と JSON Runner の Windows 実動確認。
# サンプル仕様 (crates/shirusu-test/tests/data/probe-sample.json) から
# 指定ターゲットの Probe exe を生成し、exe と Runner (shirusu-test run)
# の両方を実行する。書き戻した内容 ("hello shirusu\n") が読めたことを
# 両方の JSON 報告で確認する。作業は一時ディレクトリで行い、後始末する。
#
# 呼び出し元: scripts/ci/windows.ps1 (x86_64-pc-windows-msvc)、
# scripts/ci/windows-x86.ps1 (i686-pc-windows-msvc)。
# 終了コードの伝播: ネイティブコマンドの失敗は $LASTEXITCODE を見て
# throw する (windows.ps1 の Invoke-Native と同じ方針)。
param(
    [Parameter(Mandatory = $true)][string]$Target
)
$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$testExe = Join-Path $repoRoot "target\x86_64-pc-windows-msvc\debug\shirusu-test.exe"
$spec = Join-Path $repoRoot "crates\shirusu-test\tests\data\probe-sample.json"
$work = Join-Path $env:TEMP "shirusu-probe-l20"
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force $work | Out-Null
try {
    Copy-Item $spec (Join-Path $work "probe-sample.json")
    Push-Location $work
    try {
        $exe = Join-Path $work "probe.exe"
        & $testExe probe-exe probe-sample.json --target $Target --out $exe
        if ($LASTEXITCODE -ne 0) { throw "probe-exe build ($Target) failed (exit code $LASTEXITCODE)" }
        if (-not (Test-Path $exe)) { throw "probe exe was not created: $exe" }
        & $exe > probe-report.json
        if ($LASTEXITCODE -ne 0) { throw "probe exe ($Target) failed (exit code $LASTEXITCODE)" }
        $report = Get-Content probe-report.json -Raw
        if ($report -notmatch '"all_ok"\s*:\s*true') { throw "probe exe report is not all_ok: $report" }
        if ($report -notmatch '68656c6c6f20736869727573750a') { throw "probe exe report lacks the read-back bytes (hello shirusu)" }
        & $testExe run probe-sample.json --json > runner-report.json
        if ($LASTEXITCODE -ne 0) { throw "shirusu-test run ($Target) failed (exit code $LASTEXITCODE)" }
        $runner = Get-Content runner-report.json -Raw
        if ($runner -notmatch '"all_ok"\s*:\s*true') { throw "runner report is not all_ok: $runner" }
        if ($runner -notmatch '68656c6c6f20736869727573750a') { throw "runner report lacks the read-back bytes (hello shirusu)" }
        Write-Host "L20: probe exe + runner OK ($Target)"
    } finally {
        Pop-Location
    }
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
