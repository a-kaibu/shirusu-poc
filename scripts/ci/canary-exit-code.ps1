# 終了コード伝播のカナリア (レビュー #4 の #3)。
#
# 「失敗するネイティブコマンドを Invoke-Native 経由で実行すると、その
# スクリプトが失敗として終わる」ことを子プロセスで実際に確かめる。
# 伝播の仕掛けが壊れたら (例: $LASTEXITCODE を見ない実装へ戻ったら)
# 失敗側の子プロセスが成功してしまい、このカナリア自体が失敗する。
# つまり次回 CI で「テスト失敗をジョブが検出できる」こと自体を毎回
# 検証する。windows.ps1 / windows-x86.ps1 の先頭で実行する。
param([string] $Child = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")

if ($Child -eq "fail") {
    # 意図的に失敗するネイティブコマンド。伝播していれば Invoke-Native が
    # throw し、このプロセスは非ゼロで終わる (下の exit 0 には到達しない)。
    Invoke-Native { cmd /c exit 3 } "canary deliberate failure"
    exit 0
}
if ($Child -eq "ok") {
    # 対照: 成功するネイティブコマンドは通らなければならない。
    Invoke-Native { cmd /c exit 0 } "canary success case"
    exit 0
}

& pwsh -NoProfile -File $PSCommandPath -Child fail
if ($LASTEXITCODE -eq 0) {
    throw "canary: a failing native command did NOT fail the child script (exit-code propagation is broken)"
}
& pwsh -NoProfile -File $PSCommandPath -Child ok
if ($LASTEXITCODE -ne 0) {
    throw "canary: a successful native command failed the child script (exit code $LASTEXITCODE)"
}
Write-Host "canary ok: native exit codes propagate (failure fails the script, success passes)"
