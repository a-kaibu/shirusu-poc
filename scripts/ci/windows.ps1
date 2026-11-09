# Windows CI (windows-latest): x64 build/test + E2E supervisor 実行。
# 手元 Windows でも同じ手順を再現できる。
#
# 終了コードの伝播 (レビュー #4 の #3): $ErrorActionPreference = "Stop"
# だけではネイティブコマンドの非ゼロ終了は伝播せず、後続コマンドの
# 成功で上書きされてジョブが緑になる (run #4 で発生)。ネイティブ
# コマンドは全て Invoke-Native 経由で実行する。
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
Set-Location (Join-Path $PSScriptRoot "..\..")
# カナリア: 失敗するネイティブコマンドがジョブを落とすこと自体を検証する。
Invoke-Native { pwsh -NoProfile -File (Join-Path $PSScriptRoot "canary-exit-code.ps1") } "exit-code canary"
Invoke-Native { cargo test --workspace --target x86_64-pc-windows-msvc } "cargo test (workspace, x64)"
Invoke-Native { cargo build --workspace --target x86_64-pc-windows-msvc } "cargo build (workspace, x64)"
Invoke-Native { .\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe --all } "e2e supervisor --all"
# Phase 3: Agent DLL 注入＋フック記録の実 E2E（対象プロセスを起動して Trace を検証）
# D54: Application Verifier を対象プロセス (shirusu-hook-target) に併用する。
# appverif.exe が無い環境 (手元再現時など) では注記して従来どおり実行する。
# 検証違反は対象プロセスを例外で止めるため、capture-e2e 側の失敗として
# 検出される。設定は実行後に必ず解除する。
$appverif = $null
foreach ($candidate in @(
    "C:\Program Files (x86)\Windows Kits\10\App Certification Kit\appverif.exe",
    "C:\Program Files\Windows Kits\10\App Certification Kit\appverif.exe"
)) {
    if (Test-Path $candidate) { $appverif = $candidate; break }
}
if (-not $appverif) {
    $cmd = Get-Command appverif.exe -ErrorAction SilentlyContinue
    if ($cmd) { $appverif = $cmd.Source }
}
if ($appverif) {
    Write-Host "D54: enabling Application Verifier for shirusu-hook-target.exe ($appverif)"
    & $appverif -enable Heaps Handles Locks -for shirusu-hook-target.exe | Out-Host
    try {
        Invoke-Native { .\target\x86_64-pc-windows-msvc\debug\shirusu-capture-e2e.exe } "capture-e2e (with Application Verifier)"
    } finally {
        & $appverif -delete settings -for shirusu-hook-target.exe | Out-Host
        & $appverif -delete logs -for shirusu-hook-target.exe | Out-Host
    }
} else {
    Write-Host "D54: appverif.exe not found; running capture-e2e without Application Verifier"
    Invoke-Native { .\target\x86_64-pc-windows-msvc\debug\shirusu-capture-e2e.exe } "capture-e2e"
}
# A74: 64bit アトミック操作のコスト測定 (x64 側の対照値。判断は i686 側の実測で行う)
Invoke-Native { cargo build -p shirusu-e2e --target x86_64-pc-windows-msvc --release --bin shirusu-atomic-bench } "atomic bench build (x64)"
Invoke-Native { .\target\x86_64-pc-windows-msvc\release\shirusu-atomic-bench.exe } "atomic bench (x64)"
