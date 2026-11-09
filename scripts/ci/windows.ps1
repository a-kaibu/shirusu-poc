# Windows CI (windows-latest): x64 build/test + E2E supervisor 実行。
# 手元 Windows でも同じ手順を再現できる。
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\..")
cargo test --workspace --target x86_64-pc-windows-msvc
cargo build --workspace --target x86_64-pc-windows-msvc
.\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe --all
