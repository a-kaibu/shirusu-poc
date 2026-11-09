# Windows CI (windows-latest, x64 OS 上の WoW64): i686 テストバイナリをビルドし実行する。
# x86 Agent + x64 Host のプロセス間ストレステスト (e2e) は x64 側ジョブと対で実行する。
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\..")
rustup target add i686-pc-windows-msvc
cargo test -p shirusu-transport -p shirusu-transport-win -p shirusu-agent --target i686-pc-windows-msvc
cargo build -p shirusu-e2e --target i686-pc-windows-msvc --bin shirusu-e2e-producer
cargo build -p shirusu-e2e --target x86_64-pc-windows-msvc --bin shirusu-e2e-supervisor
$env:SHIRUSU_E2E_PRODUCER = "$PWD\target\i686-pc-windows-msvc\debug\shirusu-e2e-producer.exe"
.\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe --cross-arch
