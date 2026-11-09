# Windows CI (windows-latest, x64 OS 上の WoW64): i686 テストバイナリをビルドし実行する。
# x86 Agent + x64 Host のプロセス間ストレステスト (e2e) は x64 側ジョブと対で実行する。
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\..")
rustup target add i686-pc-windows-msvc
cargo test -p shirusu-transport -p shirusu-transport-win -p shirusu-agent --target i686-pc-windows-msvc
# Phase 3: フックの単体テストと Agent DLL の x86 ビルド（同一ビットネス注入の前提）
cargo test -p shirusu-hook --target i686-pc-windows-msvc
cargo build -p shirusu-agent-dll --target i686-pc-windows-msvc
cargo build -p shirusu-e2e --target i686-pc-windows-msvc --bin shirusu-e2e-producer
cargo build -p shirusu-e2e --target x86_64-pc-windows-msvc --bin shirusu-e2e-supervisor
$env:SHIRUSU_E2E_PRODUCER = "$PWD\target\i686-pc-windows-msvc\debug\shirusu-e2e-producer.exe"
.\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe --cross-arch
# D77: 本番経路 (実 Agent::record → data_ready Event 待機 → 検証付き
# Host 回収 → Slot 再利用) を x64 Host × i686 Producer で実行する。
# x64 同士の組み合わせは windows-x64 ジョブの --all に含まれる。
.\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe --production-path
# A74: i686 (WoW64) での 64bit アトミック操作のコスト測定。32bit
# 折り返しカウンタへの切替判断はこの実測で行う (bench 内に基準を明記)。
cargo build -p shirusu-e2e --target i686-pc-windows-msvc --release --bin shirusu-atomic-bench
.\target\i686-pc-windows-msvc\release\shirusu-atomic-bench.exe
