# Windows CI (windows-latest, x64 OS 上の WoW64): i686 テストバイナリをビルドし実行する。
# x86 Agent + x64 Host のプロセス間ストレステスト (e2e) は x64 側ジョブと対で実行する。
#
# 終了コードの伝播 (レビュー #4 の #3): windows.ps1 と同じく、ネイティブ
# コマンドは全て Invoke-Native 経由で実行する ($ErrorActionPreference
# だけでは非ゼロ終了が伝播しない)。
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
Set-Location (Join-Path $PSScriptRoot "..\..")
# カナリア: 失敗するネイティブコマンドがジョブを落とすこと自体を検証する。
Invoke-Native { pwsh -NoProfile -File (Join-Path $PSScriptRoot "canary-exit-code.ps1") } "exit-code canary"
Invoke-Native { rustup target add i686-pc-windows-msvc } "rustup target add i686"
Invoke-Native { cargo test -p shirusu-transport -p shirusu-transport-win -p shirusu-agent --target i686-pc-windows-msvc } "cargo test (transport/transport-win/agent, i686)"
# Phase 3: フックの単体テストと Agent DLL の x86 ビルド（同一ビットネス注入の前提）
Invoke-Native { cargo test -p shirusu-hook --target i686-pc-windows-msvc } "cargo test (hook, i686)"
Invoke-Native { cargo build -p shirusu-agent-dll --target i686-pc-windows-msvc } "agent dll build (i686)"
Invoke-Native { cargo build -p shirusu-e2e --target i686-pc-windows-msvc --bin shirusu-e2e-producer } "e2e producer build (i686)"
Invoke-Native { cargo build -p shirusu-e2e --target x86_64-pc-windows-msvc --bin shirusu-e2e-supervisor } "e2e supervisor build (x64)"
$env:SHIRUSU_E2E_PRODUCER = "$PWD\target\i686-pc-windows-msvc\debug\shirusu-e2e-producer.exe"
Invoke-Native { .\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe --cross-arch } "e2e supervisor --cross-arch"
# D77: 本番経路 (実 Agent::record → data_ready Event 待機 → 検証付き
# Host 回収 → Slot 再利用) を x64 Host × i686 Producer で実行する。
# x64 同士の組み合わせは windows-x64 ジョブの --all に含まれる。
Invoke-Native { .\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe --production-path } "e2e supervisor --production-path"
# A77: プロセス間メモリ順序ストレス (実 Agent が別プロセスから 100 万件を
# 順に書き、検証付き Host が順序・内容・欠落会計を検証) を x64 Host ×
# i686 Producer で実行する。x64 同士の組み合わせは windows-x64 ジョブの
# --all に含まれる。
Invoke-Native { .\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe --memory-order-stress } "e2e supervisor --memory-order-stress"
# A74: i686 (WoW64) での 64bit アトミック操作のコスト測定。32bit
# 折り返しカウンタへの切替判断はこの実測で行う (bench 内に基準を明記)。
Invoke-Native { cargo build -p shirusu-e2e --target i686-pc-windows-msvc --release --bin shirusu-atomic-bench } "atomic bench build (i686)"
Invoke-Native { .\target\i686-pc-windows-msvc\release\shirusu-atomic-bench.exe } "atomic bench (i686)"
# L10: 性能目標の測定 (x64 と同じ内容を WoW64 でも測る。測定器であり
# ゲートではないため終了コードは常に 0。CI 時間を抑えるため --rounds 1)。
Invoke-Native { cargo build -p shirusu-e2e --target i686-pc-windows-msvc --release --bin shirusu-perf-bench } "perf bench build (i686)"
Invoke-Native { .\target\i686-pc-windows-msvc\release\shirusu-perf-bench.exe --rounds 1 } "perf bench (i686)"
