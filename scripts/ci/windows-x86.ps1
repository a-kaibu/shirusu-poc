# Windows CI (windows-latest, x64 OS 上の WoW64): i686 テストバイナリをビルドし実行する。
# x86 Agent + x64 Host のプロセス間ストレステスト (e2e) は x64 側ジョブと対で実行する。
#
# 終了コードの伝播 (レビュー #4 の #3): windows.ps1 と同じく、ネイティブ
# コマンドは全て Invoke-Native 経由で実行する ($ErrorActionPreference
# だけでは非ゼロ終了が伝播しない)。
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
Set-Location (Join-Path $PSScriptRoot "..\..")
if ($env:GITHUB_ACTIONS -eq "true") {
    $env:SHIRUSU_DIAGNOSTIC_DIR = Join-Path (Get-Location) "target\ci-diagnostics"
    New-Item -ItemType Directory -Force -Path $env:SHIRUSU_DIAGNOSTIC_DIR | Out-Null
}
# カナリア: 失敗するネイティブコマンドがジョブを落とすこと自体を検証する。
Invoke-Native { pwsh -NoProfile -File (Join-Path $PSScriptRoot "canary-exit-code.ps1") } "exit-code canary"
Invoke-Native { rustup target add i686-pc-windows-msvc } "rustup target add i686"
Invoke-Native { cargo test -p shirusu-transport -p shirusu-transport-win -p shirusu-agent --target i686-pc-windows-msvc } "cargo test (transport/transport-win/agent, i686)"
# Phase 3: フックの単体テストと Agent DLL の x86 ビルド（同一ビットネス注入の前提）
Invoke-Native { cargo test -p shirusu-hook --target i686-pc-windows-msvc } "cargo test (hook, i686)"
Invoke-Native { cargo test -p shirusu-hook --release --target i686-pc-windows-msvc native_tls_vector_absence_bypasses_rust_tls_access } "native TLS availability (optimized, i686)"
Invoke-Native { cargo build -p shirusu-agent-dll --target i686-pc-windows-msvc } "agent dll build (i686)"
if ($env:GITHUB_ACTIONS -eq "true") {
    Copy-Item "target\i686-pc-windows-msvc\debug\shirusu_agent_dll.dll", "target\i686-pc-windows-msvc\debug\shirusu_agent_dll.pdb" -Destination $env:SHIRUSU_DIAGNOSTIC_DIR
}
# WoW64 transport tests alone do not execute an x86 injected tracer.
Invoke-Native { cargo build -p shirusu-e2e --target i686-pc-windows-msvc --bins } "capture targets build (i686)"
Invoke-Native { .\target\i686-pc-windows-msvc\debug\shirusu-capture-e2e.exe } "native capture (i686)"
Invoke-Native { .\target\i686-pc-windows-msvc\debug\shirusu-capture-e2e.exe --abi } "native capture ABI (i686)"
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
# L20: Probe exe 生成と JSON Runner の実動（i686）。x86 の Probe exe
# を生成・実行し、Runner でも同じ仕様を実行する。shirusu-test 本体は
# x64 でビルドしたものを使う（生成器自体はホストで動くため）。
Invoke-Native { cargo build -p shirusu-test --target x86_64-pc-windows-msvc } "shirusu-test build (x64, for L20)"
Invoke-Native { pwsh -NoProfile -File (Join-Path $PSScriptRoot "probe-l20.ps1") -Target i686-pc-windows-msvc } "probe-exe + runner (L20, i686)"
# A74: i686 (WoW64) での 64bit アトミック操作のコスト測定。32bit
# 折り返しカウンタへの切替判断はこの実測で行う (bench 内に基準を明記)。
Invoke-Native { cargo build -p shirusu-e2e --target i686-pc-windows-msvc --release --bin shirusu-atomic-bench } "atomic bench build (i686)"
Invoke-Native { .\target\i686-pc-windows-msvc\release\shirusu-atomic-bench.exe } "atomic bench (i686)"
# L10: 性能目標の測定 (x64 と同じ内容を WoW64 でも測る。測定器であり
# ゲートではないため終了コードは常に 0。CI 時間を抑えるため --rounds 1)。
Invoke-Native { cargo build -p shirusu-e2e --target i686-pc-windows-msvc --release --bin shirusu-perf-bench } "perf bench build (i686)"
Invoke-Native { .\target\i686-pc-windows-msvc\release\shirusu-perf-bench.exe --rounds 1 } "perf bench (i686)"

Invoke-Native { cargo build -p shirusu-cli --target i686-pc-windows-msvc } "CLI build (i686)"
Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "legacy-api.ps1"), "-Target", "i686-pc-windows-msvc")

Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "attach-rollback.ps1"), "-Target", "i686-pc-windows-msvc")
Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "thread-churn.ps1"), "-Target", "i686-pc-windows-msvc")

Invoke-NativeWithTimeout -FilePath pwsh -TimeoutSeconds 600 -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "native-performance.ps1"), "-Target", "i686-pc-windows-msvc")
