# Windows CI (windows-latest, x64 OS 上の WoW64): i686 テストバイナリをビルドし実行する。
# x86 Agent + x64 Host のプロセス間ストレステスト (e2e) は x64 側ジョブと対で実行する。
#
# 終了コードの伝播 (レビュー #4 の #3): windows.ps1 と同じく、ネイティブ
# コマンドは全て Invoke-Native 経由で実行する ($ErrorActionPreference
# だけでは非ゼロ終了が伝播しない)。
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
Set-Location (Join-Path $PSScriptRoot "..\..")
# V11: every step is timed, the suite stops itself before the job's 60-minute
# timeout, and the finally preserves diagnostics (traces, crash events, the
# DLL and its symbols) whichever step failed or hung.
Start-CiDeadline -Seconds 3120
$diagnostics = Join-Path (Get-Location) "target\ci-diagnostics"
New-Item -ItemType Directory -Force -Path $diagnostics | Out-Null
$env:SHIRUSU_DIAGNOSTIC_DIR = $diagnostics
$suiteStarted = Get-Date
$suiteComplete = $false
try {
    # カナリア: 失敗するネイティブコマンドがジョブを落とすこと自体を検証する。
    Invoke-Native { pwsh -NoProfile -File (Join-Path $PSScriptRoot "canary-exit-code.ps1") } "exit-code canary"
    Invoke-NativeWithTimeout -What "rustup target add i686" -TimeoutSeconds 300 -FilePath rustup -ArgumentList @("target", "add", "i686-pc-windows-msvc")
    Invoke-NativeWithTimeout -What "cargo test (transport/transport-win/agent, i686)" -TimeoutSeconds 1800 -FilePath cargo -ArgumentList @("test", "-p", "shirusu-transport", "-p", "shirusu-transport-win", "-p", "shirusu-agent", "--target", "i686-pc-windows-msvc")
    # Phase 3: フックの単体テストと Agent DLL の x86 ビルド（同一ビットネス注入の前提）
    Invoke-NativeWithTimeout -What "cargo test (hook, i686)" -TimeoutSeconds 1800 -FilePath cargo -ArgumentList @("test", "-p", "shirusu-hook", "--target", "i686-pc-windows-msvc")
    Invoke-NativeWithTimeout -What "native TLS availability (optimized, i686)" -TimeoutSeconds 1800 -FilePath cargo -ArgumentList @("test", "-p", "shirusu-hook", "--release", "--target", "i686-pc-windows-msvc", "native_tls_vector_absence_bypasses_rust_tls_access")
    # Review P1: asymmetric handshakes under the real Windows fences, optimized.
    $env:SHIRUSU_STRESS_CYCLES = "400"
    Invoke-NativeWithTimeout -What "record/shutdown/reattach stress (optimized, i686)" -TimeoutSeconds 1800 -FilePath cargo -ArgumentList @("test", "-p", "shirusu-hook", "--release", "--target", "i686-pc-windows-msvc", "--lib", "record_shutdown_reattach_stress")
    Remove-Item Env:SHIRUSU_STRESS_CYCLES
    Invoke-NativeWithTimeout -What "writer cell handshake (optimized, i686)" -TimeoutSeconds 1800 -FilePath cargo -ArgumentList @("test", "-p", "shirusu-agent", "--release", "--target", "i686-pc-windows-msvc", "--lib", "writer_cell")
    Invoke-NativeWithTimeout -What "agent dll build (i686)" -TimeoutSeconds 1200 -FilePath cargo -ArgumentList @("build", "-p", "shirusu-agent-dll", "--target", "i686-pc-windows-msvc")
    if ($env:GITHUB_ACTIONS -eq "true") {
        Copy-Item "target\i686-pc-windows-msvc\debug\shirusu_agent_dll.dll", "target\i686-pc-windows-msvc\debug\shirusu_agent_dll.pdb" -Destination $diagnostics
    }
    # WoW64 transport tests alone do not execute an x86 injected tracer.
    Invoke-NativeWithTimeout -What "capture targets build (i686)" -TimeoutSeconds 1200 -FilePath cargo -ArgumentList @("build", "-p", "shirusu-e2e", "--target", "i686-pc-windows-msvc", "--bins")
    Invoke-NativeWithTimeout -What "native capture (i686)" -TimeoutSeconds 600 -FilePath .\target\i686-pc-windows-msvc\debug\shirusu-capture-e2e.exe
    Invoke-NativeWithTimeout -What "native capture ABI (i686)" -TimeoutSeconds 600 -FilePath .\target\i686-pc-windows-msvc\debug\shirusu-capture-e2e.exe -ArgumentList @("--abi")
    Invoke-NativeWithTimeout -What "e2e producer build (i686)" -TimeoutSeconds 1200 -FilePath cargo -ArgumentList @("build", "-p", "shirusu-e2e", "--target", "i686-pc-windows-msvc", "--bin", "shirusu-e2e-producer")
    Invoke-NativeWithTimeout -What "e2e supervisor build (x64)" -TimeoutSeconds 1200 -FilePath cargo -ArgumentList @("build", "-p", "shirusu-e2e", "--target", "x86_64-pc-windows-msvc", "--bin", "shirusu-e2e-supervisor")
    $env:SHIRUSU_E2E_PRODUCER = "$PWD\target\i686-pc-windows-msvc\debug\shirusu-e2e-producer.exe"
    Invoke-NativeWithTimeout -What "e2e supervisor --cross-arch" -TimeoutSeconds 600 -FilePath .\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe -ArgumentList @("--cross-arch")
    # D77: 本番経路 (実 Agent::record → data_ready Event 待機 → 検証付き
    # Host 回収 → Slot 再利用) を x64 Host × i686 Producer で実行する。
    # x64 同士の組み合わせは windows-x64 ジョブの --all に含まれる。
    Invoke-NativeWithTimeout -What "e2e supervisor --production-path" -TimeoutSeconds 600 -FilePath .\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe -ArgumentList @("--production-path")
    # A77: プロセス間メモリ順序ストレス (実 Agent が別プロセスから 100 万件を
    # 順に書き、検証付き Host が順序・内容・欠落会計を検証) を x64 Host ×
    # i686 Producer で実行する。x64 同士の組み合わせは windows-x64 ジョブの
    # --all に含まれる。
    Invoke-NativeWithTimeout -What "e2e supervisor --memory-order-stress" -TimeoutSeconds 600 -FilePath .\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe -ArgumentList @("--memory-order-stress")
    # L20: Probe exe 生成と JSON Runner の実動（i686）。x86 の Probe exe
    # を生成・実行し、Runner でも同じ仕様を実行する。shirusu-test 本体は
    # x64 でビルドしたものを使う（生成器自体はホストで動くため）。
    Invoke-NativeWithTimeout -What "shirusu-test build (x64, for L20)" -TimeoutSeconds 1200 -FilePath cargo -ArgumentList @("build", "-p", "shirusu-test", "--target", "x86_64-pc-windows-msvc")
    Invoke-NativeWithTimeout -What "probe-exe + runner (L20, i686)" -TimeoutSeconds 600 -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "probe-l20.ps1"), "-Target", "i686-pc-windows-msvc")
    # A74: i686 (WoW64) での 64bit アトミック操作のコスト測定。32bit
    # 折り返しカウンタへの切替判断はこの実測で行う (bench 内に基準を明記)。
    Invoke-NativeWithTimeout -What "atomic bench build (i686)" -TimeoutSeconds 1200 -FilePath cargo -ArgumentList @("build", "-p", "shirusu-e2e", "--target", "i686-pc-windows-msvc", "--release", "--bin", "shirusu-atomic-bench")
    Invoke-NativeWithTimeout -What "atomic bench (i686)" -TimeoutSeconds 600 -FilePath .\target\i686-pc-windows-msvc\release\shirusu-atomic-bench.exe
    # L10: 性能目標の測定 (x64 と同じ内容を WoW64 でも測る。測定器であり
    # ゲートではないため終了コードは常に 0。CI 時間を抑えるため --rounds 1)。
    Invoke-NativeWithTimeout -What "perf bench build (i686)" -TimeoutSeconds 1200 -FilePath cargo -ArgumentList @("build", "-p", "shirusu-e2e", "--target", "i686-pc-windows-msvc", "--release", "--bin", "shirusu-perf-bench")
    Invoke-NativeWithTimeout -What "perf bench (i686)" -TimeoutSeconds 600 -FilePath .\target\i686-pc-windows-msvc\release\shirusu-perf-bench.exe -ArgumentList @("--rounds", "1")

    Invoke-NativeWithTimeout -What "CLI build (i686)" -TimeoutSeconds 1200 -FilePath cargo -ArgumentList @("build", "-p", "shirusu-cli", "--target", "i686-pc-windows-msvc")
    Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "legacy-api.ps1"), "-Target", "i686-pc-windows-msvc")

    Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "attach-rollback.ps1"), "-Target", "i686-pc-windows-msvc")
    Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "thread-churn.ps1"), "-Target", "i686-pc-windows-msvc")
    Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "terminate-writer.ps1"), "-Target", "i686-pc-windows-msvc") -TimeoutSeconds 900

    Invoke-NativeWithTimeout -FilePath pwsh -TimeoutSeconds 600 -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "native-performance.ps1"), "-Target", "i686-pc-windows-msvc")
    Invoke-NativeWithTimeout -FilePath pwsh -TimeoutSeconds 900 -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "sustained-load.ps1"), "-Target", "i686-pc-windows-msvc")

    Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "corpus-record.ps1"), "-Target", "i686-pc-windows-msvc")
    $suiteComplete = $true
} finally {
    if (-not $suiteComplete) {
        try {
            foreach ($pattern in @("shirusu-capture-e2e-*.trace", "shirusu-verify-*.trace", "shirusu-modules-*.trace")) {
                Get-ChildItem ([System.IO.Path]::GetTempPath()) -Filter $pattern -ErrorAction SilentlyContinue |
                    Copy-Item -Destination $diagnostics -ErrorAction Continue
            }
            Get-WinEvent -FilterHashtable @{ LogName = "Application"; StartTime = $suiteStarted; Id = 1000, 1001, 1002 } -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Id, ProviderName, Message |
                ConvertTo-Json -Depth 4 | Set-Content (Join-Path $diagnostics "application-errors.json")
            foreach ($dir in @("target\i686-pc-windows-msvc\debug", "target\x86_64-pc-windows-msvc\debug")) {
                Get-ChildItem $dir -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -in @("shirusu_agent_dll.dll", "shirusu_agent_dll.pdb", "shirusu-hook-target.exe", "shirusu_hook_target.pdb", "shirusu-e2e-supervisor.exe", "shirusu_e2e_supervisor.pdb") } |
                    ForEach-Object { Copy-Item $_.FullName (Join-Path $diagnostics ((Split-Path $dir -Parent | Split-Path -Leaf) + "-" + $_.Name)) -ErrorAction Continue }
            }
        } catch {
            Write-Warning "Could not preserve suite diagnostics: $_"
        }
    }
}
