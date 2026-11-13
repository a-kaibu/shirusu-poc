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
# Run independent capture scenarios even after one fails, then fail the suite.
# A failed child-tree scenario must not hide ABI, callback, or replay failures.
$captureFailures = [System.Collections.Generic.List[string]]::new()
function Invoke-CaptureScenario {
    param([scriptblock]$Command, [string]$What)
    try { Invoke-Native $Command $What }
    catch {
        $captureFailures.Add("${What}: $_")
        Write-Warning "Capture scenario failed; continuing independent checks: $What"
    }
}
# A native AV may have no Application Verifier stop entry. On disposable
# GHA runners preserve its exception context and module/stack information.
$dumpKey = $null
if ($env:GITHUB_ACTIONS -eq "true") {
    $diagnostics = Join-Path (Get-Location) "target\ci-diagnostics"
    New-Item -ItemType Directory -Force -Path $diagnostics | Out-Null
    $env:SHIRUSU_DIAGNOSTIC_DIR = $diagnostics
    $dumpKey = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\shirusu-hook-target.exe"
    New-Item -Path $dumpKey -Force | Out-Null
    New-ItemProperty -Path $dumpKey -Name DumpFolder -PropertyType ExpandString -Value $diagnostics -Force | Out-Null
    New-ItemProperty -Path $dumpKey -Name DumpType -PropertyType DWord -Value 2 -Force | Out-Null
    New-ItemProperty -Path $dumpKey -Name DumpCount -PropertyType DWord -Value 2 -Force | Out-Null
}
$captureStarted = Get-Date
$ciComplete = $false
try {
    # カナリア: 失敗するネイティブコマンドがジョブを落とすこと自体を検証する。
    Invoke-Native { pwsh -NoProfile -File (Join-Path $PSScriptRoot "canary-exit-code.ps1") } "exit-code canary"
    Invoke-Native { cargo test --workspace --no-fail-fast --target x86_64-pc-windows-msvc } "cargo test (workspace, x64)"
    Invoke-Native { cargo test -p shirusu-hook --release --target x86_64-pc-windows-msvc native_tls_vector_absence_bypasses_rust_tls_access } "native TLS availability (optimized, x64)"
    Invoke-Native { cargo build --workspace --target x86_64-pc-windows-msvc } "cargo build (workspace, x64)"
    # L20: Probe exe 生成と JSON Runner の実動（サンプル仕様から x64 の
    # Probe exe を生成・実行し、Runner でも同じ仕様を実行する）。
    Invoke-CaptureScenario { pwsh -NoProfile -File (Join-Path $PSScriptRoot "probe-l20.ps1") -Target x86_64-pc-windows-msvc } "probe-exe + runner (L20, x64)"
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
            Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath .\target\x86_64-pc-windows-msvc\debug\shirusu-capture-e2e.exe } "capture-e2e (with Application Verifier)"
        } finally {
            # Export before deleting settings/logs, including when capture-e2e fails.
            # Keep diagnostic failures from replacing the original test failure.
            try {
                $diagnostics = Join-Path (Get-Location) "target\ci-diagnostics"
                New-Item -ItemType Directory -Force -Path $diagnostics | Out-Null
                & $appverif -export log -for shirusu-hook-target.exe -with "To=$diagnostics\appverifier.xml" | Out-Host
            } catch {
                Write-Warning "Could not preserve capture diagnostics: $_"
            } finally {
                & $appverif -delete settings -for shirusu-hook-target.exe | Out-Host
                & $appverif -delete logs -for shirusu-hook-target.exe | Out-Host
            }
        }
    } else {
        Write-Host "D54: appverif.exe not found; running capture-e2e without Application Verifier"
        Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath .\target\x86_64-pc-windows-msvc\debug\shirusu-capture-e2e.exe } "capture-e2e"
    }
    # L05: 子プロセス追跡の E2E（対象が子プロセスを起動し、子の Trace が
    # 別ファイルに記録されることを検証する）。
    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath .\target\x86_64-pc-windows-msvc\debug\shirusu-capture-e2e.exe -ArgumentList @("--child-tree") } "capture-e2e --child-tree"
    # L06: ABI 適合性テスト（浮動小数点引数・構造体の戻り値・コールバック・
    # 例外・LastError の Probe を Hook ありとなしで実行して結果を比べる）。
    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath .\target\x86_64-pc-windows-msvc\debug\shirusu-capture-e2e.exe -ArgumentList @("--abi") } "capture-e2e --abi"
    # L17: 検証用アプリ 3 種（コンソール / GUI / COM）の E2E。Hook なしと Hook ありで
    # アプリの観測結果が同じことと、ファイル I/O が Trace に記録されることを検証する。
    # レジストリ・USER32・GDI・DIB・COM の未記録分はカバレッジ評価として報告される。
    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath .\target\x86_64-pc-windows-msvc\debug\shirusu-capture-e2e.exe -ArgumentList @("--verify-apps") } "capture-e2e --verify-apps"
    # L01: Inline Hook の E2E（GetProcAddress 経由の呼び出しが Trace に
    # 記録されることと、生成 API の Inline Hook を検証する）。
    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath .\target\x86_64-pc-windows-msvc\debug\shirusu-capture-e2e.exe -ArgumentList @("--inline") } "capture-e2e --inline"
    # L23: モジュール列挙・署名検証・API Set 解決・フック時呼び出し元分類の E2E。
    # Trace の Environment.modules に列挙・分類されたモジュールが載ることと、
    # 直接呼び出しのファイル I/O が記録されることを検証する（record_runtime_apis の
    # on/off 両方）。CRT 経由の呼び出しは L01 の Inline Hook で Detour に届き、
    # 既定でも Windows API 呼び出しが記録されることを検証する。
    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath .\target\x86_64-pc-windows-msvc\debug\shirusu-capture-e2e.exe -ArgumentList @("--modules") } "capture-e2e --modules"
    # A74: 64bit アトミック操作のコスト測定 (x64 側の対照値。判断は i686 側の実測で行う)
    Invoke-Native { cargo build -p shirusu-e2e --target x86_64-pc-windows-msvc --release --bin shirusu-atomic-bench } "atomic bench build (x64)"
    Invoke-Native { .\target\x86_64-pc-windows-msvc\release\shirusu-atomic-bench.exe } "atomic bench (x64)"
    # L10: モデル性能の測定 (実注入の測定は native-performance.ps1)。API 追加遅延・
    # スループット・バッファ使用率)。測定器でありゲートではないため終了コードは
    # 常に 0。判定の読み取りはログで行う。CI 時間を抑えるため --rounds 1。
    Invoke-Native { cargo build -p shirusu-e2e --target x86_64-pc-windows-msvc --release --bin shirusu-perf-bench } "perf bench build (x64)"
    Invoke-CaptureScenario { .\target\x86_64-pc-windows-msvc\release\shirusu-perf-bench.exe --rounds 1 } "perf bench (x64)"

    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "exception-transparency.ps1")) } "native SEH transparency"
    # Actual captured file I/O must produce an executable replay, not only a rule.
    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "replay-e2e.ps1")) } "native capture-to-replay"

    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "legacy-api.ps1")) } "native ANSI and file API coverage"

    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "attach-rollback.ps1")) } "native attach rollback and reattach"
    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "thread-churn.ps1")) } "native thread creation during attach"

    Invoke-CaptureScenario { Invoke-NativeWithTimeout -FilePath pwsh -TimeoutSeconds 600 -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "native-performance.ps1")) } "native injected performance"

    if ($captureFailures.Count -gt 0) {
        throw ("Windows scenarios failed:`n" + ($captureFailures -join "`n"))
    }
    Invoke-NativeWithTimeout -FilePath pwsh -ArgumentList @("-NoProfile", "-File", (Join-Path $PSScriptRoot "corpus-record.ps1"))
    $ciComplete = $true
} finally {
    try {
        $diagnostics = Join-Path (Get-Location) "target\ci-diagnostics"
        New-Item -ItemType Directory -Force -Path $diagnostics | Out-Null
        foreach ($pattern in @("shirusu-capture-e2e-*.trace", "shirusu-verify-*.trace", "shirusu-modules-*.trace")) {
            Get-ChildItem ([System.IO.Path]::GetTempPath()) -Filter $pattern |
                Copy-Item -Destination $diagnostics -ErrorAction Continue
        }
        Get-ChildItem target -Directory | Where-Object { $_.Name -eq "native-exception" -or $_.Name -like "native-replay-*" } |
            Get-ChildItem -Recurse -File |
            Where-Object { $_.Extension -in @(".trace", ".json", ".txt") } |
            ForEach-Object { Copy-Item $_.FullName (Join-Path $diagnostics ($_.Directory.Name + "-" + $_.Name)) -ErrorAction Continue }
        if (-not $ciComplete) {
            # WER can be disabled on hosted runners. Event 1000 still often
            # identifies the faulting module and offset; retain matching
            # symbols so a dump/offset from this build can be diagnosed.
            Get-WinEvent -FilterHashtable @{ LogName = "Application"; StartTime = $captureStarted; Id = 1000, 1001 } -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Id, ProviderName, Message |
                ConvertTo-Json -Depth 4 | Set-Content (Join-Path $diagnostics "application-errors.json")
            Get-ChildItem "target\x86_64-pc-windows-msvc\debug" -File |
                Where-Object { $_.Name -in @("shirusu_agent_dll.dll", "shirusu_agent_dll.pdb", "shirusu-hook-target.exe", "shirusu_hook_target.pdb") } |
                Copy-Item -Destination $diagnostics -ErrorAction Continue
        }
    } catch {
        Write-Warning "Could not preserve suite diagnostics: $_"
    } finally {
        if ($dumpKey) { Remove-Item $dumpKey -Force -ErrorAction Continue }
    }
}
