# 当初構想に対する完成条件

要件の正は `overview.md`（2026-11-08）。2026-11-13 に現行実装と照合した。
過去の実装件数、IID の名前件数、静的カバレッジを機能の完成率に読み替えない。

| 要件 | 現状と残件 | 合格に必要な証拠 |
| --- | --- | --- |
| Runtime → Windows の標準記録 | 呼び出し元 Runtime の除外を廃止し、呼び出し先 Runtime の設定へ修正。共通 kernelbase 実装まで thunk を解決。x64 2 環境の CRT E2E 通過 | `--modules` E2E が既定／設定有効の両方で CRT 経由 CreateFileW を記録 |
| 標準の呼び出し境界 | Nt は詳細モードに分離。公開 Windows API 同士の内部呼び出しは caller address による境界判定が未実装 | Application / Runtime 起点の記録と Windows 内部起点の除外、callback 内の再開を実走で比較 |
| LastError の透明性 | x86/x64 の TEB を直接読み書きする実装へ変更 | Windows API との往復、スレッド別値、Hook 有無の比較 |
| 全 Win32 の L0/L1 | 現在197件。system/C の型付き Wrapper に対応。選択表外の API、可変長引数、複合構造体の値渡しが不足 | Metadata 全体の分類と未対応理由、対応 ABI 別のネイティブ往復 |
| 高頻度 API を暗黙に除外しない full | GetLastError/SetLastError を選択表へ追加。短すぎる関数の Inline Hook は不足理由を残して拒否 | 再入なしの記録、短い関数への Inline Hook の透過性 |
| COM の L1 と寿命追跡 | Factory と IID 名識別は実装。共有オブジェクトの通常メソッド追跡は未完成 | 共有オブジェクトの並行呼び出し、QI、AddRef/Release、既存ポインタ同一性を壊さない実機テスト |
| 動的 API と既存プロセス Attach | Inline Hook は実装。新規スレッド競合・停止先ロックの制約が残る | 既存プロセスとスレッド生成中の透明性テスト、失敗時の安全な復元 |
| 子プロセス／スレッド寿命 | PID の同一性検証と thread-exit queue を追加 | 再利用、短命スレッド、ファイバー削除、再 Attach の実機テスト |
| L2/L3 の意味情報 | ファイル等の手書き対応。全 API の出力・資源意味は未対応 | SAL と手書き意味定義、引数／出力／資源の対応検査 |
| Parquet 出力 | 型付きの検索用列と JSONL 互換のイベント内容、完全性メタデータを実装 | 境界値・NULL・空ファイル・複数 row group の回帰テスト、DuckDB での読み込み |
| 公開 Trace、解析、修復 | Writer/Reader/CLI、復旧と不正入力検査を実装 | 形式適合性・破損復旧・Linux/macOS の解析 CI |
| 比較と再実行可能な Probe | オブジェクト相関と同期ファイル I/O 再生を実装。一般 API、非同期、コールバックは未対応 | Windows Capture → 差分 → Probe 実行の E2E、不足条件を拒否するテスト |
| 性能と完全性 | ベンチマーク・損失通知を実装 | GUI 3倍／高負荷5倍を同一条件で測定し、未達時は数値と原因を記録 |
| Windows x86/x64 の検証 | ローカル compile と CI を分離。`e7e2fc2` で x86 Capture / ABI と x64 2 環境の全 CI シナリオ通過 | Windows 実行・Application Verifier・ABI・SEH・replay の通過 |

優先順は観測境界と透明性、Windows 実走の失敗解消、Metadata 全体の
対応拡大、安全な COM Adapter、再生可能範囲の拡大。並行する CI を待つだけで
開発を止めない。ARM64、値のすり替え、ETW 等は overview で次段階／未決とされた
項目として別に残し、x86/x64 の未完成をそれらで覆い隠さない。

## Windows 実行の追跡

最新の検証は `e7e2fc2` の [run `43281728421`](https://github.com/a-kaibu/shirusu-poc/actions/runs/43281728421)。
Windows latest / Server 2022 の x64 で基本 Capture + Application Verifier、
child-tree、ABI、GUI / COM / WinRT、詳細 Nt、Inline、CRT、native SEH、
Capture → 差分 → Probe 再実行が通過した。x86 の実注入 Capture / ABI、
native SEH の所有権回収、debug / release の TLS 回帰テストも通過。
これは上表の全 Win32 対応、共有 COM メソッド追跡、実アプリ性能目標の完成を
意味しない。以下は原因と修正を追えるよう残した過去の検証記録。

`d8b6e11` の CI run `43260941181` は Windows x86 が通過。
Windows Server 2022 は Verifier 有効時に対象が `0xC0000005` で終了。
保存 Trace は注入用スレッドの ExitThread と HeapSize までで、Verifier XML に
違反の記録はない。短い関数の後ろまでパッチする危険を独立した回帰テストで
修正し、次回は WER ミニダンプも保存する。これをクラッシュ解消の証拠とは扱わず、
新しい CI と例外位置で確認する。

## WinMD 全体の API 棚卸し

`bash scripts/ci/fetch-winmd.sh` の後、以下で固定版 Metadata の全 Apis
メソッドを TSV に出す。Wrapper の生成物は変更しない。

```sh
cargo run -p shirusu-metadata-gen -- --inventory target/api-inventory.tsv
```

`--check` を追加すると保存済み TSV との一致を検査する。
列は namespace / module / function / status / reason。
`selected` は生成表の対象、`generatable` は型の変換が可能だが生成表の対象外、
`excluded` は設定による除外、`unsupported` は理由付きの未対応。
手書き API も生成表の対象外なので `generatable` に含まれる場合がある。
これはネイティブで記録できた API 数ではない。

現在の 18,364 メソッドは selected 184、generatable 17,444、unsupported 736。
C 呼び出し規約の Wrapper は元関数にも `C-unwind` を使い、x86 でのスタックの
後始末を保持する。LDAP 3 API と LastError 2 API の追加は ABI 回帰テスト付き。
可変長引数と複合構造体などの残件を、この一覧で追跡する。

GlobalFree / LocalFree も生成対象へ追加。NULL が成功となる解放 API の
LastError 条件を Schema に追加し、成功時の残留値をエラーとして扱わない。

単一フィールドの構造体を無条件にスカラーへ変換しない。NativeTypedef 属性で
別名型だと確認できるものだけを変換し、実構造体／未確認の別名型は未対応理由を残す。
この保守的な判定で、生成可能と分類していた 322 メソッドを未対応へ修正した。

`7d4ca21` の run `43266202012` では x86 が通過。x64 は Windows latest /
Server 2022 の基本 Capture + Verifier が正常終了まで通過した。次の
`--child-tree` はルートの注入初期化が `0xC0000005` で失敗する。
初回 Verifier だけでなく後続 E2E の失敗にもダンプ、Trace、イベントログ、
対応する DLL/EXE と PDB を保存するよう診断の範囲を広げた。

CI の `SHIRUSU_DIAGNOSTIC_DIR` 指定時は、Agent の初期化前に 4 KiB の
ファイルマッピングと vectored exception handler を準備する。最初の AV の
例外位置・アクセス先・整数レジスタを固定長 u64 列へ書き、例外は処理せず
継続検索する。handler は確保・ロック・ファイル I/O を行わない。
通常実行では有効にしない。診断を有効にしたプロセスでは view と handler を
プロセス終了まで保持し、ロード済みモジュール範囲も別 TSV に保存する。

短い x64 関数への中継は、近傍に確保した relay へ 5 バイトで分岐する。
relay と元関数の trampoline は同じ確保領域に置き、既存の保持上限と寿命を
共有する。再設置時は relay 経由の既存パッチも認識する。5 バイト未満や
近傍確保失敗は引き続き見送り、隣接コードを上書きして成功扱いにしない。

`9d19318` の run `43274704982` で x86 の実注入 Capture と ABI E2E、
RoGetActivationFactory の 3 引数転送、debug / release の native TLS
欠落回帰テストが通過した。以前の WoW64 transport 検証と区別する。
x64 は独立シナリオを最後まで実行してから失敗を集約するよう変更し、
先行ケースの失敗で WinRT・callback・SEH・replay の問題を隠さない。

## ANSI / ファイル API の拡張

従来の Unicode 中心の選択表に 41 API を追加し、合計 190 API とした。
CreateFileA、ANSI レジストリ、A/W のファイル列挙・パス変換・ディスク情報を
含む。既存 ID は変更せず 150〜190 を追加した。これは L1 の型付きの引数・
戻り値の記録であり、ANSI 文字列や出力構造体の L2 復元を意味しない。
`e2e/native/legacy-api.cpp` は追加した全 41 API を実行し、出力・副作用・
失敗時の LastError をアプリ側で検査する。`scripts/ci/legacy-api.ps1` は
Hook 有無の成功、Trace の完全性、各 API の Enter/Leave 対応と型付きの失敗値を
x64 / x86 の CI で検証する。`54b1bde` の run `43284387895` で x64 の全 41 API 検証が通過した。
`005a343` の run `43285474543` では x86 / x64 Server 2022 も全 41 API が通過。
実注入ベンチは実際の Event Integrity 欠落を観測した。inspect の終了コード 1 を
測定用の incomplete として読み込み、レポートを最後まで出すよう修正中。

## 実注入の性能測定

`scripts/ci/native-performance.ps1` は release の Agent DLL / Host を使い、
300 フレームの GDI 再描画・メッセージ処理と 50,000 回の
GetCurrentProcessId / HeapAlloc / HeapFree を実際に実行する。GUI の
BeginPaint / EndPaint / InvalidateRect / UpdateWindow / FillRect / TextOutW /
GetStockObject も L1 に追加した（計197 API）。

3 回ずつ Hook 無し／full の順序を交互に変え、アプリ内 QPC 区間の中央値と
倍率、反復当たり追加時間、出力の一致、Trace サイズ・件数・完全性を JSON に
保存する。起動・注入・終了まで含む wall time は別列とする。Ring は本番既定値を
使い、欠落時も数値を残す。3倍／5倍は評価目標なので未達だけでは CI を失敗に
しないが、実行失敗・対象 API 未観測は失敗にする。対象 API 全体の Coverage と
全アプリの性能保証は別であり、モデルベンチのバッファ占有率とも区別する。
`c0e21a9` の run `43286917384` で x86 の測定が完走。GUI 3.061倍、
高負荷387.312倍で、両方 Event Integrity は不完全。Server 2022 x64 は
GUI 5.189倍、高負荷474.833倍、latest x64 は GUI 2.438倍、高負荷384.163倍。
すべての環境で Event Integrity は不完全なため、目標達成とは扱わない。
成功した CI でも測定 JSON を artifact に保存するよう追加する。

記録ごとに Schema 構築・ハッシュ計算・型 Vec 確保を繰り返していたため、
既存の静的フィールド表から直接符号化するよう変更。184 生成 API の境界値で
旧経路と同じバイト列を検査する。`encoding-cost` example の Linux release
測定では HeapAlloc enter の符号化部分が約570〜700nsから約33〜40nsになった。
これは局所的な比較値であり、Windows 全体の倍率改善は次の CI で測る。

## Parquet の実装検証

`--format parquet --output <path>` を追加。CLI の 33 単体テストと 52 統合テスト、
Rust 1.87、x86/x64 のクロスチェックで検証する。1075 イベントの Windows 実記録を
変換し、DuckDB で件数一致、API 別集計、UBIGINT 列、JSON の取得状態を確認した。
新しい境界値テストで Writer が global_order=0 を許して Reader が拒否する不一致も
見つかったため、書き込み前に拒否するよう修正し、拒否後の正常書き込みも検証した。

`RuntimeSlot::for_detour` は記録ガード内の通常経路を TLS Weak キャッシュへ変更した。
登録ごとにプロセス内で一意な世代番号を発行し、再接続時にはロック下で新しい
参照を取得する。Weak の upgrade で所有権を確保し、古いキャッシュは Agent や
共有メモリを生存させない。終了後の古い参照は既存の recording gate で記録を拒否する。
ガード外の素通し、TLS 不在・破棄済み・再入借用中は従来の RwLock 経路を使う。
Linux の isolated component 測定は通常経路 4.72 ns、素通しロック経路 9.28 ns
（5 回の中央値）。Windows 全体の速度目標やイベント欠落改善の達成を意味しない。
Writer 経路や Host 処理を含む性能要件は引き続き未達。

`c0e21a9` の [CI run `43286917384`](https://github.com/a-kaibu/shirusu-poc/actions/runs/43286917384)
は全ジョブ通過（Windows x86/x64、Server 2022、Linux、macOS、MSRV、Kani、TLA、fuzz）。
Parquet の Windows 統合テストも通過。性能ベンチが完走したことと、数値目標や
Event Integrity が合格したことは区別する。上記の符号化改善は後続コミットで測定する。

## 起動時の回収と Host 検査の改善

`e9f6a03` の [run 43291349934](https://github.com/a-kaibu/shirusu-poc/actions/runs/43291349934)
で Windows x86 / x64 latest / Server 2022 が通過。モジュール署名確認を回収開始の
前提から外したことで、GUI は全 3 環境・各 3 試行で欠落ゼロになった。
GUI の倍率は x86 1.949、latest x64 1.847、Server 2022 2.468 で 3 倍以内。
高負荷ではまだ sequence gap と counter loss があり、完成とは扱わない。

Host の引数検査は登録済み型列を借用し、文字列・バッファや復号結果 Vec を
生成せず検査する。旧 decoder との正常値・全切断位置・不正入力の差分テストと
fuzz を追加した。Linux release の HeapAlloc enter 局所測定では約82〜89nsから
約36〜39nsとなった。Windows 全体の倍率への効果は別途 CI で測る。
単一対象の回収ループも、イベントを回収できた間は再回収し、空の場合だけ
指定間隔待つよう変更する。Ring の容量や欠落の判定基準は変更しない。

生成 L1 Detour の enter/leave 符号化には、フィールド数 × 11 バイトの
スタック領域を使う（capture byte + 最大 10 バイトの LEB128）。
元 API の呼び出し前に一時領域の使用を終え、SEH と ExitThread の所有権回収は
維持する。従来の Codec との全生成 API 境界値・任意の scalar bit pattern の
差分検査を追加した。Linux release の HeapAlloc enter 取得＋符号化は局所測定で
約70〜87nsから約15〜17ns。手書き L2 や実行時管理には別の確保・ロックが残る。


`e41c4d8` の run 43292337379 でも Windows x86 / x64 両環境が通過。
GUI は引き続き全試行で欠落ゼロ、高負荷には欠落が残る。
追加調査で、Host が Agent へ渡した data_ready の自分側ハンドルを
初期化後に捨て、通知を待たず固定 sleep していたことが分かった。
同じイベントをセッション終了まで保持し、空の回収後は通知またはタイムアウトで
再確認する。通知は閾値通過時などに間引かれるため、定期確認も維持する。
実際の通知イベントがセッション準備後も同一であることを Windows 回帰テストで検査する。


## 宣言的な意味契約の初期移行

CreateFileW / ReadFile / WriteFile / CloseHandle の Schema と LastError 有効条件を
[意味契約](semantic-contracts.md)から生成する。移行前から採取した 8 Schema の
Golden と一致し、Capture の判定も同じ定義を参照する。未知の語彙や重複を拒否し、
CI が生成物の更新漏れを確認する。メモリ取得・サイズ式・所有権・非同期処理と
境界値テストの自動生成は未完了であり、意味契約の項目全体はまだ完了にしない。

## TLS Runtime と意味契約のネイティブ検証

`b0c7436` の [run 43397847010](https://github.com/a-kaibu/shirusu-poc/actions/runs/43397847010)
で Windows x64 / x86-WoW64 / Server 2022 が成功。途中で発生した TLS destructor
登録中の allocator 再入は、初期化順序と READY 判定で解消を確認した。
スレッド終了時には TLS の破棄状態も確認し、READY の履歴だけでは記録を開始しない。

| 環境 | Runtime ロック経路 / TLS (ns) | GUI 倍率 / integrity | 高負荷倍率 / integrity |
| --- | --- | --- | --- |
| Windows latest x64 | 10.26 / 7.82 | 1.651 / Complete | 152.265 / Degraded |
| Windows Server 2022 x64 | 9.99 / 8.27 | 1.602 / Complete | 144.586 / Degraded |
| Windows latest x86/WoW64 | 9.92 / 8.02 | 1.579 / Complete | 154.107 / Degraded |

Runtime の値は同じ部品ベンチの異なる経路の中央値であり、アプリ全体の改善率ではない。
高負荷の 5 倍目標とイベント完全性は未達。次の性能作業は Writer の共有状態、
Host の並行回収・変換・通知と欠落を測定し、通常経路全体を対象にする。

## Host 回収と Trace 変換の並行化

[Host Trace pipeline](host-trace-pipeline.md) を実装。所有済みの検証済みイベントを
上限4コマンドの FIFO で worker に渡し、回収と変換・圧縮を並行させる。
Loss と環境更新の順序も保存し、stop が全受理分と worker の結果を確認してから
Finalization を生成する。失敗・panic・キュー満杯・途中終了をテストする。
Windows の高負荷性能と欠落への効果はネイティブ CI で測定するまで未確認。


## 意味契約からの取得処理生成

契約を version 2 とし、4 API の enter / leave の取得関数も生成する。
出力カウントを一度だけ読み、先行フィールドから出力バッファ取得に渡す。
容量・成功 BOOL・非同期指定の対応を宣言し、型や取得タイミングの不正は生成時に拒否。
移行前の23ケースの Compact Binary Golden と一致。上限から生成した境界値の
組合せで、容量外アクセスと未完了出力の読み取りがないことを確認した。
解放・寿命モデルと非同期完了の追跡は引き続き手書きであり、全移行の完了ではない。

Host 並行化 `0a536af` の run 43400920442 は Windows 3 環境で実行テスト成功。
高負荷倍率は x64 latest 128.171、Server 2022 100.380、x86 108.033 で全て Degraded。
GUI は latest x64 1.606 倍で3試行中1回欠落、Server 2022 1.615 / x86 1.914 倍は Complete。
CI マシン差もあるため、前回との倍率差を厳密な改善率とは扱わない。
最新 GUI での欠落も含め、性能・完全性の要件は未達のまま追跡する。

Host キューの満杯回数・送信待ち時間・worker の処理時間を SessionSummary と Trace に
保存し、CLI の結果へ表示する。変換・I/O が回収を止めているのかを実測するための診断で、
wall-clock の重なりを加算した CPU 時間やアプリ区間の性能値とは扱わない。

### Windows reference corpus v1

`shirusu-probe corpus record/compare` now provides immutable entries bound to
canonical Probe inputs and raw Runner reports, recomputed normalized file-I/O
observations, Windows build/process identity and explicit provenance labels.
The Windows CI matrix records the same six-call Probe and preserves entries as
30-day artifacts. See [reference-corpus.md](reference-corpus.md). Native validation
of this addition is tracked by its CI run; permanent publication, wider Windows
release coverage and a broader API corpus remain incomplete. The preceding Host
pipeline diagnostic change (`6372bf4`, run `43404035077`) passed the complete CI
matrix, including fuzz. Queue backpressure was observed on all three Windows
jobs; this measurement does not establish that the performance target is met.

Native corpus execution passed on WoW64 (build 26100) and Server 2022 x64
(build 20348) in run `43405537057`. Downloaded entries were independently loaded
and compared on Linux: all six normalized observations matched. Exact reports,
execution metadata and scratch files are now retained in `corpus/windows/` with
source commit/run/artifact provenance; a regression test verifies their digests
and comparison on every platform. This supersedes the initial artifact-only
publication status above, without implying broad Windows/API coverage.

A further high-load review reproduced a missing Host wakeup: Runtime forwarded
`Published` notifications but discarded `PublishedDegraded` notifications even
though a descriptor had been published. A real Ring regression test failed on
the old implementation and passes after forwarding both outcomes. This preserves
loss reporting and the existing bounded polling fallback; it is not evidence
that the high-load performance target has been reached. Performance artifacts
now also retain the full capture environment, including exact Host queue/writer
counters, alongside each timing sample.

The same corpus Probe also passed on Windows latest x64 (build 26100); its entry
is retained beside the other two and all three compare equal. Native performance
in this corpus CI run was GUI 1.598x / 1.701x / 1.641x with complete event integrity,
and high-load 115.497x / 112.969x / 102.794x with degraded integrity (latest x64 /
Server 2022 x64 / WoW64 respectively). This precedes the degraded-event wakeup fix.

The notification review also reproduced a stale threshold latch after partial
consumer drain: with a four-descriptor Ring, publish two (50%), drain one (25%),
then publish one (50%) failed to notify. PublishNotifyTracker now rearms from the
observed pre-publication occupancy instead of requiring an intermediate producer
publication below the threshold. The real Ring regression fails before the fix;
all transport tests, Clippy and MSRV checks pass after it. No new fence or waiting
operation was added, and the bounded polling fallback remains required.

### Rejected Agent cache borrowing experiment

An isolated Linux release component experiment held a checked TLS state borrow
through publication to avoid the per-event Arc clone/drop, while retaining the
Ring writer Mutex and falling back to owned state on cache misses. It passed the
Agent tests, including management calls while the cache was borrowed, but
`shirusu-phases-bench` measured roughly 81–87 ns/event instead of 65–70 ns/event.
Explicit inlining did not improve it; restoring the original source restored
roughly 65–70 ns/event. The experiment was discarded, not shipped as a Fast Path.
These are isolated component observations, not Windows injected measurements.

The corpus CI suite now also includes a 14-call error/sharing/disposition Probe.
It records errors without pinning an unobserved numerical LastError value in the
input. Expected valid handles and successful closes of those handles are checked;
CreateFileW's raw failure and meaningful success errors remain evidence to
compare across environments. This extends the initial happy-path sample without
claiming complete filesystem-state or asynchronous coverage.

Run `43407103711` (`4dc6364`) passed the complete CI matrix, including fuzz and
both notification regressions on Windows. GUI remained complete at 1.524x /
1.742x / 2.074x, while high-load remained degraded at 121.123x / 111.979x /
100.704x (latest x64 / Server 2022 / WoW64). The next measurement adds an explicit
release-only invocation of the real typed HeapAlloc Detour with a stub original,
including Runtime acquisition, call-stack state, SEH cleanup boundary and two
Ring events. Direct-stub and SEH-only timings are reported separately. It patches
no process, allocates no real application heap block, has no competing Host or
notification event, verifies zero losses and preserves LastError; it must not be
read as the injected application's slowdown or additive CPU attribution.


The first error Probe run (`43408912881`, `cbf4eb2`) exposed an incorrect fixture
expectation: CloseHandle of the `-1` returned by failed CreateFileW returned TRUE
on all three native environments. `-1` is also a pseudo-handle value. The Probe
now observes these closes without asserting that they must fail; raw returns and
errors remain preserved. The entry validator correctly refused the aborted
sequence, so no complete reference entry was emitted for the failed attempt.
The new typed-Detour measurement itself passed: 253.32 / 217.87 / 369.34 ns/call
(latest x64 / Server 2022 / WoW64), including two Ring events. SEH-with-stub was
4.98 / 2.83 / 7.13 ns/call. These isolated measurements do not include a competing
Host or actual heap allocation and must not be added to injected timings.

### Input-dependent CreateFileW LastError contract

File-I/O contract v3 declares the original creation disposition as a leave capture
input and the success-meaningful modes `[2, 4]` (CREATE_ALWAYS / OPEN_ALWAYS).
Failures keep their meaningful error; other successful dispositions remain Stale.
Schema condition 8 (`DependsOnInputs`, bit11 newly used) makes this explicit;
existing condition values 0–7 and field layouts are unchanged. Older three-bit
readers see condition 8 as Unspecified and can still decode Captured/Stale values.
A return-only capture helper preserves input-dependent raw errors as Unsupported
rather than claiming the missing input condition was evaluated.

The CreateFileW leave Schema flags/hash Golden changes intentionally; the prior
23 capture-byte Goldens remain unchanged for their existing inputs. Added tests
exercise all five dispositions, generated Capture → emitter → compare behavior,
contract binding rejection and the actual Windows Detour passing the original
input. Old Trace Stale decisions are not retroactively rewritten. CreateFileA
was still pending at this checkpoint; its subsequent correction is recorded below.
Other APIs outside these four contracts still need input-dependent coverage.

The corrected error/sharing Probe and CreateFileW input-dependent Capture tests
passed on Windows latest x64, WoW64 x86 and Server 2022 in run `43410242785`
(`cc86db2`). Fuzz was still running when these native results were checked.

Detour preparation now reads ClientId.UniqueThread from the executing thread's
TEB on x86/x64 instead of calling GetCurrentThreadId, which is itself selected
for hooking. This removes the internal detour/passthrough traversal without
excluding application GetCurrentThreadId calls. Direct reads use GS:0x48 on x64
and FS:0x24 on x86/WoW64, with API fallback on other architectures. Native tests
compare with Windows on eight simultaneously live threads and check LastError
preservation. The component bench measures unhooked API and TEB reads separately;
any injected performance effect must be established by the next native run.

### Host queued batch coalescing (2026-11-13)

Adjacent, already-queued Events with identical context now share conversion and
compression, bounded by five commands, 4096 events and 1 MiB of payload. Context,
environment and loss boundaries retain FIFO order, and no fill delay is added.
Standalone oversized batches retain their existing acceptance behavior. Queue
and lookahead memory ownership is documented. A new counter records merged
commands without changing original command/event totals. Linux release component
measurement: 256,000 events, five rounds, 102–121 ms without coalescing versus
68–74 ms with coalescing; a second enabled run measured 71–91 ms. Native
application impact still requires CI measurement.

### ANSI file creation error semantics (2026-11-13)

The generated CreateFileA L1 schema also marks LastError as DependsOnInputs.
Its stack encoder receives the original scalar arguments: successful
OPEN_ALWAYS/CREATE_ALWAYS retain meaningful LastError, while other successful
creation modes retain it as Stale. Failure sentinels remain meaningful on both
pointer widths. Without the required input context the raw value is Unsupported,
not silently discarded. This is a narrow handwritten L1 semantic rule; the
four-API declarative contract pilot remains unchanged. Native typed-Detour tests
exercise all five dispositions and caller LastError transparency.

### Terminal events after dropped entries (2026-11-13)

RingWriter now consumes dropped-enter tracking on CallAborted as well as CallLeave,
so an exceptional return cannot leave a stale marker or publish an orphan terminal
that the normal-return policy would suppress. Forced terminal drops now count their
payload bytes as well as their event. A regression failed against the old writer
(dropped payload 5 instead of 10 bytes) and passes with the fix; it also covers an
aborted call and subsequent reuse of its ID to detect stale tracking. Full transport
and Agent tests pass. This corrects loss accounting, not the underlying throughput
shortfall; it must not be reported as eliminating event loss.

### Backlog-aware Event Chunk compression (2026-11-13)

A compression-disabled experiment measured 45–59 ms for the same 256,000-event
Host component workload, versus 68–91 ms with compression, at a file-size cost of
about 0.86 MB → 4.09 MB. The live pipeline now requests raw Event Chunks only when
already-ready Events establish backlog, and resumes normal compression when caught
up. The implemented policy measured 46–59 ms locally. It retains all values and
uses the existing mixed-codec container; validation, CRC, index and durability
remain shared with the normal Writer path. Tests cover mixed-codec exact event
roundtrips, rejected invalid batches and resuming normal policy. Native workload
validation is still required; slower storage can change the performance tradeoff.

### Runtime-target policy lookup (2026-11-13)

Runtime construction now classifies the fixed API table once into an immutable
boolean array. Detour entry indexes that array instead of rescanning module-name
strings; record_runtime_apis remains authoritative and unknown IDs remain
fail-open. The policy still concerns target APIs, not their callers. A parity test
covers every API under both policy settings. Linux release component measurement
for kernel32: name lookup 8.14 ns versus ID lookup 0.83 ns. This is a small isolated
improvement, not a measured application-level speedup or source-boundary filter.

### Cleanup after an initialized capture is abandoned (2026-11-13)

Review found a lifecycle gap beyond the previously fixed attach-preparation error:
LaunchedCapture's Drop only closed its process handle. A poll error, unwind or
explicit drop could leave installed hooks in a still-running application. Drop
now attempts shutdown before releasing its process/mapping ownership, without
terminating the application or fabricating Finalization. Every shutdown outcome
is cached so a timed-out remote worker is never duplicated by Drop. Explicit
run/finish errors retain both the original error and cleanup outcome; a bare
Drop reports unconfirmed cleanup to stderr. Native attach regression now includes
successful attach followed by plain drop and caught unwinding, then checks target
survival, restored entry bytes, absent Finalization and successful reattach.

### Native Ring-capacity experiment (2026-11-13)

The default native acceptance benchmark remains unchanged. A separate report now
runs the same high-load fixture with 4096, 16384 and 65536 descriptors per Ring,
keeping payload capacity at 1 MiB, eight initial Rings and the 2 ms polling policy.
Each capacity runs three times in alternating order. The report retains application
QPC timings, workload checksums, trace bytes, full integrity and capture metadata;
missing observations or changed workload results fail the experiment. Timing or
loss differences are evidence for tuning, not proof of the 5x target. Capture
metadata now records actual descriptor and payload capacities. Defaults have not
been enlarged; native results are required before selecting a new configuration.

### Fixed-size validation scratch storage (2026-11-13)

ValidatingReader now keeps its 256-byte Control copy and 64-byte Descriptor copy
in fixed-size arrays instead of allocating Vecs. The Host-owned snapshot,
validation rules, payload ownership and cursor publication order are unchanged.
This removes a source-level allocation per event, plus one per drain/resume.
Transport and Host suites pass, including malformed images and resume checks.
Local component timings are noisy (most cases improved, one large-batch case
regressed); no application-level speedup is claimed without native measurements.
