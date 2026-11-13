# 当初構想に対する完成条件

要件の正は `overview.md`（2026-11-08）。2026-11-13 に現行実装と照合した。
過去の実装件数、IID の名前件数、静的カバレッジを機能の完成率に読み替えない。

現時点で全ジョブの成功を確認済みの基準は `8b6baac` の
[CI 43453132419](https://github.com/a-kaibu/shirusu-poc/actions/runs/43453132419)。
Windows x64 latest / Server 2022 / x86 WoW64、Linux、macOS、MSRV、
形式検証と短時間 fuzz を含む。以降の修正の実機検証は別途追跡し、この基準の
成功を新しいコードの合格証拠に流用しない。

性能は未完成。`8b6baac` の Windows 3 環境では GUI が約 1.39〜1.88 倍で
完全な記録を達成した一方、高負荷は約 38〜45 倍で欠落が残った。
これは同じ fixture の今回の測定結果であり、他のアプリの完全性を保証しない。
Coverage 台帳、同期ファイル Probe の限定的な削減、4 API の意味契約、
2 Windows ビルドの参照コーパスは実装済みだが、下表の一般化・安全性・性能の
残件があるため、全体の完成率を単純な実装件数から算出しない。

| 要件 | 現状と残件 | 合格に必要な証拠 |
| --- | --- | --- |
| Runtime → Windows の標準記録 | 呼び出し元 Runtime の除外を廃止し、呼び出し先 Runtime の設定へ修正。共通 kernelbase 実装まで thunk を解決。x64 2 環境の CRT E2E 通過 | `--modules` E2E が既定／設定有効の両方で CRT 経由 CreateFileW を記録 |
| 標準の呼び出し境界 | Nt は詳細モードに分離。公開 Windows API 同士の内部呼び出しは caller address による境界判定が未実装 | Application / Runtime 起点の記録と Windows 内部起点の除外、callback 内の再開を実走で比較 |
| LastError の透明性 | x86/x64 の TEB を直接読み書きする実装へ変更 | Windows API との往復、スレッド別値、Hook 有無の比較 |
| 全 Win32 の L0/L1 | 現在197件。system/C の型付き Wrapper に対応。選択表外の API、可変長引数、複合構造体の値渡しが不足 | Metadata 全体の分類と未対応理由、対応 ABI 別のネイティブ往復 |
| 高頻度 API を暗黙に除外しない full | GetLastError/SetLastError を選択表へ追加。短すぎる関数の Inline Hook は不足理由を残して拒否 | 再入なしの記録、短い関数への Inline Hook の透過性 |
| COM の L1 と寿命追跡 | Factory、IID 名識別、image-backed 共有 IUnknown の QI/AddRef/Release は実装・実走済み。派生メソッドと private/heap vtable は未対応 | 共有オブジェクトの並行呼び出し、QI、AddRef/Release、既存ポインタ同一性を壊さない実機テスト |
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

初期の統合検証は `e7e2fc2` の [run `43281728421`](https://github.com/a-kaibu/shirusu-poc/actions/runs/43281728421)。
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

### Payload-pressure notification (2026-11-13)

The first native capacity sweep on `9f8c2fd` found that enlarging descriptors alone
could make losses worse. On x64 latest, 65536-descriptor samples lost roughly
29k–62k counted events while 4096-descriptor samples lost 0–6.8k. These are noisy
runs, not a causal proof. Inspection found a real notification gap: only descriptor
occupancy could trigger a watermark notification, even when payload storage filled
first. RingWriter now tracks payload occupancy with its own watermark edge and
notifies after the same publication Release. Either edge wakes the Host; staying
above a watermark does not repeatedly notify, and a partial drain rearms it.
The regression fails before the fix with `notify: None` at 50% payload usage while
descriptor usage is below 5%, and passes afterward including partial-drain rearming.
Transport, Agent and Host suites pass. Defaults remain unchanged and native
performance/loss impact still requires measurement.

### HeapAlloc LastError semantics (2026-11-13)

The generic pointer-return default incorrectly treated HeapAlloc's residual
LastError as meaningful on NULL failure. Microsoft explicitly states that
[HeapAlloc does not call SetLastError on failure](https://learn.microsoft.com/windows/win32/api/heapapi/nf-heapapi-heapalloc).
Its metadata override is now `never`: capture preserves the raw value as Stale
on both success and failure. A regression failed on the old generated table and
passes with NULL/non-NULL results and four residual values. Hook and generator
suites, strict Clippy and generated-file consistency checks pass.

### Native confirmation and watermark arithmetic (2026-11-13)

`8df6862`, CI 43419161805, passed all three native Windows jobs. GUI ratios were
1.551x (latest x64), 1.836x (Server 2022), 1.572x (x86), each Complete. Default-ring
high-load ratios were 64.307x, 63.067x, 65.369x respectively, each with losses.
The capacity sweep did not produce an all-platform, all-sample loss-free setting:
65536 descriptors eliminated losses in all three x86 samples, but not all x64
samples. Production defaults therefore remain unchanged. This comparison includes
both fixed-size validation scratch buffers and payload notifications, and is not
an isolated attribution to either change. The fuzz job was still pending when
these native results were collected.

Watermark comparisons now avoid division using checked threshold multiplication,
retaining the prior saturating numerator and zero-capacity behavior. Random u64
properties and explicit extreme values check equivalence to the prior percentage
calculation. Local release component median was 3.41 ns before and 1.99 ns after;
this small isolated improvement is not an application speedup claim. The native
phase benchmark now records this component too.

### Named synchronization object creation (2026-11-13)

CreateMutexW/ExW, CreateEventW/ExW and CreateSemaphoreW previously marked successful
ERROR_ALREADY_EXISTS as Stale under the generic NULL-only failure rule. Their
schemas now declare input-dependent meaning. NULL failures are Captured; successful
unnamed objects are Stale; successful named ERROR_ALREADY_EXISTS is Captured. Other
named successes or missing inputs remain Unsupported with raw values preserved,
without pretending the L1 capture knows all creation state. The regression checks
all five generated lpName bindings and failed against the prior generated schemas.
A native CreateEventW reopen test checks the real Windows error and encoded capture
status. Linux Hook/generator suites and x86/x64 strict Clippy pass; native execution
of the new test is pending CI.

### COM pointer reuse and delayed completion (2026-11-13)

The tracker retained destroyed/IID/interception state when a factory reused an
address after an observed Release(0). It also merged QI identity groups solely by
raw pointer values, allowing a new lifetime to absorb an older lifetime's aliases.
Fresh discoveries now reset retired records; opaque allocation identities separate
interface lifetimes and QI groups without relying on address uniqueness or wrapping
counters. Factory, QI, method-return and discovery paths share fresh-state creation.
An already-live record remains intact; missing Release observations do not prove
reuse. Historical trace events are unchanged; the tracker indexes the latest record
for each address, not an unlimited history of incarnations.

COM method completion checks the lifetime captured before calling the original,
so a delayed old AddRef/Release cannot update or destroy a newly discovered object
at the same address. That lifetime token is owned by the native SEH finally tuple.
Two regressions failed before the tracker fix; all Hook tests pass afterward,
including rediscovery through each entry point and old/new identity separation.
Windows also compiles a delayed-completion regression. This fixes tracking state;
standard shared COM method interception remains deliberately disabled.

## 既存 IAT ラッパーの保持

IAT の実際の参照先が解決済みのシステム export（透明な import thunk を含む）と
異なる場合、そのスロットを置き換えない。Inline 設置が API 共通の original を
trampoline に更新した結果、アプリや別ツールの既存ラッパーを迂回する問題を防ぐ。
Coverage には `noncanonical-import-preserved` を記録し、一部スロットだけを
設置した場合も `partial` として区別する。静的 import の証拠は失わない。

ネイティブ Attach fixture は事前に GetCurrentProcessId の IAT ラッパーを設置し、
失敗時 rollback、Drop/unwind、再 Attach の後にも 100 回の呼び出しがすべて
ラッパーを通ることと、Inline 経由の記録を確認する。`41dd0a6` の
[CI 43426765835](https://github.com/a-kaibu/shirusu-poc/actions/runs/43426765835) で
x86 WoW64 / x64 latest / x64 Server 2022 の全ネイティブジョブが通過した。並行する第三者の IAT 書き換えとの
競合解決はこの変更の保証に含めない。

### IAT 更新のアラインメント

Attach 中に対象スレッドが IAT を読み取るため、設置・復元のポインタ更新は
整列した AtomicUsize の Release store で行う。不正な未整列スロットは保護属性を
変える前に拒否する。元の値の保存・公開順序は維持する。
未整列スロットで周囲のバイトが変化しない Windows 回帰テストを追加し、
x86/x64 Clippy と MSRV 1.87 の x86 compile を確認した。
`f935d11` の [CI 43427821285](https://github.com/a-kaibu/shirusu-poc/actions/runs/43427821285)
で Windows x86 / x64 latest / x64 Server 2022 の未整列スロット拒否テストと
Attach の復元・再 Attach を含む全ネイティブジョブが通過した。

### 採用しなかった Host 符号化の最適化

EventChunk のサイズ見積もりを Vec の予約容量へ流用し、分割間でバッファを
再利用する案を試した。Trace / Host 全テストは通ったが、同じ release 設定で
変更前後のバイナリを交互に 10 回測定したところ、変換・圧縮の中央値は
改善せず一部で遅くなったため、コードを元に戻した。変更前後の実験値を
実アプリの速度改善としては扱わない。

### Host 回収バッチの容量予約

ValidatingReader は毎回空の Vec から回収結果を構築していた。公開済み件数、
Host が保持する Ring 容量、呼び出し側の回収上限の最小値を初期容量にする。
共有側 Cursor は信用せず、初回 Descriptor 検証より前の予約でも Ring 容量を
超えない。Descriptor／Payload の検証・コピー・Cursor 前進は維持する。

同じ release 設定で変更前後を交互に 10 回比較した Linux の単体計測では、
128 / 1024 / 3072 イベント、借用／所有権移動の 6 条件すべてで Host drain の
中央値が約 6〜20% 短縮した。これは Windows アプリ全体の高速化率ではない。
Transport / Host 全テスト、Clippy、MSRV 1.87 の x86 compile は通過。
Windows の速度・欠落への効果はネイティブ CI で別途検証する。

### Probe の複数操作削減

単独削除を試して変更がなくなった後、削除可能な ReadFile / WriteFile の
連続した候補群をまとめて削除する。大きな候補から半分ずつ幅を狭め、境界を
またぐ組も試せるよう重なりのある窓を使う。採用したら単独削除から再検証する。
Create / Close、結果を保存する操作、差分の対象は保持する。各候補は既存の
Runner 判定で同じ対象差分が 2 回連続して確認できたときだけ採用し、全試行は
既存の max_trials に含める。予算不足・不安定な再現では候補を採用しない。

単独では消せない 2 操作、重なった窓、前提操作と対象位置の保持、二重確認と
試行予算の回帰テストを追加した。2 操作の回帰テストは修正前のコードで失敗を
確認。Probe 全テスト、Clippy、MSRV 1.87 check が通過した。
`single_deletion_fixed_point` は単独削除の固定点だけを表し、群の全組合せ・
入力値の縮小・大域的最小性は保証しない。実際の互換実装との再現性は、
利用者が設定する Runner と記録する実行証拠で判定する。

## 共有 IUnknown の Adapter と標準経路への接続

画像に属する vtable の先頭 3 スロットだけを、正確な QueryInterface / ULONG
ABI の Adapter にアトミックに置き換える実装を追加した。オブジェクトの vptr と
派生メソッドは変更しない。未知のオブジェクトは IID を推測せず素通しし、
Factory 等で発見済みのオブジェクトだけを既存の寿命追跡へ接続する。
ヒープ上の vtable、未整列データ、終了中のセッションは拒否する。

公開済み Wrapper の番号・元関数・Weak なセッション参照はプロセス終了まで
保持し、古い保存済み関数ポインタを新しいセッションに接続しない。
未公開の失敗は番号を回収し、保護属性の復元失敗は Shutdown の再試行対象とする。
別ツールが書き換えたスロットを復元処理が上書きしない。ラッパーは最大 256 組。

DLL のアンロード通知はロック・確保・TLS なしで世代を無効化し、同じアドレスへ
再ロードされた別の画像に古いポインタや保護属性を書き戻さない。コールバックを
含む Agent 自身だけを固定し、COM 実装 DLL を保持してアンロードを妨げない。
初期化は Loader Lock 外の cold path に限定する。

Windows の隔離子プロセステストで、共有 vtable、参照カウントの上位ビット、
LastError、QI の同一性、元メソッドを実際に停止させた状態での並行解除、遅延呼出し、
SEH の所有権回収、復元失敗、未公開失敗の反復、第三者の置換保持、実 DLL の
アンロード通知とアドレス再利用モデルを検証する。x86/x64 Clippy と MSRV 1.87
compile、Linux Hook テストに加え、`7e8f22e` の CI 43435482648 で x86、x64 latest、
Server 2022 のネイティブ検証を通過した。

次の変更で標準 Factory / QI 経路へ接続し、Shutdown の復元・再試行にも組み込む。
DLL アンロード済みの Adapter を持つ追跡記録は旧寿命として終了させ、同じアドレスの
再発見に引き継がない。アンロードから Release=0 を推測しない。メソッド Leave は
`return_i32_bits` と `return_kind` で HRESULT / ULONG を区別し、Factory Leave の
3 フィールドは維持する。Bootstrap v12 で旧 Agent との混在を拒否する。
標準経路の ShellLink E2E と新しい Trace のネイティブ検証は `85b7d7d` の
CI 43438911044 で通過した。x64 の ShellLink E2E で QI / AddRef / Release を記録し、
x86/x64 の Adapter テストで ULONG の型付き Leave を確認した。
派生メソッドやヒープ vtable の未対応は引き続き残る。


## IAT の所有権と復元失敗の再試行

IAT 書き換えの記述子を公開前に保存し、ポインタと元のページ保護属性を個別に
追跡する。VirtualProtect の復元に失敗したスロットもロールバック対象から落とさない。
復元は自分の Detour と一致する場合だけ CAS で行い、別ツールの置換を保持する。
ポインタだけ復元済みで保護属性が未復元の場合、再試行はポインタを書き直さない。
設置直前にも元ポインタの正規性を確認し、計画後の変更は巻き戻して拒否する。

Agent は未復元記述子または進行中呼び出しがある設置失敗で、記録を停止した
Runtime と復元状態を保持する。Host は Hook 設置失敗コードに限って Shutdown を
再試行する。既存セッションへの再初期化拒否などでは Shutdown しない。
障害注入で設置後／復元後の保護属性の失敗と第三者ポインタの保持を検査し、
Agent の再試行テストは失敗状態の保持経路から実行する。実機結果は次の CI で確認する。
Inline Hook 側の保護属性復元の追跡は別の残件として継続する。


## Inline Hook の保護属性・命令キャッシュの復元

設置前の失敗と、コード公開後の後処理失敗を分離した。公開後に VirtualProtect の
復元や FlushInstructionCache が失敗しても、Trampoline と解除記述子を保持する。
未公開 Trampoline のキャッシュ更新失敗は公開前に拒否する。通常 API の設置証拠は
後処理が残る場合 `installed-restoration-pending` / `partial` とする。

解除では実際にパッチしたバイト数だけを書き戻す。元バイトを書き戻した後の
再試行は保護属性とキャッシュ更新だけを行い、後から変更されたコードを書き直さない。
最初の解除でも公開済みパッチとの一致を読み取り確認し、第三者が変更したコードは保持する。
比較と復元は既存のスレッド停止区間内で行う。設置でも計画時の命令列との一致を
停止後に再確認し、変更されていれば Trampoline を公開せず解放する。外部から新しく作られる RemoteThread の
競合を完全に防ぐものではなく、既存の設置／解除の制約は残る。
異なる属性の領域にまたがるパッチは、一つの旧属性で複数ページを上書きしないよう
公開前に拒否する。保護属性／キャッシュ更新の障害注入と領域境界の回帰テストを追加。
ネイティブ結果はこの変更の CI で確認する。


## Loader Lock 不明時の Ring 待機

WriterPolicy は Unknown なら既定で 0ms 待機とするが、Agent が生成した Writer は
NotHeld のままで、この設定が実際の Hook 経路に届いていなかった。DLL では
全 Writer に Unknown を設定する。別 DLL の DllMain から API が呼ばれる可能性があり、
Agent の初期化が Loader Lock 外という事実だけでは記録時の NotHeld を証明できない。

満杯 Ring で Unknown の場合に待機回数・仮想時計が増えず、明示的な NotHeld では
従来の bounded wait が働くことを、複数 Writer の Agent テストで確認する。
これは Ring の空き待ちの修正であり、Hook 内の全管理処理を lock-free にするものではない。
待機を減らすと欠落が増える可能性があるため、同じ native fixture で欠落と倍率を分けて検証する。

`b98c7ca` の CI 43440514975 は全ジョブ成功。ただし性能目標の達成とは異なる。
x64 の高負荷 3 サンプルは 134.65 / 114.61 / 146.74ms、うち欠落なしは 1 件。
Host FIFO 満杯は 45 / 48 / 49 回、drain 待機は 53.17 / 25.94 / 41.59ms、
変換 wall time は 143.38 / 121.82 / 154.25ms。これらは重なる wall time なので合算しない。
少なくとも Host 側の処理待ちが Ring 回収を止めていることが観測できる。
x64 GUI は 1.502 倍で 3 件とも完全だが、x86 GUI は 1.396 倍でも 1 件に欠落があり、
速度だけをもって GUI 全環境達成とは扱わない。高負荷は x64 76.198 倍 / x86 59.497 倍で未達。


## Capture の OS ビルドと ISA の証拠

実 Capture の Environment は OS 名・ビルド・CPU arch が空のままになっていた。
Host が初期化前に RtlGetVersion から取得した major/minor/build を記録し、取得元を
`os_version_source=RtlGetVersion` として残す。失敗時は推測値を引き継がず空／0と
`unavailable` にする。Windows の販売名や、互換レイヤーではないという証明には使わない。

ISA は pointer width だけで推定せず、Agent DLL の COFF Machine と optional header を
照合する。I386 + PE32 は x86、AMD64 + PE32+ は x86_64、それ以外は unknown。
同一ビットネス注入の現行制約を維持する。x86/x64 の Capture E2E で OS ビルド・ISA・
pointer width・取得元が Trace に残ることを検証する。native 結果は次の CI で確認する。

Loader Lock 修正 `1898616` は CI 43444166213 の全ジョブを通過した。
x86 の GUI は 1.619 倍・3 件とも欠落なし、高負荷は 69.810 倍で欠落が残る。
待機しない設定の有効化は完全性や速度目標の達成を意味しない。

### 子プロセス回収の待機と終了条件

単一プロセスでは実施済みだった「回収できたら次の sweep へ進む」方針を
child-tree にも適用する。各 sweep で全プロセスを一度ずつ処理し、全て空なら
poll interval を待つ。プロセス一覧探索は同じ interval で行い、忙しい Ring の
回収回数に比例して一覧探索を増やさない。最後の探索が失敗した場合は、子が
いない証拠とせず、既存の連続失敗上限まで再試行する。Windows の child-tree
E2E と x86/x64 クロスチェックで追跡する。

### CreateFileW の成功／失敗差からの Probe

成功側の生成オブジェクトが失敗側に存在しない場合でも、未対応の生成呼び出しを
スレッド内の呼び出し列で対応付け、戻り値差の証拠を残す。取得済みの失敗結果も
生成結果の序数へ数え、以後の成功オブジェクトをずらして比較しない。既に
オブジェクト経由で比較済みの呼び出しは二重に比較しない。中断と成功の対は
「呼び出し欠落」ではなく CallShapeDifference として扱う。

Probe の fingerprint は、既知の初期状態から再生できる CREATE_NEW / OPEN_EXISTING
について、有効 HANDLE と INVALID_HANDLE_VALUE の差・失敗時の LastError を扱う。
成功時の Stale LastError と生 HANDLE の番号は差分にしない。ポインタ幅が不明、
値が範囲外、NULL 戻り値の場合は拒否する。両幅の Trace → Runner report 照合、
失敗理由の変化と情報不足の拒否を検査する。Windows の同一 Runner を隔離して
2 回実行するテストも CreateFileW を対象に追加し、差分を捏造しないことを確認する。
実互換 Runner との再現検証・大域的最小性はこの実装の完了条件とは分けて残す。

### バースト用バッファの選択

`capture` / `attach --buffer burst` は Descriptor 65,536件 / Payload 1 MiBを
明示的に選択する。既定の4,096件は維持。初期8 Ring の共有 Mapping は
約10 MiBから約40 MiBとなり、Host のコピー・キュー等は別途必要。
`8b6baac` の x64 latest では当該構成で容量比較3回とも欠落なしだったが、
高負荷5倍目標や一般アプリの完全性の達成とは扱わない。CI はこの構成を
CLI 経由でも実行し、Trace に保存した実容量・対象終了・観測内容を確認する。
SlotPool には Ring 構成を使ったメモリ計算を追加し、Agent DLL は Bootstrap と
同じ構成を渡す。カスタム構成を使うライブラリ利用者も共有前に
`with_ring_config` を設定する必要がある。拡張予算の境界は大小の構成で検査する。
