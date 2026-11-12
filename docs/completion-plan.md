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

通常経路の共通ロックをなくす要件も残る。`RuntimeSlot::for_detour` は現在
セッション参照に RwLock を使っている。セッション差し替え・終了後の素通し・
ネイティブ TLS がない経路を壊さずに、読み手の所有権を保護する方式が必要。
性能値だけを理由に既存の寿命保護を外さない。

`c0e21a9` の [CI run `43286917384`](https://github.com/a-kaibu/shirusu-poc/actions/runs/43286917384)
は全ジョブ通過（Windows x86/x64、Server 2022、Linux、macOS、MSRV、Kani、TLA、fuzz）。
Parquet の Windows 統合テストも通過。性能ベンチが完走したことと、数値目標や
Event Integrity が合格したことは区別する。上記の符号化改善は後続コミットで測定する。
