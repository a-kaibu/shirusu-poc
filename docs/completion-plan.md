# 当初構想に対する完成条件

要件の正は `overview.md`（2026-11-08）。2026-11-13 に現行実装と照合した。
過去の実装件数、IID の名前件数、静的カバレッジを機能の完成率に読み替えない。

| 要件 | 現状と残件 | 合格に必要な証拠 |
| --- | --- | --- |
| Runtime → Windows の標準記録 | 呼び出し元 Runtime の除外を廃止し、呼び出し先 Runtime の設定へ修正。共通 kernelbase 実装まで thunk を解決。x64 2 環境の CRT E2E 通過 | `--modules` E2E が既定／設定有効の両方で CRT 経由 CreateFileW を記録 |
| LastError の透明性 | x86/x64 の TEB を直接読み書きする実装へ変更 | Windows API との往復、スレッド別値、Hook 有無の比較 |
| 全 Win32 の L0/L1 | 現在190件。system/C の型付き Wrapper に対応。選択表外の API、可変長引数、複合構造体の値渡しが不足 | Metadata 全体の分類と未対応理由、対応 ABI 別のネイティブ往復 |
| 高頻度 API を暗黙に除外しない full | GetLastError/SetLastError を選択表へ追加。短すぎる関数の Inline Hook は不足理由を残して拒否 | 再入なしの記録、短い関数への Inline Hook の透過性 |
| COM の L1 と寿命追跡 | Factory と IID 名識別は実装。共有オブジェクトの通常メソッド追跡は未完成 | 共有オブジェクトの並行呼び出し、QI、AddRef/Release、既存ポインタ同一性を壊さない実機テスト |
| 動的 API と既存プロセス Attach | Inline Hook は実装。新規スレッド競合・停止先ロックの制約が残る | 既存プロセスとスレッド生成中の透明性テスト、失敗時の安全な復元 |
| 子プロセス／スレッド寿命 | PID の同一性検証と thread-exit queue を追加 | 再利用、短命スレッド、ファイバー削除、再 Attach の実機テスト |
| L2/L3 の意味情報 | ファイル等の手書き対応。全 API の出力・資源意味は未対応 | SAL と手書き意味定義、引数／出力／資源の対応検査 |
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

現在の 18,364 メソッドは selected 177、generatable 17,451、unsupported 736。
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
x64 / x86 の CI で検証する。追加部分の Windows 実走は次の CI で確認する。
