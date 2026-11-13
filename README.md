# shirusu-poc

API 別の観測証拠は `shirusu coverage <trace> [--json]` で確認できます。範囲と制限は [Coverage 台帳](docs/coverage-ledger.md) を参照してください。

同期ファイル I/O の差分は `shirusu-probe reduce --help` から、指定した 2 つの Runner で
再現を確認しながら不要な読み書きを削減できます。実行器の契約、証拠の保存場所と対応範囲は
[ippai 連携仕様](docs/ippai-integration.md#外部-runner-による実行検証付き削減) を参照してください。

Trace は `shirusu export capture.trace --format parquet --output events.parquet` で
Parquet に出力できる。DuckDB からの検索とデータの扱いは
[Parquet 出力仕様](docs/parquet-export.md) を参照。

現在の対応範囲は `shirusu capabilities`（機械可読出力は `--json`）で確認できる。
Win32／内部 API は 5,890 件。標準層 197 件（生成 L1: 184、手書き: 6、内部: 7）は
IAT と Inline の両方で設置し、主要 23 DLL の生成可能な export 5,693 件は
メインモジュールの IAT に限る広域層として L1 で記録する（Inline・動的解決は対象外）。
除外した API と理由は `crates/shirusu-metadata-gen/apis.toml` の `[[skip]]` に残す。
32/64bit 整数・短整数・浮動小数点の元の ABI を保って中継する。
COM は Factory の観測と 7,797 IID の名前解決に対応するが、共有オブジェクトの
メソッドを安全に追跡する通常経路は未完成。全 Windows API・COM 対応が完成した
リリースとしては扱わない。検証方法と実動確認の範囲は [docs/verification.md](docs/verification.md) を参照。


shirusu の Agent–Host 転送仕様 v0.4（SPSC Ring と状態遷移）の PoC 実装。
仕様の正は `docs/spec-transport.md`、全体設計は `docs/overview.md`、検証戦略は `docs/verification.md`。
仕様条項・テスト項目と実装の対応は `docs/traceability.md`（網羅チェックリスト、進捗の分母）にあります。

> 範囲について: 最初の実装対象は `shirusu-transport` の SPSC Ring と状態遷移でした（spec.md 末尾の決定）。
> 2026-11-09 の指示で対象はトレーサー全体へ拡大し、Phase 2（公開 Trace への変換）、Phase 3（フック＋レコーダ）、Phase 4（解析 CLI）、Phase 5（ippai 連携基盤）へ対象を拡大しました。Windows／Linux／macOS の CI でも検証していますが、全体の完成を意味しません。確認済みの基準と残件は completion-plan に記録しています。
> COMとWinRTはFactory／Activation呼び出しと返却ポインタを記録します。通常の記録では、画像領域のvtableに対してIUnknownの3メソッドを型付きで記録し、オブジェクトのvptrは変更しません。ヒープ上のvtableと派生メソッドは未対応で、Coverageに`image-backed-iunknown-only`として不足を残します。Inline Hookの解除ではトランポリンをプロセス終了まで保持し、公開済みの保持領域と未公開の予約を合わせて4,096件に制限します。未公開の領域は見送り・失敗時に解放し、解放を確認できた予約分を上限へ戻します。Hostへの再接続と予備Queueは初版では扱いません。

## 当初設計との照合（2026年11月13日）

完成条件は [overview](docs/overview.md) の要件に置く。残件は
[completion-plan](docs/completion-plan.md) で追跡し、過去のチェックリストの
「未着手 0」をトレーサー全体の完成とは扱わない。
標準の記録境界は Runtime → Windows API も含む。`--record-runtime-apis` は
Runtime 自身のエクスポートを追加する設定で、CRT 経由の Windows I/O を隠す設定ではない。
全 WinMD の対応状況は `cargo run -p shirusu-metadata-gen -- --inventory target/api-inventory.tsv`
で出力できる。生成可能な型の件数と実機で記録を検証した件数は区別する。

## 構成

| クレート | 内容 | Windows 依存 |
|---|---|---|
| `crates/shirusu-crc32c` | CRC32C。公開 Trace 形式と共有メモリ転送が共用する基礎処理 | なし |
| `crates/shirusu-api-catalog` | API Catalog。API ID・Schema ID・フィールドの型と意味・取得契約の共有定義と、Agent/Host 照合用の Fingerprint。Hook は Capture に、Host は Schema 登録に同じ表を使う | なし |
| `crates/shirusu-transport` | 共有メモリレイアウト、SPSC Ring、Payload、Overflow 状態機械、Slot、通知ロジック、Host 検証 | なし |
| `crates/shirusu-transport-win` | File Mapping（名前なし）、DuplicateHandle、Event Object（data_ready: プロセス単位 auto-reset / space_available: Ring 単位）、2ms 再確認付き待機、継承ハンドル付き子プロセス起動 | あり（他 OS はスタブ） |
| `crates/shirusu-agent` | 書き手側。スレッド毎 Ring 取得・書込、再入ガード、Host 生存確認、DETACH 通知 | transport-win 経由 |
| `crates/shirusu-host` | 読み手側。Drain Worker、検証付き読み、Loss Event 生成、Enter/Leave 対応付け、終了不明判定、完全性報告、公開 Trace 変換（A72） | transport-win 経由 |
| `crates/shirusu-hook` | フックエンジン。API Catalog による型付き引数取得・IAT フック計画・Inline Hook と Windows 実装（Phase 3） | あり（計画・スキーマ・Inline コアは非依存） |
| `crates/shirusu-agent-dll` | Agent DLL。対象プロセスへ注入され、Bootstrap 初期化でフックを設置する cdylib（Phase 3） | あり |
| `crates/shirusu-trace` | 公開 Trace 形式 v1（`docs/trace-format.md`）。Block Container + Protobuf メタデータ（手書きワイヤ形式）+ Compact Binary + BLAKE3 Blob + Zstd チャンク、Trace Writer / Reader（回復意味論） | なし |
| `crates/shirusu-analysis` | 公開 Trace の解析ビュー（共有基盤）。イベント復号・表示・完全性サマリ・JSON 出力（Phase 4） | なし |
| `crates/shirusu-cli` | 解析・記録 CLI。inspect / dump / export / repair / capture・attach（Phase 4） | なし |
| `crates/shirusu-compare` | 正規化つき差分エンジン。非決定値の正規化とオブジェクト相関による Trace 間比較（Phase 4） | なし |
| `crates/shirusu-test` | shirusu-test 基礎。言語非依存 JSON 仕様による Trace 期待ルールの評価（Phase 4）。JSON Runner と Probe exe 生成（L20）もここ | なし |
| `crates/shirusu-emit` | 外部レコーダ向けエミッタキット（Phase 5）。shirusu 本体以外の実装（sake 等）が公開 Trace 仕様に適合した Trace を出すための高水準 API：セッション管理、共有 API セットの Schema 登録、sequence / call_id の自動採番、Enter/Leave 対応の保証 | なし |
| `crates/shirusu-conformance` | 外部生成 Trace の適合性チェッカ（Phase 5）。形式仕様＋compare/test が依存する規約を 11 項目で検査する lib + CLI | なし |
| `crates/shirusu-probe` | 差分→Probe 最小化（Phase 5）。compare の候補から回帰バンドル（ブリーフ＋shirusu-test ルール＋トリム済み Trace ペア）を生成する lib + CLI。契約は `docs/ippai-integration.md` | なし |
| `crates/shirusu-loom-tests` | loom による公開/回収プロトコルの網羅検査モデル | なし |
| `e2e/` | Test Supervisor / producer / consumer。同期ポイント経由のシナリオ群と、Windows でのプロセス間実テスト | 一部 |
| `fuzz/` | cargo-fuzz ターゲット 6 件（validate_control / decode_descriptor / decode_payload / snapshot_fragments / decode_compact / recover_trace）とシードコーパス | なし |
| `tla/` | TLA+ モデル（SPSC Ring + Slot 再利用 + スレッド終了、容量 2・書手 2・読手 1）と TLC 設定 | なし |

転送の核となる契約は 1 つです。

- 書き手: Payload コピー → Descriptor 書込 → `write_cursor` を Release 更新（公開点はここだけ）
- 読み手: `write_cursor` を Acquire → 確定分だけコピー → 検証 → `read_cursor` / `payload_read_position` を Release 更新

通常経路ではプロセス共通ロックも全順序フェンスも使いません。満杯時は既定 1ms まで待って
OVERFLOW に入り、まず Payload だけ落として Descriptor を残し、それも無理ならイベントを捨てて
Loss カウンタと Sequence 欠番で欠落を残します。

## 使い方

```bash
# ビルドとテスト (Linux/macOS でも transport の核は動く)
cargo test --workspace
cargo test -p shirusu-loom-tests

# Windows ターゲットのコンパイル確認 (Linux から)
cargo check -p shirusu-transport-win -p shirusu-agent -p shirusu-host -p shirusu-trace --target x86_64-pc-windows-msvc
cargo check -p shirusu-transport-win -p shirusu-agent -p shirusu-host -p shirusu-trace --target i686-pc-windows-msvc

# E2E シナリオ (プロセス内 + 子プロセス起動スモーク)
cargo build --workspace
./target/debug/shirusu-e2e-supervisor --all
# Windows: x86 producer + x64 host のプロセス間実テスト
#   $env:SHIRUSU_E2E_PRODUCER = "target\i686-pc-windows-msvc\debug\shirusu-e2e-producer.exe"
#   .\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe --cross-arch
#   .\target\x86_64-pc-windows-msvc\debug\shirusu-e2e-supervisor.exe --memory-order-stress
```

CI と同じ手順は `scripts/ci/` にあります（`linux.sh` / `windows.ps1` / `windows-x86.ps1` /
`kani.sh` / `fuzz-short.sh` / `tla.sh`）。GitHub Actions の定義は `.github/workflows/` です。

CIは同じrefとスイートの最新実行だけを残し、新しいpushや同じスイートの手動実行で古い実行をキャンセルします。
定期実行と長時間検証のスイートは通常のCIと別に管理します。
集約ジョブは失敗を報告しますが、キャンセル後には起動しません。
Rustの依存キャッシュはジョブとツールチェーンごとに分け、mainでは後続テストが失敗した場合にも保存します。
通常のワークスペースに加えてfuzzの依存ビルドとKaniの導入先を保存し、WinMDとTLA+ツールは取得スクリプトのハッシュをキーに再利用します。
TLA+だけを実行するジョブではRustのセットアップとRustキャッシュの復元を行いません。

## 検証状況

正直な現状は次のとおりです。「検証済み」は、ローカルと CI の両方で通過した項目だけを指します。
詳細な項目別状態は `docs/traceability.md` を見てください。

| 検証 | ローカル (Linux) | CI (GHA) |
|---|---|---|
| Unit / 統合 / 仕様テスト表 19 項目 + 境界スイート 69 件 | 通過（下記テスト総数参照） | run #6（2026-11-10、全 12 ジョブ成功）で確認 |
| PBT (参照モデル / Overflow / Fragment / Slot / DST 故障混入 + 損失会計保存則 / Snapshot 故障モデル / 通知意味論 / Slot 影モデル / Enter-Leave 対応付けの新規 6 プロパティ) | 通過（主要プロパティ 1024 cases、DST 512 cases。`SHIRUSU_PBT_CASES` で調整可） | run #6（2026-11-10、全 12 ジョブ成功）で確認 |
| loom (小容量モデル、18 件: Claim 競合 / Slot 再利用 / 世代ガード / 待機インテント回復性 / Slot 回収の操作列転写モデル (R3) / 旧順序 should_panic 回帰 (D53) / Control 初期化の公開順序モデル 2 件 (K04)) | 通過 | run #6（2026-11-10、全 12 ジョブ成功）で確認 |
| ストレステスト (SPSC 並行ソーク、release で 1000 万 ops・整合性確認済み、破壊耐性など。規模は `SHIRUSU_STRESS_OPS` で調整可) | 通過 | run #6（2026-11-10、全 12 ジョブ成功）で確認 |
| E2E シナリオ (16 件: Host 再起動再開 / 公開途中 kill / 32 スレッドストーム / 100 万イベント会計突合 / 共有メモリ破壊注入 / DETACH ストーム等。Windows ではプロセス間 3 件を加え 19 件) | 通過 (supervisor `--all`、同期ポイントのみで同期) | run #6（2026-11-10、全 12 ジョブ成功）で確認 |
| Windows x64 / i686 の cargo check | 通過 (この VM から両ターゲット。README の手順どおりの `-p shirusu-transport-win -p shirusu-agent -p shirusu-host` は x64・i686 とも通過。`--workspace` での i686 は loom-tests 経由の第三者クレート `generator 0.8.12` が i686 用 asm を持たず失敗する既存の問題で、自クレートは `--exclude shirusu-loom-tests` で通過。CI の i686 ジョブでは loom-tests の除外が必要——所感参照） | run #6（2026-11-10、全 12 ジョブ成功）で確認 |
| Windows 実機テスト (windows-latest, WoW64 含む) | 未実行 (Linux のため) | run #6 の windows-x64 / windows-x86-wow64 / windows-x64-win2022 ジョブで実行し成功。ジョブログ本文は未読のため、ジョブ内の個別テスト単位の確認は traceability の実装済み未検証に残る |
| Windows E2E プロセス間 (File Mapping + 継承ハンドル) | 未実行 (Linux のため) | run #6 の windows-x64 / windows-x86-wow64 / windows-x64-win2022 ジョブで実行し成功。ジョブログ本文は未読のため、ジョブ内の個別テスト単位の確認は traceability の実装済み未検証に残る |
| Kani (14 harness: Cursor 演算 / 占有量 / Slot 割当 / Snapshot 分割 / Descriptor 解釈 / Payload 範囲 / 損失差分) | **全 14 harness が VERIFICATION SUCCESSFUL、0 failures**（`cargo kani -p shirusu-transport`）。証明の入力範囲は CBMC の実力に合わせて絞った箇所があり、理由と代替カバーは各 harness のコメントに明記 | CI ジョブあり (continue-on-error) |
| Miri (UB 検査) | **実施済み・UB 検出なし**（transport lib 38 件 + boundary 61 件、純粋演算テスト 1 件のみ解釈コストで除外。開始時に SharedRegion の provenance 違反など 3 種の UB を検出して修正済み——所感参照）。spec_table からは c03/c14/c15/c17 が Miri で通過（約 2 秒）。c01/c08 も小規模で通過（c01 は OPS=200 で 1.86 秒、c08 は OPS=20 で 0.52 秒）。注意: Miri は既定でホストの環境変数を転送しないため、繰り返し回数の指定には `MIRIFLAGS="-Zmiri-env-forward=SHIRUSU_SPEC_TABLE_C01_OPS"` が要る（指定なしでは既定の 100,000 件で回る。D59 の罠だった——所感参照） | CI ジョブなし（nightly 前提、ローカルで回すもの） |
| cargo-mutants (shirusu-transport 全件) | **実施済み**: 554 件中 caught 431 / missed 75 / unviable 41 / timeout 7。missed のうち 50 件は `#[cfg(kani)]` 証明本体内で cargo test からは原理的に倒せず (Kani が担当)、数件は等価 mutant と判断 (理由を所感に明記)。倒せる中核 mutant はテスト追加で kill 済み (追試で確認) | CI ジョブなし（長時間のためローカルで回すもの） |
| コードカバレッジ (cargo-llvm-cov) | **測定済み (2026-11-12 19:29)**: `cargo llvm-cov --workspace`（`--tests`、doctest 除外）でワークスペース全体 **行 86.62%（23,024 / 26,580 行）**、関数 86.60%、リージョン 85.78%（18:29 回の行 86.60% から上昇）。中核 transport モジュールは clock/context/crc32c/descriptor/layout/notify/slot/snapshot が行 100%。未達行の内訳：Windows 専用コード（fls・agent-dll・transport-win 等、CI の Windows 実走で閉じるもの）、compare/diff・view の残り数行（normalize.rs 99.1%・diff.rs 99.8%・view.rs 99.7% まで 14:29 回のテスト追加で到達。残りは到達不能な防御コードと閉じ行の帰属のクセ——所感参照）。emitter.rs は 276/278 行、writer.rs は 335/362 行（19:29 回に estimate_event_len を削除して 340/367 行から 5 行減。残りは到達不能な None 腕と 256 MiB 超の上限チェック——所感参照）。recorder.rs は 430/443 行（97.07%）まで 16:29 回のテスト追加で到達（残り 8 行は Linux では到達不能——所感参照）。metadata-gen は lib.rs 477/487 行（97.95%）・main.rs 56/56 行（100%）まで 17:29 回のテスト追加で到達（残り 10 行は実 winmd に実例の無い防御コードと winmd 不在時のスキップ腕——所感参照）。CLI バイナリ 4 件は 18:29 回のテスト追加で compare 57/57 行（100%）・conformance 42/42 行（100%）・probe 113/116 行（97.41%）・test 293/294 行（99.66%）まで到達（残りは到達不能な防御コード——所感参照）。e2e は supervisor 実行のため本測定では 0% になる (別途 16 シナリオ通過で確認)。旧行の「e2e 除き全体 98.5%」は Phase 3/4 以前の測定で、今回の全ワークスペース測定と食い違うため訂正した | CI ジョブなし（ローカルで回すもの） |
| cargo-fuzz 4 targets (10 分ずつ) | **長時間実行済み・クラッシュなし**: validate_control 15,132,063 runs/600s、decode_descriptor 16,332,921 runs/600s、decode_payload 12,909,484 runs/600s、snapshot_fragments (4 本目として追加) 404,754 runs/600s、合計約 4478 万 runs。成長したコーパスは hex 種 79 件に書き戻し済み | CI ジョブあり (continue-on-error、短時間版) |
| Phase 2: Trace 形式の単体・PBT・回復意味論テスト (shirusu-trace 88 件 + host 変換 9 件) | **通過**（往復・前方参照禁止・チャンク分割・回復意味論は形式仕様の表の各行に対応するケーステスト、手組みバイト列のテストベクター、破壊入力 PBT） | run #6（2026-11-10、全 12 ジョブ成功）で確認 |
| Phase 2: cargo-fuzz 2 targets (decode_compact / recover_trace) | **実行済み・クラッシュなし**: decode_compact 5,843,310 runs/75s、recover_trace 1,120,017 runs/75s（2026-11-09 ローカル）。test.md の 5 ターゲットが全て揃った | CI ジョブあり (continue-on-error、短時間版) |
| Phase 2: Windows x64 / i686 の cargo check (shirusu-trace / shirusu-host) | **通過**（この VM から両ターゲット。blake3 は `pure` フィーチャで純 Rust 実装に固定——所感参照） | run #6（2026-11-10、全 12 ジョブ成功）で確認 |
| Phase 5: ippai 連携基盤のテスト (emit 8 + conformance 12 + probe 8 = 28 件) | **通過**（エミッタ往復、規約違反注入→該当項目のみ Fail、通しシナリオ「emit→適合→compare→バンドル→ルールが左 pass / 右 fail を再現」、CLI 終了コード。sake 側の実装は本 repo に無く、対象外——所感参照） | run #6（2026-11-10、全 12 ジョブ成功）で確認 |
| Phase 5: Windows x64 / i686 の cargo check (shirusu-emit / shirusu-conformance / shirusu-probe) | **通過**（この VM から両ターゲット。windows-check-targets に matrix.json の最小変更で追加済み） | run #6（2026-11-10、全 12 ジョブ成功）で確認 |
| TLA+ / TLC | **実行済み・エラーなし**: 990,889 状態生成 / 310,249 相異状態 / 深さ 28 / 13s（MaxCursor=4、Generation<=2 の制約下。全 7 不変条件が成立）。Slot 再利用は段階分割（ReclaimBegin → PublishFree）でモデル化し、旧順序の変種モデルでは `ClaimedGenerationIsCurrent` の違反を 924 状態で検出（モデルが競合を表現できる証跡。詳細は docs/verification.md） | CI ジョブあり |
| 待機方式ベンチマーク (shirusu-wait-bench) | **実行済み・選定あり**: 50 ラウンドで event を選定（中央値 14µs / p95 24µs、sleep 方式は中央値 48µs / p95 97µs）。spin / yield は遅延は小さいが CPU を焼くため不採用 | CI ジョブなし（参考計測。ローカルで回すもの） |
| 調整値ベンチマーク (shirusu-tuning-bench, A73) | **実行済み・全既定値を維持**: Ring 容量・BOUNDED_WAIT 上限・再確認周期・復帰閾値・Slot 数を掃引測定し、現行既定値（4096 件 / 1MiB、1ms、2ms、50%、32 スロット・低水位 8）を維持と決定。詳細は「調整値の測定による決定」節 | CI ジョブなし（参考計測。ローカルで回すもの） |

- Fuzz 対象について: 転送側 4 ターゲットに加え、Phase 2 で `decode_compact` と
  `recover_trace`（公開 Trace 形式の復号）を追加し、test.md の対象表 5 件が
  全て揃った。長時間実行の結果は上の表と traceability の F13 / F14 を参照。

### テスト総数（ローカル実測）

`cargo test --workspace` で **2232 件**がローカルで通過
（2026-11-12 07:29 JST に再実行し 2,232 passed / 0 failed を確認。実行ログは goal の hidden_files 参照）。
下の内訳は 1773 件時点（2026-11-09 18:17 測定）の分解で、現在の実測（2142 件）とは
loom 13→18、transport lib 52→54、host lib 21→24、行列 slot 28→29、writer/reader 7→9、
回復意味論 14→15、invalid_handle_width 新規 7 件、F24 の 2 件（container_compact・recovery 各 +1）、F17 の 3 件（recovery +3）、F23 の 3 件（recovery +3）、H14 の 3 件（cli +3）、F21 の 4 件（durability 新規）、F19 の 4 件（schema 2 + hook api 1 + capture 1）、F20 の 9 件（schema 4 + hook api 1 + capture 1 + emit 1 + compare 1 + view 1）、F22 の 5 件（writer/reader 3 + analysis 1 + cli 1）、G15 の 6 件（hook runtime 5 + engine 1）、F18 の 13 件（blob_schema 4 + writer/reader 3 + recovery 4 + conformance 2）、F25 の 3 件（writer/reader +3）、L12 の 8 件（cli +8）、L11 の 24 件（transport 2 + agent 5 + trace 7 + host 3 + cli 6 + hook 1）、A77 の 10 件（e2e lib の検証ロジック）などの増加分で食い違う。
1773 件時点の内訳は 1559 件 + Phase 2 の 78 件
（shirusu-trace 69（proto 16 + container/compact 16 + blob/schema 9 + writer/reader 7 +
回復意味論 14 + テストベクター 3 + PBT 4）+ host 変換 9）+ Phase 3 の 36 件 + Phase 4 の 40 件
+ Phase 5 の 28 件 + 転送層残項目の 8 件 + レビュー第4回対応の 24 件）がローカルで通過
（2026-11-09 18:17 JST に再実行し 1,773 passed / 0 failed を確認）。
内訳は従来分：transport lib 52 + 境界スイート 69 + 仕様表 19 +
PBT 12（参照モデル系 6 + 新規プロパティ 6）+ ストレス 5 + agent 13 + host 21 +
host PBT/DST 3（一時キーの一意性・参照整合性）+ loom 13 +
transport-win 14 + 行列スイート 1304（crc32c 290 + layout 507 + descriptor 163 +
validate 94 + ring 62 + snapshot 55 + slot 28 + notify/clock/context 60 +
host 25 + agent 20）+ レビュー回帰・統合 19（R1 1 + R7 2 + R2 2 + R3 1 + R6 2 +
Agent→検証 Host E2E 2 + レビュー第2回デルタ 9（Reader 多層防御 4 + Clock 分離 5））+ A70 拡張フロー 19（transport Slot 追加 4 + agent 管理スレッド 9 +
host サービス 4 + 往復 E2E 2））がローカルで通過（全実行 約 40 秒）。なお transport lib 52 件には A70 の Slot 追加 4 件が含まれており、A70 拡張フロー 19 件との重複 4 件を除くと内訳の合計は 1559 件になる（総数 1749 件は cargo test の実測と一致）。行列スイートは
拡充第2弾（2026-11-09）で追加したもので、各ケースが境界・状態・エラー経路の
実在の違いを参照式や遷移表と照合する。E2E supervisor のシナリオはプロセス内 15 件 + 子プロセススモーク 1 件の
全 16 件がローカル (Linux) で通過（Windows プロセス間の 3 件＝cross_arch と production_path と memory_order_stress は CI 待ち）。
失敗したテストを緑に見せることはしません。落ちたら原因と直し方を所感に残します。

## 調整値の測定による決定 (A73)

spec 冒頭「リングの容量、Slot 数、待機上限、復帰の閾値は測定で調整する
値であり、変えても安全性やイベントの意味は変わらない」に対応する測定。
ベンチは `e2e/src/bin/shirusu-tuning-bench.rs`（A65 の wait-bench と同じ流儀）。

- 環境: Linux VM（4 CPU、約 8GB）、`cargo run --release -p shirusu-e2e --bin shirusu-tuning-bench -- --rounds 3`。
  3 回実行し、同じ傾向を確認した（数値は 2 回目の中央値。S1/S2/S4/S5 は
  3 回とも概ね 10% 以内で一致。S3 の検出遅延だけ到着位相のランダム化の
  ため実行ごとに 2〜3 割程度ばらつくが、区間の半分に沿う序列は 3 回とも同じ）。
  Windows 実機での数値は CI 待ち。
- S1 の consumer は検証なし RingReader を使う。検証付き DrainWorker は
  回収のたびに像全体をコピーする（D65）ため、容量が大きいほど回収コスト
  が増える——それは容量そのものの効果ではなく検証経路のコストなので、
  容量の掃引からは分離した。この像コピーコスト自体は、Ring を大きくし
  すぎない理由の一つでもある（下記「維持」の根拠）。
- S1b の producer は「書けるだけ書く」ため、欠落率の高さは実運用の損失
  率ではない（実 Hook の発生頻度はこの測定の数百万件/秒には遠く及ばない）。
  比較の意味があるのは同じ offered load での構成間の Published 件数である。

### S1a: Ring 容量 × スループット（consumer は 200µs 周期で回収、50,000 件 × 256B）

| descriptor | payload | 共有メモリ | events/s（中央値） | 欠落 |
|---|---|---|---|---|
| 256 | 256KiB | 272KiB | 約 0.89M | 0 |
| 1024 | 256KiB | 320KiB | 約 2.74M | 0 |
| 4096 | 256KiB | 512KiB | 約 2.67M | 0 |
| 16384 | 256KiB | 1280KiB | 約 2.40M | 0 |
| 256 | 1MiB | 1040KiB | 約 0.87M | 0 |
| 1024 | 1MiB | 1088KiB | 約 2.78M | 0 |
| **4096** | **1MiB（本番既定）** | **1280KiB** | **約 5.70M** | **0** |
| 16384 | 1MiB | 2048KiB | 約 6.04M | 0 |
| 256 | 4MiB | 4112KiB | 約 0.88M | 0 |
| 1024 | 4MiB | 4160KiB | 約 2.79M | 0 |
| 4096 | 4MiB | 4352KiB | 約 5.80M | 0 |
| 16384 | 4MiB | 5120KiB | 約 6.55M | 449 件（0.9%、1 ラウンドのみの外れ値） |

スループットは descriptor 容量ではなく実効深さ `min(descriptor 容量, payload 容量 / 平均 Payload 長)`
で決まる。256KiB payload では 256B/件で最大 1024 件しか入らず、descriptor を
1024 → 16384 に増やしても伸びない（2.4〜2.8M/s で頭打ち。1 回目の 4096 件
2.41M/s に対する 1024 件 2.80M/s の逆転は 2 回目で解消し、ノイズと判断）。
本番既定（4096 件 / 1MiB、実効深さ 4096）は約 5.7M/s で、256 件構成の約 6.5 倍、
1024 件構成の約 2.1 倍。16384 件 / 4MiB は約 6.6M/s とさらに伸びるが、
共有メモリ 4 倍（1280KiB → 5120KiB）に対して +15% 程度でしかない。

### S1b: 遅い Host（5ms 周期で回収）での Published 件数（producer は 2 秒間書き続け）

| descriptor | payload | attempted | published | degraded | dropped（欠落率） |
|---|---|---|---|---|---|
| 256 | 256KiB | 約 6.96M | 約 91k | 1 | 約 6.87M（98.7%） |
| 1024 | 256KiB | 約 6.94M | 約 359k | 2 | 約 6.58M（94.8%） |
| 4096 | 256KiB | 約 0.39M | 約 391k | 1540 | 0（0%） |
| 16384 | 256KiB | 約 0.40M | 約 395k | 1542 | 0（0%） |
| 256 | 1MiB | 約 7.27M | 約 89k | 1 | 約 7.18M（98.8%） |
| 1024 | 1MiB | 約 7.69M | 約 354k | 2 | 約 7.34M（95.4%） |
| **4096** | **1MiB（本番既定）** | **約 7.36M** | **約 1.38M** | **1** | **約 5.99M（81.3%）** |
| 16384 | 1MiB | 約 1.48M | 約 1.48M | 1397 | 0（0%） |
| 256 | 4MiB | 約 7.43M | 約 93k | 3 | 約 7.34M（98.8%） |
| 1024 | 4MiB | 約 7.52M | 約 366k | 2 | 約 7.16M（95.1%） |
| 4096 | 4MiB | 約 7.93M | 約 1.39M | 2 | 約 6.54M（82.4%） |
| 16384 | 4MiB | 約 9.18M | 約 4.55M | 3 | 約 4.63M（50.4%） |

ここで欠落率の差には仕組みがある。payload 容量が先に尽きる構成
（payload 容量 / 256B < descriptor 容量）では、書き手は 1ms の
BOUNDED_WAIT に入って Host の回収を待つため、attempted 自体が抑えられ
欠落はほぼ 0 になる（4096 件 / 256KiB、16384 件 / 1MiB など）。一方
descriptor と payload が同時に尽きる構成（4096 件 / 1MiB など）では
descriptor 空きが無くなり、書き手は待たずに高速で欠落させる。
Published 件数は実効深さにほぼ比例して伸びる（256 件で約 90k →
4096 件 / 1MiB で約 1.38M → 16384 件 / 4MiB で約 4.55M）。本番既定は
5ms 周期の遅い Host でも約 690k 件/秒を通す。欠落率 81% という数字は
producer が 3.6M 件/秒で書き続けた場合のもので、実運用の目安ではない。

### S2: BOUNDED_WAIT 上限（Host が書き手の待機確認から 500µs 後に回収、25 ラウンド）

| max_wait | 再開できた | 再開遅延（中央値 / p95） | 書き手の待機時間（中央値） |
|---|---|---|---|
| 0 | 0/25 | —（待たない） | 0 |
| 0.25ms | 0/25 | —（回収前に期限切れ） | 0 |
| **1ms（既定）** | **25/25** | **68µs / 87µs** | **643µs** |
| 5ms | 25/25 | 72µs / 92µs | 643µs |

Host が 30ms 回収しない場合の、満杯への 1 回の書込の停滞時間（中央値、10 ラウンド）:
0 → 0µs、0.25ms → 313µs、1ms → 1057µs、5ms → 5056µs。
上限ちょうど + 約 57µs（50µs スライス + スケジューリング）で返る。
1ms は 500µs の Host 遅延を 2 倍の余裕で吸収し、5ms は Host が速い
場合の再開遅延が 1ms と同じ（72µs 対 68µs）で、Host が止まった場合の
停滞だけが 5 倍になる。0.25ms は 500µs の遅延に間に合わず全滅する。

### S3: 再確認周期（通知を取りこぼし、データ到着は 1〜21ms でランダム化、25 ラウンド）

| interval | 検出遅延（中央値 / p95） | アイドル時の再確認回数（/100ms） |
|---|---|---|
| 1ms | 648µs / 1210µs | 96 回（約 960 回/秒） |
| **2ms（既定）** | **1506µs / 2136µs** | **51 回（約 510 回/秒）** |
| 5ms | 2151µs / 5222µs | 22 回（約 220 回/秒） |
| 10ms | 4588µs / 9360µs | 12 回（約 120 回/秒） |

検出遅延の中央値はおおむね区間の半分（+ 起床オーバーヘッド）で、区間を
短くするほど検出は速くなるが、アイドル時の wakeup が比例して増える。
2ms は検出遅延の中央値 1.5ms に対して wakeup 約 510 回/秒。1ms にすると
検出は約 0.65ms まで速くなるが wakeup は約 960 回/秒とほぼ倍になる。
（1 回目の測定では到着時刻を 7ms 固定にしており、5ms/10ms が同じ再確認
境界に当たって区間の差が出なかったため、到着時刻をランダム化して測り直した）

なお、2ms は再確認の周期であり回収の上限ではない。待機が終わった後にすぐ
実行されるとは限らないため、2ms 以内の回収は保証しない（p95 2136µs のとおり、
2ms を超える検出遅延も起き得る）。利用側は 2ms 以内の回収を前提にしないこと。

### S4: 復帰閾値（16 件 Ring、Payload 256B/件、決定的測定）

| 復帰閾値 | OVERFLOW から復帰に必要なまとまった回収件数 | 復帰後の headroom（再 OVERFLOW までの Published 数） |
|---|---|---|
| 25% | 13 件 | 12 件 |
| **50%（既定）** | **9 件** | **8 件** |
| 75% | 5 件 | 4 件 |

25% は復帰が遅く（16 件中 13 件の回収が必要）、75% は早く復帰するが
復帰後わずか 4 件で再 OVERFLOW する（フラッピング）。50% は中間で、
9 件の回収で復帰し 8 件の余裕がある。なお、1 件ずつ小刻みに回収して
書く、を繰り返しても 32 回以内ではどの閾値でも復帰しなかった。
OVERFLOW 中は劣化 Descriptor が空いた枠を即座に埋め戻すため、復帰には
使用率が閾値を下回るだけの「まとまった」回収が必要、という実装の性質
そのものが測れた。

### S5: Slot 数・低水位

- 1 Slot あたり 1,310,976 バイト（1280KiB。本番既定 Ring 1 本分）。
  32 スロットの Pool 全体で 41,951,232 バイト（40.0MiB）。
- 32 スロットの claim は 8〜31µs（2 回の測定値。どちらも無視できる速さ）。
- 拡張要求の発火点は設計どおり: 24 件 claim（空き 8 件）では要求 0 回、
  25 件 claim（空き 7 件）で要求 1 回。低水位 8 は「空きが 8 件を切ったら」
  要求を立てる、という意味で、発火後に残る空きは 7 件分ある。

### 決定（全て「維持」。既定値のコード変更なし）

| 調整値 | 採用値 | 根拠 |
|---|---|---|
| Ring 容量（本番既定） | descriptor 4096 件 / payload 1MiB | S1a: 実効深さ 4096 で約 5.7M/s。256 件構成の約 6.5 倍、1024 件構成の約 2.1 倍。16384 件 / 4MiB は +15% 程度しか伸びず、共有メモリは 4 倍（Pool 全体で 40MiB → 160MiB）かつ検証付き回収の像コピーも 4 倍になる。S1b: 遅い Host でも約 690k 件/秒を通す |
| BOUNDED_WAIT 上限 | 1ms | S2: 500µs の Host 遅延を 25/25 で吸収し再開遅延は約 68µs。0.25ms では全滅、5ms では再開は速くならず Host 停止時の停滞だけ 5 倍（約 5.06ms）になる |
| 再確認周期 | 2ms | S3: 検出遅延の中央値約 1.5ms に対してアイドル wakeup 約 510 回/秒。1ms は検出約 0.65ms だが wakeup 約 960 回/秒と倍増。10ms は検出約 4.6ms まで遅くなる |
| 復帰閾値 | 50% | S4: 9 件の回収で復帰し 8 件の余裕。25% は復帰が遅く、75% は 4 件で再 OVERFLOW するフラッピング |
| Slot 数・低水位 | 初期 32・低水位 8 | S5: Pool 全体 40.0MiB と軽く、claim は µs 単位。低水位 8 は 25 件目の claim で発火し、残り 7 件分の余裕を残す。非同期の拡張フロー自体は A70 として実装済み（ローカルで 19 件のテストが通過）だが Windows 実機での CI 検証はまだで、低水位の実効性はその検証次第であることを正直に記録する |
| 通知閾値（notify_threshold_percent） | 50%（現行維持・掃引なし） | 復帰閾値の掃引対象外。通知の発火条件のみで、欠落率や復帰遅延には直接影響しないため今回は測っていない。Host 側の通知頻度の測定と合わせて後で測る余地がある |

## 開発記録

レビュー対応の経緯と実装中の記録は [docs/development-journal.md](docs/development-journal.md) に移しました。

## ライセンス

MIT

依存ライセンス（L21、2026-11-10 17:29 確認）: `cargo metadata` で Cargo.lock の全 94 パッケージの license 欄を確認した。自クレート 16 件はすべて MIT。第三者 78 件はすべて、MIT / Apache-2.0 / BSD-2-Clause / CC0-1.0 / MIT-0 / Unlicense のいずれかを選択肢に含む許容的ライセンスで、コピーレフト単独・非公開のものは無かった（r-efi の LGPL-2.1-or-later は MIT との選択肢の一つ）。一覧は 2026-11-10 17:29 の定時実行ログ（goal hidden_files/2026-11-10-licenses.txt）に保存。依存の版が変われば再確認が必要。
