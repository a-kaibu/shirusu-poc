# ippai 連携契約（shirusu 側基盤と、sake 側エミッタが満たすべき契約）

Phase 5 の成果物と境界を定義する文書。対象読者は (a) sake 側で
Trace エミッタを実装する人、(b) ippai のテストスイートへ回帰
バンドルを取り込む人、(c) shirusu 側の今後の拡張を判断する人。

## 境界（最初に明記する）

- **このリポジトリに ippai / sake のコードは存在しない。**
  本書と Phase 5 のクレートは「shirusu 側で用意できる半分」
  ――エミッタキット、適合性チェッカ、Probe バンドル生成とその
  形式――であり、sake が実際に Trace を出すところは ippai 側の
  実装を待つ。本書のどこにも「sake との統合が動いている」とは
  書かないし、書いてはいけない。
- 最終的な統合（sake への組み込み、ippai のテストスイートでの
  実行）は kota が ippai 側で行う。本書はそのための契約である。
- 線引きは従来どおり：compare が出すのは契約違反の「候補」まで
  であり、Probe バンドルは「再現パッケージ」であって「違反の
  判定」ではない。判定は ippai 側の Probe 実行と人間の調査で行う
  （レビュー第3回 §4）。

## 全体像

```text
Windows 実機                         sake（ippai 側）
  ゲーム実行                           ゲーム実行
  shirusu Agent/Host が記録            sake が記録（本書の契約に従う）
        │                                   │
        ▼                                   ▼
  windows.trace                       sake.trace     ← 公開 Trace 形式 v1
        │                                   │        （docs/trace-format.md）
        └──── shirusu-conformance で両側を検査 ────┘
                          │
                shirusu-compare で差分候補を検出
                          │
                shirusu-probe で候補を最小化
                          ▼
              回帰バンドル（本書「回帰バンドル形式」）
                          │
              ippai の回帰テストへ取り込み（ippai 側の作業）
```

## エミッタ契約（sake 側が満たすべき規約）

番号は契約項目。括弧内は適合性チェッカの検査 ID（自動で確認
できるもの）。契約の正は本節であり、チェッカはその機械化できる
部分を検査するにすぎない。

- **C1 形式**: 出力は公開 Trace 形式 v1（docs/trace-format.md）に
  従う。Block Container、Protobuf メタデータ、Compact Binary、
  Blob の各仕様はそちらが正。（clean-scan）
- **C2 生成者の明示**: CaptureEnvironment の `created_by` に、
  生成した実装とバージョンを入れる（例 `sake 0.3.0`）。空の
  Trace は取り込まない。（environment）
- **C3 セッションの完結**: 記録の終わりには必ず Finalization を
  書き、総数（イベント/Blob/Loss Record）を実内容と一致させる。
  途中で終わった記録は「未完」として区別され、回帰テストの
  根拠には使わない。（finalization / finalization-counts）
- **C4 共有 API セット**: 比較対象の API は共有 API セットに
  登録された Schema で記録する。Schema の同一性は content_hash
  の一致で判定される（後述）。セットに無い API を記録すること
  自体は自由だが、比較の対象にはならない。（schemas-registered）
- **C5 sequence**: スレッドごとに sequence は単調増加（重複なし
  が望ましい）。後退は形式違反。（sequence-monotonic）
- **C6 Enter/Leave 対応**: 呼び出しは CallEnter / CallLeave を
  同じ call_id で対にする。記録終了時点で終了していない呼び
  出しは Leave を捏造せず、Loss Record（kind =
  UNKNOWN_TERMINATION）で表す。（enter-leave-pairing）
- **C7 オブジェクト生成の規約**: オブジェクト（ハンドル）を生成
  する API は、CallLeave の `return` フィールド（Ty::U64）に
  生成した生値を記録する。生成しなかった場合は 0 または全
  ビット 1 を入れ、成功/失敗を区別できるようにする。compare は
  この規約でオブジェクトの同一性を相関させる。逆に「個数を
  U64 で返す」ような API を共有セットへ入れてはいけない
  （生成と誤認される）。個数は Ty::U32 等で記録する。
- **C8 last_error**: CallLeave の最後のフィールドに `last_error`
  （Ty::U32）として GetLastError 相当の値を記録する（本体の
  フック表と同じ規約）。
- **C9 Payload と欠落**: 大きなデータは Blob として格納し、
  参照は必ず解決可能にする（参照だけあって実体が無い Trace は
  不適合）。取得できなかった Payload は黙って落とさず、
  Dropped（元長と理由）として記録し、必要なら Loss Record も
  併記する。（blob-refs-resolvable）
- **C10 完全性の正直な申告**: Finalization の 3 指標
  （Capture Coverage / Event Integrity / Semantic Completeness）
  は実際の記録状況に即して申告する。損失があるのに Complete を
  名乗る Trace は不適合。なお Capture Coverage の真偽は Trace の
  内側からは検証できない（何を観測できなかったかは記録に残ら
  ない）ため、C10 のこの部分は申告者の誠実さに依存する。
  （integrity-consistent）

### 共有 API セットと Schema の同一性

- 共有セットの基準形は shirusu-emit の `file_io_api_set()`
  （本体フック表 = CreateFileW / ReadFile / WriteFile /
  CloseHandle と同一定義）。Schema ID の割当規約は API の登録順
  に 1..=N、Schema は enter = 2n−1 / leave = 2n。
- 同一性の判定は **content_hash の一致**である：別実装が同じ
  名前・同じフィールド列で Schema を生成すれば同じハッシュに
  なり、Trace 間で「同じ API の記録」として突き合わせられる。
  本体側の表が変われば shirusu-emit の照合テストが落ちるので、
  定義の drift は検出できる。
- セットへの API 追加は末尾への追加のみ（既存の ID の意味を
  変えない）。追加は shirusu 側の変更として行い、本体フック表と
  共有セットの両方に同じ定義を入れること。

### エミッタキット（shirusu-emit）の位置づけ

sake 側が Rust で書かれている（または Rust 実装を組み込める）
場合は `shirusu-emit` を使うと C2〜C9 の大半が自動で満たされる
（セッション管理、Schema 登録、sequence 自動採番、CallToken に
よる Enter/Leave 対応、引数の Schema 照合、Finalization の必須
化）。キットは必須ではない：他言語の実装が自前で形式を書き、
`shirusu-conformance` で全項目パスすれば契約上は等価である。
C10 の 3 指標の値だけは、キットを使っても記録側が正直に決める
必要がある（キットは値を発明しない）。

## 適合性チェッカ（shirusu-conformance）

```sh
shirusu-conformance <trace> [--json]
# 終了コード: 0 = 適合、1 = 不適合（Trace として読めない場合を含む）、2 = 使い方/入力エラー
```

検査項目（10 件）の定義と根拠はクレートのモジュール文書が正。
運用上の想定：ippai 側では、記録ペアを作るたびに両側の Trace を
このチェッカに通し、不適合な側は「比較以前の問題」として差分
調査から外す。適合は「形式と規約への適合」であって「振る舞い
の正しさ」の証明ではない。

## 回帰バンドル形式 v1

`shirusu-probe` が生成するディレクトリ構成。ippai 側の
テストスイートは、この構成と manifest の形だけに依存して
取り込める。

```text
<bundle>/
  manifest.json        バンドルの素性と生成結果の要約（機械可読）
  brief.md             Probe ブリーフ（人間向け）
  rules.json           shirusu-test 仕様 v1（識別ルールがある場合のみ）
  replay.json          API 再実行仕様（前提条件が揃う場合のみ）
  left.trimmed.trace   基準側（Windows）のトリム済み Trace
  right.trimmed.trace  被検側（sake）のトリム済み Trace
```

- `manifest.json` の主なフィールド：`format`
  （"shirusu-probe-bundle"）、`version`（1）、`name`、
  `sources`（left / right の表示名）、`candidate`（kind /
  severity / message / api / object / field）、`rules`
  （識別ルールがある場合に file と spec_name と
  `discriminating: true`、無い場合は null）、
  `rule_generation.tried`（試した戦略と結果）、`trimmed`
  （保持イベント数と `candidate_reproduced`）、`notice`
  （候補が断定ではない旨の留保文）。
- `rules.json` は shirusu-test 仕様 v1 そのもの。生成時点で
  「基準側 pass・被検側 fail」が評価で裏付けられている。
- トリム済み Trace は差分の再現用スライスであり、セッション
  全体の記録ではない（その旨は Trace 内の Finalization notes
  にも残る）。`candidate_reproduced` が false のバンドルでは、
  調査は元の Trace ペアで行うこと。
- バンドル名（生成時の `--name`、省略時は候補から導出）は
  ippai 側のテスト名の素になる。取り込み後の改名は自由だが、
  manifest の `name` は生成時の記録として残る。

### Probe 生成の仕組みと限界（正直な現状）

- ルール生成は種別ごとの戦略（欠落呼び出し→api-called、
  戻り値/引数差分→フィールド equals、完全性差分→
  no-integrity-loss、オブジェクト状態差分→object-closed、
  ほか汎用フォールバック）を **両 Trace で実際に評価** し、
  識別が成立した最小の 1 ルールを採用する。推測でルールを
  書くことはしない。
- 現行の shirusu-test ルール形式 v1 では表現できない候補が
  ある：Payload の内容差分、取得状態（Capture）の差分には
  対応するルールが無い。その場合バンドルは rules.json を
  含まない「ブリーフのみ」となり、manifest に試した戦略と
  棄却理由が残る。ルール形式の拡張（v2）は将来の検討事項で
  あり、本書はそれを約束しない。
- トリミングは関与呼び出しの抜き出しであり、再解釈はしない
  （sequence・引数・Payload・Blob ID は元のまま）。ただし
  オブジェクトの序数を保つため、先行する同種オブジェクトの
  生成呼び出しは一緒に残す。

## ippai 側に残る作業（shirusu 側では行わない）

1. **sake 側エミッタの実装**：上記契約（C1〜C10）に従って、
   sake の API 実行から公開 Trace を出す実装。shirusu-emit を
   使うか、自前実装＋適合性チェッカで検証するかは ippai 側の
   選択。
2. **記録ペアの作成運用**：同じゲーム/Probe を Windows 実機と
   sake で実行し、Trace ペアを作る手順（shirusu 側の記録は
   Phase 3 の Host レコーダが担う）。
3. **バンドルの取り込み**：回帰バンドルを ippai のテスト
   スイートの規約に沿って配置し、新しい記録ペアに対して
   `shirusu-test <trace> rules.json` を両側で実行する仕組み。
4. **判定**：候補が本当に API 契約違反かを Probe で切り分け、
   sake を直すか、差異が許容範囲（契約内の非決定性）かを決める
   判断。これは自動化しない前提の、人間と Probe の仕事である。

## 関連

- 公開 Trace 形式：docs/trace-format.md
- クレート：crates/shirusu-emit、crates/shirusu-conformance、
  crates/shirusu-probe、crates/shirusu-compare、crates/shirusu-test
- 背景：レビュー第3回（GOAL.md の「レビュー第3回」節と
  hidden_files のアーカイブ）

### 同期ファイル I/O の再実行仕様

バンドルには、差分候補の基準側イベントが操作するファイルについて、記録された
全ハンドル寿命の操作を再実行する `replay.json` も生成する。閉じた後に開き直す
場合も、前のハンドルによる作成・書き込みを保持する。他のファイルの操作は除く。
元の全呼び出し列を先に検証し、未知の API や副作用を除去して生成可能に見せることは
しない。基準側の根拠イベントが無い候補も生成を拒否する。
`manifest.json` の `replay.kept_source_steps` は元の呼び出し列での 0 始まりの位置、
`target_source_step` / `target_replay_step` は差分の根拠となる呼び出しの位置を示す。
全ファイル履歴を保持する保守的な抽出で、最小化ではない。両環境での再実行も
生成時には行わないため、`minimal` と `execution_verified` は共に false とする。
対応範囲は、単一プロセス・単一スレッドのトップレベル呼び出しで、
`CreateFileW`、`WriteFile`、`ReadFile`、`CloseHandle` の成功した同期操作。
最初のオープンは `CREATE_NEW`、以後は記録内で作成した同じファイルの
`OPEN_EXISTING` に限る。排他的共有、通常属性、GENERIC_READ/WRITE のみ扱う。
非 NULL の `lpOverlapped` は同期ハンドルでも明示位置の指定になり得るため拒否する。
このフィールドが無い旧 Trace も再実行には使わず、不足を報告する。

生成器は記録元のパスを `shirusu-replay-0.bin` 等の相対パスに置き換える。
実行は新しい空の作業ディレクトリで行うこと。ファイルは検査用に残る。
`CREATE_NEW` と `valid-handle` の期待値により、同名ファイルがあると最初の
作成で失敗し後続を実行しない。`valid-handle` は NULL と
INVALID_HANDLE_VALUE の両方を拒否する。元のパスを操作しない。

書き込み内容と位置から読み込み結果を再構成し、記録と一致する場合だけ
仕様を返す。1 回の I/O は 4096 バイト、モデル内の各ファイルは 1 MiB に
制限する。記録の欠落、未対応 API、未知の初期状態、未閉鎖ハンドル等は
`manifest.json` の `replay.missing` に理由を返し、`replay.json` は生成しない。
生成された仕様は既存の `shirusu-test run` と Probe exe 生成で使用できる。
これは差分候補だけへの最小化やアプリ全体の再生を保証するものではない。

フィールド等価ルールでは `{"bytes":[0,255]}` と `{"utf16":[55296]}` も
使える。後者は不正な UTF-16 コード単位を置換せず保存する。未取得・切り詰め・
Stale の値は等価条件の証拠にしない。非同期完了イベントのフィールドも
ルール生成対象に含む。独立した Payload と取得状態そのものの条件は未対応。

Capture Coverage の警告だけでは再実行生成を禁止しない。例えば、対象が
インポートしない API の分だけカバレッジが低くても、記録されたファイル操作の
入出力を復元できる場合がある。元の評価値は manifest の
`replay_source_capture_coverage` に残す。記録されなかった操作の再現を
保証するものではない。Event Integrity と Semantic Completeness の劣化、
Reader の回復 issue、欠落したイベントや入力は生成を禁止する。

### 再現確認を伴う削減のライブラリ API

`shirusu_probe::reduce::reduce_file_io` は `ReplaySlice` と実行側の oracle を受け取り、
対象以外の ReadFile / WriteFile を 1 件ずつ除去する。作成・クローズ・対象呼び出しと
結果を変数に保存する呼び出しは保持する。元の Probe と採用する候補は、同じ対象差分が
2 回連続で確認できた場合だけ採用する。タイムアウト、前提条件不足、Capture 欠落などは
`Inconclusive` として返し、削減を採用しない。実行回数の予算も必須。

oracle は各試行を **両環境の新しい隔離ディレクトリ** で実行し、基準側の期待値成立と
同じ対象差分の維持を判定する必要がある。単なる非ゼロ終了や別の API の失敗では
`SameTargetDifference` を返してはいけない。`Trial` は元の呼び出し位置と、削減後の
対象位置を渡す。証拠となる結果と環境情報の保存は実行側の責務。

この API は実行器を起動せず、CLI と Windows／互換実装の実行器の接続は未実装。
`single_deletion_fixed_point` は追加の単一削除が採用されなかったという意味で、
大域的な最小性やフレーク不在の証明ではない。後の削除で依存が変化した場合は再走査する。


`shirusu_probe::oracle::DifferenceFingerprint` は既存 Runner の `RunReportData` を
削減の判定へ接続する。基準側全体の成功、比較側の対象以前の成功、実行済み・取得完了、
呼び出し位置・名前の一致を確認する。対象は ReadFile / WriteFile / CloseHandle に限定し、
成功可否、転送バイト数、有効な読み取りデータ、失敗時だけの last-error を照合する。
成功時の残留 last-error と未使用バッファ末尾、別実行で変わる生 HANDLE は根拠にしない。
CreateFileW 対象は現段階では判定不能。別の戻り値やデータへの変化は同じ差分としない。

最初の実行ペアから確立した fingerprint は、その後の削減で差分を維持するためのもの。
元 Trace の候補との値の対応付けは呼び出し側で別途必要で、これだけでは元アプリの問題を
再現したとは断定しない。外部実行器の起動・OS/architecture の来歴保存・CLI
接続も引き続き未実装。Windows CI には隔離した 2 回の実 API 実行で同じ結果が得られた
場合、差分を捏造しないテストを追加している。


Runner の JSON は `shirusu_test::parse_runner_report_json` で `RunReportData` へ
読み戻せる。CLI と生成 exe の同じ出力形式を受け付ける。入力は 8 MiB / 65,536 steps、
各バッファ出力は Runner の取得上限までとし、重複キー、欠落・未知の項目、整数範囲外、
不正な hex、矛盾する成功・実行フラグ、未実行なのに値がある報告を拒否する。
標準出力へ混ざったログも JSON として受け付けない。dry-run は読み戻せるが、実行した
証拠ではなく、対象差分の oracle は判定不能にする。外部プロセスからの収集時にも
読み込み上限とタイムアウトを設ける必要があり、パーサだけでは収集を安全に制限しない。
