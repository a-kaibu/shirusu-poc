# 性能目標と測定（L10）

根拠: overview「記録モードと性能目標」節。

## 基準

- 代表的な GUI ワークロードで実行時間の増加を **3 倍以内**、高負荷のケースで
  **5 倍以内**を開発中の評価基準とする。**保証値ではない**。
- 実行時間の倍率とは別に、次も測る。
  - API 一件あたりの追加遅延
  - 記録スループット
  - バッファ使用率
- 短い API（`GetLastError` 的）と数ミリ秒かかる I/O では Hook の相対的な負荷が
  大きく異なるため、倍率だけでは判断できない。短い API 単体の倍率は損益分岐で
  見る（後述）。
- `full` は間引かないモードだが記録を保証するモードではない。欠落したら Trace
  は `incomplete` 扱いになる。

## 短時間の高負荷に備えるバッファ

Windows の `capture` / `attach` は `--buffer burst` を選べる。
例えば `shirusu capture --buffer burst -- game.exe`。既定は
`--buffer standard` で、記録する API や完全性の判定は変わらない。

| 設定 | Ring ごとの Descriptor | Ring ごとの Payload | 既定の本数 | 既定本数の共有 Mapping |
| --- | ---: | ---: | ---: | ---: |
| standard | 4,096件 | 1 MiB | 32 | 約40 MiB |
| burst | 65,536件 | 1 MiB | 16 | 約84 MiB |

Ring の本数は同時に記録できるスレッドの数で、`--rings <1..32>` で変えられる
（2026-11-14 レビュー P1-1。以前は 8 本固定）。Slot を取れなかったスレッドの
呼び出しは記録されず、Agent が全 Ring の Control（オフセット 200）へ掲示する
欠落数を Host が読んで Capture Coverage を Degraded にする。Slot が空くまで、
そのスレッドは取得と登録を間引いてやり直す。

これは共有 Mapping の容量であり RSS ではない。Host の検証用コピー、
回収済みイベントのキュー、変換用バッファなどは別途必要になる。
子プロセスを追跡する場合はプロセスごとに必要。選択された容量は
Trace の `capture_config` に保存し、`shirusu inspect` で確認できる。

`8b6baac` の Windows x64 latest 容量比較では、同じ50,000反復で
standard は3回とも欠落、65,536件構成は3回とも301,028イベントを
欠落なしで保存した。対象内の測定時間はそれぞれ58.2〜60.1 msと
47.0〜50.1 ms。これはライブラリ経由の当該 fixture の実測であり、
高負荷5倍目標の達成や長時間の欠落防止を保証しない。大きいバッファは
一時的な遅れを吸収するが、継続して生産速度が回収速度を上回れば満杯になる。
CI の容量比較では burst 構成を CLI 経由でも実行し、容量の適用と
対象の終了、観測内容を検査する。

CLI 実装後の `f3cc175` / CI `43458190540` でも実行した。各3試行の
保存 artifact の `measurement_complete`、`required_api_observed`、
`integrity.status=complete` と損失0を確認した。

| 環境 | burst 対象内実行時間 | 各試行のイベント数 | 完全な試行 |
| --- | --- | --- | --- |
| x64 latest | 47.50〜49.06 ms | 301,028 | 3/3 |
| x64 Server 2022 | 73.03〜73.57 ms | 300,918 | 3/3 |
| x86 WoW64 | 98.89〜118.22 ms | 301,240 / 301,240 / 301,244 | 3/3 |

同じ run の既定構成では GUI は1.393 / 2.042 / 1.669倍で全試行が完全、
高負荷は36.986 / 40.131 / 48.235倍で欠落あり（上表の環境順）。
burst の実行時間を既定構成の倍率の代わりに採用せず、別の容量比較として残す。


## 測定器

`e2e/src/bin/shirusu-perf-bench.rs`。

使い方: `cargo run -p shirusu-e2e --bin shirusu-perf-bench --release [-- --rounds 3]`

終了コードは常に 0。基準は開発中の評価目標でありゲートではないため、判定が
FAIL でも失敗にしない。判定の読み取りはログで行う。CI の Windows ジョブ
（`scripts/ci/windows.ps1`・`windows-x86.ps1`）では `--rounds 1` で回す。

判定ロジック（基準値・倍率・損益分岐の計算）は `e2e/src/perf.rs` にあり、
テストで固定している。ベンチ本体の数値が変わっても判定の意味は変わらない。

## 方法

- API 本体のコストは校正済みスピンでモデル化する。Linux では実 Windows API
  を呼べないため、`spin_loop` の 1 回あたり時間をベンチ開始時に測り、目標時間
  から反復回数を決める。校正値は出力する。
- 記録経路そのものは本物を使う（Agent・Ring・DrainWorker・TraceRecorder・
  TraceWriter）。Windows の Detour 自体のコストは含まない（F26 の M1 と同じ
  範囲。Detour の実測は L06 / CI の範囲）。
- ワークロードは `e2e/src/perf.rs` の `gui_mix_spec` / `high_load_spec` で
  定義する（決定的）。
  - gui-mix: 短い呼び出し 80%（100ns 級・Payload 無し）・中程度のファイル I/O
    15%（10µs・512B）・長い I/O 5%（500µs・4KiB）。API 本体の加重平均は
    26,580 ns/呼び出し。
  - high-load: 短い呼び出し 50%・中程度の I/O 30%（10µs・4KiB）・長い I/O
    20%（1ms・16KiB）。API 本体の加重平均は 203,050 ns/呼び出し。
  - 1 呼び出しは enter + leave の 2 イベント。enter にだけ Payload を載せる。
- 比率測定の Ring は本番既定（4096 件 / 1MiB）を使う。Host は drain のたびに
  リージョン全体像をコピーするため、Ring サイズがそのまま drain コストになる。
  大きめの Ring（64MiB）で測ると全像コピーが 50 倍になり、比率が水増しされる
  （初回測定で gui-mix 1.300x になったのはこのため。本番サイズでは 1.004x）。
- 回収は 2ms 間隔のポーリング。実 Host は data_ready 通知＋2ms 再確認で回収
  する。プロセス内ベンチでは通知が結線されないためポーリングで代用するが、
  間隔は実運用の再確認周期と同じ 2ms にする。
- TraceRecorder へは 5,000 イベントずつ溜めて渡す。drain のたびに
  `record_batch` を呼ぶと EventChunk が細切れになり、Trace バイト数が
  バッチング依存になる（初回測定で 10.4 B/event になったのはこのため。
  5,000 件ずつでは 5.0 B/event）。
- 消費者スレッドの終了条件は「done 確認を先に行い、最終 drain で全公開を見る」
  順序にする。drain→done 確認の順だと、drain の直後に公開された最後の 1 件を
  落とすレースがある（測定中に 20,000 件中 1 件の取りこぼしで発覚し修正した）。

## 測定値

Linux VM（共有・1.5 CPU）での測定。2026-11-11、`--rounds 3` の中央値。
絶対値はマシン依存の参考値であり、判定の意味は `e2e/src/perf.rs` が固定する。

### L1: API 一件あたりの追加遅延

`Agent::record_enter` + `record_leave` の 1 呼び出しあたり時間。Detour 自体は
含まない。

| 形状 | Payload | ns/呼び出し | 3 倍の損益分岐 | 5 倍の損益分岐 |
| --- | --- | --- | --- | --- |
| no-payload（CloseHandle 的） | 0 B | 273 | 136 ns | 68 ns |
| path（CreateFileW 的） | 100 B | 280 | 140 ns | 70 ns |
| data（ReadFile 的） | 512 B | 286 | 143 ns | 72 ns |
| data（WriteFile 的） | 4 KiB | 530 | 265 ns | 132 ns |

損益分岐は「API 本体がこの時間なら倍率がちょうど上限になる」値。
API 本体がこれより短い呼び出しは、単体で呼べば 3 倍（5 倍）を超える。
`GetLastError` 的な数十 ns の API は単体では上限を超えるが、基準は代表的な
ワークロードに対するものであり、短い API 単体には適用しない（overview の
注記どおり。だからこそ遅延を別に測る）。

### L4 + L2: 実行時間の倍率と記録スループット

| ワークロード | baseline | recorded | 倍率 | 上限 | 判定 | スループット | Trace |
| --- | --- | --- | --- | --- | --- | --- | --- |
| gui-mix | 272.2 ms | 273.3 ms | 1.004x | 3x | PASS | 70,632 ev/s | 99,598 B（5.0 B/event） |
| high-load | 2,035.3 ms | 2,008.5 ms | 0.987x | 5x | PASS | 9,957 ev/s | 109,628 B（5.5 B/event） |

high-load の倍率が 1 を下回るのは測定のぶれである（中央値 3 回・共有 VM。
消費者スレッドが別 CPU で並行するため、記録ありが baseline と同等かわずかに
速く出ることがある）。中間実行では gui-mix 1.030x、high-load 1.221x だった。
いずれも上限の 3 倍・5 倍を大きく下回る。

倍率が上限を大きく下回るのは、モデル化したワークロードでは API 本体コスト
（平均 26.6µs / 203µs）が記録コスト（0.3〜0.5µs/呼び出し）を大きく上回る
ためである。記録コストそのものは L1 の表のとおり。

スループットは記録あり走行の端から端までの壁時間（producer 開始から consumer
の最終回収＋finish 完了まで）で割った値。high-load のスループットが低いのは
API 本体のスピン（1ms 級）が壁時間の大半を占めるためで、記録経路の限界では
ない。Host 処理量そのものの分離測定は F26 の M2 を参照。

### L3: バッファ使用率

本番 Ring（4096 件 / 1MiB）で API 作業なしのバースト（20,000 呼び出し＝
40,000 イベントを記録だけ連打し、2ms 周期で回収）を測ったもの。

| 指標 | 値 |
| --- | --- |
| Descriptor Ring のピーク使用率 | 4,096 / 4,096（100%・満杯） |
| Payload Ring のピーク使用率 | 580,096 / 1,048,576（55%） |
| 回収イベント数 | 32,491 / 40,000 |
| 欠落イベント数 | 7,509（19%） |

2 回の実行で欠落は 7,509〜11,328 イベント（19〜28%）とぶれた（スケジューリング
依存）。これは API 作業なしのモデル測定であり、実ワークロードの欠落率を
予測するものではない。実 Windows の高頻度 API 測定にも欠落が残っている。本番 Ring の容量では
バーストに耐えられないこと自体は確かで、`full` が記録を保証しないことの裏づけ
でもある。欠落した Trace は `incomplete` 扱いになる。

## 限界と今後の課題

- Linux 測定は Detour 自体のコストと実 Windows API のコストを含まない。
  Windows 実機の数値は CI の Windows ジョブで同じバイナリを回し、ログで読む
  （run #7 待ち）。
- バースト測定の回収は 2ms ポーリング。実 Host は data_ready 通知でも回収する
  ため、実運用ではこの測定より回収は速い。通知駆動の回収を含めた測定は今後の
  課題。
- 共有 VM のため絶対値は実行ごとにぶれる。判定は中央値と上限との余裕で読む
  こと。決定（基準値の変更など）に使う場合は、同一マシンでの再測定が必要。


## 部品別の追加測定（追加レビュー 0fc9a82）

`cargo run -p shirusu-e2e --release --bin shirusu-phases-bench` は実装の部品を
単独で 5 回測定し、中央値・最小値・最大値を出す。Windows では Agent と同じ
QPC 時刻源を使い、x64 / x86 の native-performance CI でテキストを artifact に保存する。
Runtime の RwLock + Arc、再入ガード、実行中カウンタ、スレッド登録キャッシュ、
Call ID、時刻取得、HeapAlloc の引数／戻り値符号化を個別に測る。

本番容量の Ring に 128 / 1024 / 3072 イベントずつ書き、公開、Host 回収、
引数検証＋変換＋圧縮＋メモリ出力、回収バッファ解放を分ける。各回の公開成功、
件数、欠落なし、引数の変換成功も検査し、イベントを落として速くなった結果は採用しない。
これは単一プロセス・単一 producer の部品測定であり、同時実行、プロセス間通知、
Detour のパッチ／SEH 境界、ディスク永続化は含まない。測定範囲は重複するため
値を足して実アプリの追加遅延と扱わない。全体の倍率と損失は既存 native fixture で確認する。

Linux x64 の初回参考実測では Ring 公開が約 66 ns/event に対し、1024 イベントの
Host 回収が約 102 ns/event、変換・圧縮が約 320 ns/event だった。小バッチ 128 件では
変換・圧縮が約 902 ns/event に上がった。Host が回収と変換を直列実行する間に
producer が Ring を埋め得るため、符号化を速くするだけでは欠落を解消しない。
Windows での比較は CI 結果を待つ。共有 VM の単発結果だけで最適化方針を確定しない。

Host の通常 Capture は、回収済み引数バッファの所有権を Trace 変換へ移す経路に変更した。
引数として検証できた payload の再確保・コピーと、変換前の参照一覧確保を省く。
既存の借用 API も維持する。部品ベンチは borrowed / transferred を両方測り、
所有権移転ではバッファ解放も変換区間内に含むため、別表示の release と合わせて読む。
正常・不正・空・欠落 payload と Full / Detailed / Profile / Filtered の比較で、
出力 Trace 全体のバイト一致を検査する。これは欠落解消や性能目標達成を意味しない。


`4805f08` / run `43300983104` の Windows x64 / Server 2022 / x86 は通過。
GUI は順に 1.870 / 2.106 / 1.618 倍で欠落なし。高負荷は 141.817 / 140.510 /
160.071 倍で依然 incomplete。部品ベンチの非競合 Runtime 取得は約 9〜22 ns、
3072 件バッチの Host 変換・圧縮は約 370〜490 ns/event だった。単独部品と実際の
競合・通知待ちを混同せず、RwLock の置換だけで全体が解決すると扱わない。

Detour の API ID 検索は全 API 表の走査からコンパイル時索引へ変更した。
索引の ID 重複・範囲外はビルド時に拒否し、全 API の Schema 一致と不明 ID の
拒否をテストする。新しい所有権や遅延初期化は導入しない。Linux 単独測定では
HeapAlloc (ID 72) が約 13.4 → 0.54 ns、末尾 ID 197 が約 54.3 → 0.54 ns。
Windows の同じ測定は CI に追加。これは全体倍率や欠落解消の実測ではない。


### 復元修正後の再測定と Loader Lock の待機設定

`b98c7ca` / CI `43440514975` の x64 高負荷では Host FIFO 満杯 45〜49 回、
回収待機 25.94〜53.17ms を記録した（アプリ計測区間は 114.61〜146.74ms）。
変換 wall time は 121.82〜154.25ms。異なる区間なので合算・差し引きで CPU 時間を推定しない。
3 サンプル中 1 件だけ欠落なし。x86 GUI でも 3 件中 1 件に欠落があった。
CI 自体の成功は性能目標達成を意味しない。

Agent DLL が Writer に LoaderLockState::Unknown を渡す修正を追加する。
初期化が DllMain 外でも、後の Hook 呼び出しが Loader Lock 外だとは証明できないためである。
従来は既定の NotHeld が残り、Unknown 時 0ms というポリシーが実記録に反映されていなかった。
この修正による倍率低下は、欠落なしの同条件測定を伴わない限り性能改善と扱わない。


### 値列検証の scalar fast path

`validate_values_completeness` は文字列等を確保しない検証器だが、scalar でも
大きな TypedValue enum を一度構築していた。scalar では必要な読み取りと範囲検査
だけを行う変更を比較した。I32/U32 の範囲、Bool、固定長、LEB128、取得状態の
検査は維持し、既存 decoder との PBT／fuzz 比較と明示的な異常値テストを用いる。

Linux x64 / Rust 1.100 release、変更前後を交互に 10 組実行し、各実行内 5 回の
中央値を集計した。両方に同じ scalar 検証の測定項目を追加し、基準実装は `1898616`。
HeapAlloc 引数検証は中央値 23.30→13.32ns、戻り値検証は 17.19→9.60ns。
Host の所有権移転経路は 1024 件バッチで 284.84→273.96ns/event、3072 件で
327.49→267.28ns/event。一方 128 件では 447.43→449.08ns/event と改善しない。
3072 件の組ごとの比率は 0.69〜1.08 と変動するため、部品の変化をアプリ全体の
改善率とは扱わない。Windows の同一 fixture と完全性は次の CI で確認する。


### Host FIFO の短時間の詰まりへの余裕

`b98c7ca` の実測で 4 件の Host FIFO が繰り返し満杯になり、回収待機が記録されていた。
件数上限を 16 に増やす比較を行う。各バッチの Ring 上限と、worker の結合上限
4096 イベント／1MiB は維持する。16 件を超えると従来どおり Host が待ち、
アプリ側の Unknown Loader Lock 経路へ待機を戻すことはしない。

既定 Ring の x64 event queue 部分は概算 5.4→21.5MiB。これは allocator、
producer／worker、共有 Ring、環境更新等を除く見積もりで、プロセス RSS ではない。
遅い writer で 17 件目が拒否され、受理済みバッチがすべて保存されるテストを通す。

Linux release の既存 queued-conversion 測定を前後交互に 10 組、各 5 回実行した。
中央値は 47.53→46.33ms、出力は約 4.09→4.07MB。CPU 処理を大幅に短縮する変更とは
扱わない。Windows の同じ GUI／高負荷 fixture で、欠落と Host FIFO 満杯回数を確認する。
この容量変更だけで持続的な処理量不足を解決できるとは扱わない。

16 件 FIFO の `6e53418` は Windows 3 環境の実行検証を通過。x86 の同じ
高負荷 fixture（各 3 試行）では queue full が `31/12/21 → 2/0/9`、
回収待機が `9.37/4.42/6.99 → 0.56/0/6.35ms` だった。高負荷倍率は
Windows x86 49.41、latest x64 50.90、Server 2022 x64 40.19 で、全環境に欠落が残る。
FIFO が一度も満杯にならない試行でも欠落したため、容量だけを増やす対応では
不十分。GUI は今回の 3 環境で 1.44〜1.79 倍、全試行で完全だった。
異なる CI マシン上の前後測定であり、倍率差を容量変更だけの効果とは断定しない。

### Event Chunk の確保サイズ再利用

Writer が Chunk 分割時に算出済みの符号化サイズを、出力 Vec の初期容量へ渡す。
符号化・圧縮方式と分割位置は変えない。小さい容量からの反復拡張を避ける変更で、
公開の単独 encoder に追加のサイズ計算パスは設けない。

16 件 FIFO の Linux queued-conversion を前後交互に 10 組、各 5 回比較したところ、
中央値は 47.66→46.38ms。組ごとの比率は 0.89〜1.05 と重なるので、これだけで
有意な性能改善とは判断しない。Trace の全テスト（サイズ上限、Chunk 分割、
Golden、往復 PBT を含む）と Clippy を通し、Windows 全体は CI で追跡する。

### 本番 Capture の未使用 Payload キー履歴

CaptureSession は検証済みイベントと Payload の所有権を一緒に Writer へ渡すため、
別途保存する TemporaryPayloadKey の履歴を参照しない。従来は RingIdentity を
設定してこの診断用履歴を有効にし、Payload ごとに 5 個の u64 を Ring の寿命中
保持していた。本番経路での有効化を除き、この未使用履歴の線形増加を止める。
低レベル API の明示的なキー収集、世代・Sequence 検証、イベント内容は維持する。
同様に、終了済み call ID の集合は低レベル診断の completed_calls 相関カウンタ
だけが使用しており、本番 Capture の出力・完全性判定では参照しない。本番では
この集合も保存しない。CallCompleted 自体は全件 Trace へ送り、Leave が欠けた
開いた呼び出しを閉じる処理と UnknownTermination の検出は維持する。
低レベル DrainWorker の既定の診断カウンタと明示的キー収集は変更しない。
これは Host 全体のメモリ上限を保証する変更ではなく、未終了の呼び出しや損失履歴、
Writer の索引等は別に残る。

### CRC32C の CPU 命令経路

Trace の CRC32C は Castagnoli の同じ多項式・初期値・最終反転を保持し、
x86/x64 で SSE4.2 を実行時検出できた場合だけ CRC 命令を使用する。
x64 は 8 バイト、x86 は 4 バイトずつ処理し、末尾は 1 バイトずつ処理する。
非対応 CPU と他のアーキテクチャでは既存テーブル実装を使う。Trace 形式は変えない。

標準ベクトル、0〜2048 バイトの全長、先頭位置 0〜7、複数の初期 CRC、
分割継続計算をソフトウェア実装と照合する。従来の継続計算テストは計算結果を
捨てていたため、全体 CRC と実際に一致する assertion へ修正した。

Linux x86_64 release の 16 件 FIFO / 容量再利用済み queued-conversion を
前後交互に 10 組、各 5 回比較し、中央値は 46.71→37.17ms。組ごとの比率は
0.69〜0.92 だった。この測定は 256,000 件をメモリへ出力する Host 部品の値で、
DLL 注入や実アプリの速度、欠落ゼロを示すものではない。Windows の同一
fixture での効果と、非対応 CPU のフォールバックは別に検証する。

`8b6baac` の Windows CI は x86 / latest x64 / Server 2022 x64 とも通過。
GUI はそれぞれ 1.387 / 1.386 / 1.879 倍、全試行で Event Integrity が完全。
高負荷は 44.485 / 37.711 / 45.168 倍で、いずれも欠落が残った。部品の CRC 高速化が
Windows の全環境で同じ倍率改善につながったとは扱わず、5倍目標は引き続き未達。

## 記録経路の再設計（高負荷目標 3倍、2026-11-13）

高負荷の目標は 5倍から 3倍（full モード）へ引き上げた。CI の判定
（`scripts/ci/native-performance.ps1`）も両 workload とも 3倍で読む。

### 変更点

- **イベント時刻**: Ring Writer ごとの `EventTimestamper`（`shirusu-transport::tsc`）が、
  invariant TSC（CPUID 0x80000007 EDX bit 8）を持つ CPU で QPC を約 1ms ごとに
  再アンカーし、間を TSC で補間する。単位は QPC のまま、Writer 内で単調。
  アンカーは TSC と QPC の組を3回読み、TSC の幅が最も狭い組を使う。
  補間誤差はアンカー間隔の小さな割合で、負荷の高いホストではペアリングの
  揺らぎで大きくなる（テストは 30,000 tick の間隔に対し 300 tick 以内で判定）。
  `SHIRUSU_EVENT_CLOCK=qpc` で直接 QPC に戻せる。
- **Host の回収**: 回収スレッドは確定済みの Descriptor と参照先 Payload を
  コピーして、すぐに読み位置を進める（`CommittedRangeCollector`）。検証
  （`DrainWorker::ingest_chunk` → `ValidatingReader::drain_chunk`）と変換は
  Trace worker で行う。コピーした内容は信用せず、`drain_image` と同じ検査で
  矛盾を見つけたら Ring を停止し、以後の解放もしない。旧経路との違いは、
  検証より先に空きを Writer へ返すこと。返すのは Host がすでにコピーした範囲だけ。
- **キュー**: 16 件固定の有界キューをやめ、バイト上限（64bit 256 MiB、32bit
  64 MiB）にした。上限を超えると回収側が待つ（`queue_full` / `drain_wait`）。
  検証状態を読む前（世代交代と停止）にはバリアで全コマンドの処理を待つ。
- **回収の間隔とスレッド優先度**: 容量の 1/8 未満しか回収できなかったら、
  スピンせずに Writer の通知（または poll 間隔）を待つ。Agent の通知閾値は
  使用率 25%。回収スレッドは優先度 Highest、Trace worker（検証・変換）は
  BelowNormal で動かす。2 vCPU の CI ランナーで変換が回収と対象プロセスから
  CPU を奪い、Ring があふれていたため。
- **異常経路の Host 生存確認**: 欠落・劣化イベントごとに呼んでいたシステム
  コール（`WaitForSingleObject`）を、最初の1件と以後 256 件に1回へ間引いた。
- Agent: 落とした Enter が無い間はハッシュ照合を省略、TLS キャッシュから
  Arc を複製せずに書く、生成 Detour のランタイム参照を1つに、ExitThread の
  判定を ID 比較に、生成 API のスカラーを直接エンコード、Ring 位置の計算で
  2 の冪の容量は除算をビット演算に置き換え。

### 計測（`801b914`、CI run 43469123340、x64 Server 2022）

| 項目 | 値 |
| --- | --- |
| Native high-load | 28.451倍（再設計前 約37〜45倍）、3試行中1回は欠落0・Event Integrity 完全 |
| Native gui | 1.652倍、全試行完全 |
| Host のキュー満杯 / 回収待ち | 0回 / 0ms |
| `floor_raw_tsc` | 9.47 ns |
| `floor_call_two_tsc_two_records` | 19.00 ns / 呼び出し |
| `event_timestamp`（補間） / `timestamp`（QPC） | 9.50 / 23.54 ns |
| `ring_publish_batch_3072` | 59.99 ns / イベント |
| `host_collect_release_batch_3072` | 20.54 ns / イベント（旧 drain 125〜150） |
| `typed_detour_two_events` | 190.04 ns / 呼び出し（再設計前 210） |

latest x64 は TSC 補間テストの不安定さで失敗した（`fa76ae5` で修正）。
x86 WoW64 は 35.892倍、`typed_detour_two_events` 272.85 ns。

### 計測（`5bcdb85`、CI run 43478557299、優先度とスピン廃止の後）

| ランナー | Native high-load | 欠落 | `typed_detour_two_events` | `floor_call_two_tsc_two_records` |
| --- | --- | --- | --- | --- |
| x64 latest | 30.382倍 | 3試行とも0 | 251.07 ns | 23.39 ns |
| x64 Server 2022 | 29.702倍 | 3試行とも0 | 188.96 ns | 18.95 ns |
| x86 WoW64 | 29.979倍 | 3試行とも0 | 273.14 ns | 19.19 ns |

全ランナーで Event Integrity 完全（約 301,000 イベント）。Native gui は
1.39〜1.46倍。残る差はほぼ Agent の1呼び出しあたりのコスト
（`typed_detour_two_events`）で、Host 側の欠落と待ちは解消した。

### 3倍の下限

high-load のベースラインは 1呼び出しあたり約 10 ns（50,000 反復 × 3 API、
中央値 約 1.5ms）。3倍に収めるには、追加を約 20 ns / 呼び出しに抑える必要がある。

一方、記録を一切せずに「精密な時刻を2回読み、32 バイトを2回書く」だけの
下限（`floor_call_two_tsc_two_records`）が、CI で 19.0 ns / 呼び出しだった。
フックの入口、再入判定、引数のエンコード、Ring への公開を入れる前に、予算の
9割以上を使い切る。呼び出しごとに Enter と Leave を精密な時刻つきで記録する
full モードでは、この fixture の 3倍はハードウェアの下限で届かない。

この判断は Windows CI の部品計測に基づく。実機の別 CPU では TSC の読み取りコストが
異なり得るが、下限が 1/2 以下になる見込みはない。

### 記録経路の固定費の削減（2026-11-14）

- **クレートをまたぐ呼び出しのインライン化**: Windows の非 LTO ビルドでは、
  layout の load/store、publish guard の TLS、`should_record`、Ring のカーソル読み
  などの小さな関数が、イベントごとに実際の call になっていた。Agent の書き手
  セル（`WriterCell::try_owner`）を所有者の高速経路として inline 化し、publish の
  深さカウンタを Agent の TLS キャッシュに持たせた（1記録あたり TLS 参照1回）。
- **Hazard slot**: 生成 Detour は呼び出しごとにランタイム `Arc` の増減と in-flight
  カウンタの増減（ロック付き命令4回）を払っていた。スレッドごとの hazard slot へ
  通常のストアと非対称フェンスで公開し、slot の revision と記録ゲートを再確認する。
  終了とランタイム差し替えは重いフェンスの後に slot を走査する。
- **スカラーのエンコード**: 生成 API のスカラーを固定 11 バイトの窓へ1回で書く。
- **Detour 入口の TLS 判定**: 入口は毎回、デストラクタを持つ TLS（呼出スタック、
  ランタイムキャッシュ、Agent の書き手キャッシュ。最後のものはクレート越しの
  call）と終了フラグ、キャッシュ準備フラグを確かめていた。全判定に一度通った
  スレッドは `CAPTURE_TLS_LIVE` を立て、以後は深さ1つの確認で入る。これらの
  TLS は破棄の開始時に（Agent のものは teardown hook 経由で）、スレッド終了の
  印でもフラグを下ろす。
- **満杯の Ring の待機**: Agent は Loader Lock の状態を Unknown と申告するため、
  満杯の Ring は待たずに捨てていた。Server 2022 では Host が一瞬遅れただけで、
  高負荷3試行中2回で 600〜770 イベントを失った。Ring Writer は待機の直前だけ
  判定関数を呼ぶ。DLL は `PEB.LoaderLock` の `OwningThread` と TEB のスレッド ID
  を比べる関数を渡す（x64 / x86・WOW64）。保持していないと分かった書き込みは
  `max_wait`（1ms）まで Host の回収を待つ。保持中、または判定できないときは
  従来どおり待たない。

### 計測（`49fe41f`、CI run 43548854674）

| ランナー | Native high-load | 欠落 | `typed_detour_two_events` | `detour_stage_prepare` | `floor_call_two_tsc_two_records` |
| --- | --- | --- | --- | --- | --- |
| x64 latest | 26.252倍（前回 32.847） | 3試行とも0 | 129.69 ns（前回 200.88） | 32.32 ns（前回 53.81） | 16.84 ns（前回 19.15） |
| x64 Server 2022 | 28.512倍（前回 23.030、欠落あり） | 3試行とも0 | 254.10 ns | 63.96 ns | 22.71 ns |
| x86 WoW64 | 30.709倍 | 3試行とも0 | 315.53 ns | 66.99 ns | 23.12 ns |

「前回」は `08f3e21`（run 43544739351）。CI ランナーの速さは同じ種類でも run ごとに
1.3〜1.5 倍ぶれる。変更していない部品（`floor_*`、スカラーのエンコード、Host の
変換）で正規化して比べる。この run の Server 2022 は部品がおよそ 1.2〜2 倍遅い
ランナーに当たったため、その行は前回と直接比べない。latest x64 は下限が 0.88 倍で、
正規化しても `typed_detour_two_events` は約 25%、入口（prepare）は約 30% 減った。
3 ランナーとも高負荷の全試行で欠落 0、Event Integrity 完全になった。

生成 Detour の内訳（latest x64）: 入口 32 ns、2イベント分のエンコード 16 ns、
エンコードと2記録 86 ns、呼出スタック 2 ns。1記録は Ring Writer 単体 17 ns に対し
Agent 経由 30 ns。3倍（追加 約 20 ns / 呼び出し）までは、まだ約 6 倍の開きがある。

### Agent 中継の省略（`dfb9091`、CI run 43559909476）

生成 Detour とファイル I/O の Detour は `Agent::record`（`EventInput` を組んで汎用の
判定を通る）を経由せず、`Agent::record_captured` を直接呼ぶ。高速経路は Agent の
TLS キャッシュを1回借り、書き手セルの所有者確認と publish 区間だけを通って
`write_captured` に書く。Host の起床が要るかは戻り値で返し、通知は cold な関数で
送る。異常な書き込み結果と高速経路に乗らない状態は従来の `record` に落とす。

| ランナー | `layer_ring_writer_write` | `layer_hook_runtime_record`（従来） | `layer_hook_runtime_emit`（新） | Native high-load | 欠落 |
| --- | --- | --- | --- | --- | --- |
| x64 latest | 37.01 ns | 58.24 ns | 37.57 ns | 28.977倍 | 3試行とも0 |
| x64 Server 2022 | 36.00 ns | 65.33 ns | 36.62 ns | 21.514倍 | 3試行とも0 |
| x86 WoW64 | 55.14 ns | 78.61 ns | 93.07 ns | 27.042倍 | 3試行とも0 |

x64 では1記録あたり Agent 中継の約 21〜29 ns が消え、Ring Writer 単体と同じ費用に
なった。WoW64 の行は `layer_agent_record`（107 ns）が、それを内包する
`layer_hook_runtime_record`（79 ns）より遅く、この run の部品計測が乱れているため
判断に使わない。

この run の `floor_call_two_tsc_two_records` は 20.7〜24.0 ns（`49fe41f` の latest
x64 は 16.8 ns）で、ランナーが遅かった。また同じ期間に別の変更（`d7e7b0f`、
Windows 内部からの呼び出しを境界で除外する判定）が Detour 入口に入り、
`detour_stage_prepare` は 57〜67 ns だった。Native high-load の倍率は 21.5〜29.0 倍で、
前回（26.3〜30.7 倍）からランナーのぶれを超える改善は見えない。高負荷の1呼び出しは
記録以外（入口の判定、エンコード、元 API）の費用が大きく、記録の短縮だけでは
3倍に届かない。

## 持続負荷の測定（外部レビュー `4ab9601` の P1、2026-11-14）

`native-performance.ps1` の高負荷ワークロードは有限のバースト（5 万回）であり、Host はアプリの終了後も変換と保存を続けられる。そのため、そこでの「欠落 0」から長時間の連続記録でも欠落 0 になるとは言えない。`scripts/ci/sustained-load.ps1`（`e2e/native/sustained-load.cpp`）は同じ 3 つの呼び出しを一定時間続け、次の指標を別々に記録する。

| 指標 | 内容 |
| --- | --- |
| アプリの処理量 | 1 秒ごとの反復数。記録が時間とともにアプリを遅くするかを見る。無制限の実行では非記録時との比（throughput_ratio）も出す |
| 記録量と Host の処理量 | Trace のイベント数、ループ分の期待イベント数（6 × 反復数）、Host が受け取ったイベントの毎秒量 |
| 欠落率 | 欠落イベント数 ÷ 期待イベント数。欠落を含む Trace が complete と確定したら失敗にする |
| キュー | 変換待ちキューの最大バイト数（`host_queue_peak_bytes`、今回追加）、満杯待ちの回数と時間、アプリの計測区間の後に Host が要した時間（終了時の積み残し） |

実行条件は 50,000 反復/秒（30 万呼び出し/秒）で 10 秒と 30 秒、200,000 反復/秒で 10 秒、無制限で 10 秒（非記録の基準も測る）。Host が追いついていれば、10 秒と 30 秒でキューの最大値と終了時の積み残しはほぼ変わらない。追いつかなければ、どちらも時間に比例して増える。

これは測定であり合否の判定ではない。代表 GUI ワークロードの倍率、1 呼び出しあたりの追加時間（`native-performance.ps1`）とは分けて読む。結果は CI の成果物 `native-performance-*` の `sustained-load-*.json` に残る。
