# Host の回収・変換パイプライン

CaptureSession は検証済み Ring バッチの所有権を、専用の Trace writer スレッドへ渡す。
回収側が次の Ring を読む間に、worker が前のバッチを変換・圧縮・書き込める。
worker は共有 Ring のポインタを受け取らない。Descriptor と Payload を Host へコピーし、
検証に成功した範囲の read cursor を公開する既存の順序は維持する。

キューはセッションごとに4コマンド。イベント、Loss、環境更新は同じ FIFO を通る。
キュー満杯時は回収側が待つ。キューからイベントを捨てるポリシーは設けない。
Agent 側の Ring が追いつかなくなれば既存の Loss 会計で記録し、欠落を隠さない。

イベントバッチの上限は Ring の Descriptor / Payload 容量に依存する。
キュー内4件に加え、worker の結合中の最大5件、先読み1件、回収側の送信待ち1件を持ち得る。
worker は同じ文脈の隣接 Events のみ、最大4096イベント・Payload合計1MiBまで結合する。
もともと上限を超える単独バッチは変更せず処理する。新しいデータの到着は待たず、
Loss・環境更新・異なるスレッドやプロセスの文脈を越えて結合しない。
物理的な Trace chunk の境界は変わり得るが、イベントの順序と内容は維持する。
これは固定バイト数のプロセス全体メモリ上限ではない。環境更新や Loss、既存の Ring
snapshot、Trace の圧縮バッファも別に存在する。OS の I/O 自体には新しい時間制限を設けない。

`poll_once` の件数はキューで受理したイベント数であり、永続化完了の通知ではない。
`stop` はキューを閉じ、受理済みコマンドをすべて処理してから、引数取得状態の集計と
Profile を取り出し、Finalization を書く。worker の I/O エラーや panic は poll / stop に
伝え、Finalization を成功として生成しない。セッションを途中で drop した場合も worker
の終了を待つが、正常終了の Finalization は作らない。

Trace の capture_config に `host_pipeline=async-fifo; host_queue_commands=4` を残す。
Full / Detailed / Profile / Filtered について、環境更新と Loss を挟んだ同期処理との
バイト一致を検証する。書き込み失敗、worker panic、低速 Writer による満杯、途中終了、
書き込み失敗後の空 poll も検証する。実アプリの性能は Windows native-performance CI で
測り、この構造変更だけで欠落ゼロや倍率目標の達成を宣言しない。

## 待機と変換の診断値

SessionSummary と capture_config に、worker が処理したコマンド数・受け取ったイベント数・
変換処理の wall-clock 時間、キュー満杯を観測した回数、その後の回収側の送信待ち時間を残す。
CLI の capture / attach の結果にも表示する。キューが空いている通常の送信では、
待機時間計測用の時刻取得を行わない。worker の処理時間はコマンド単位で計測する。

`host_conversion_wall_ns` は変換・圧縮・書き込み・環境更新・Loss の処理中の経過時間で、
スケジューラによる中断も含む。CPU 時間ではなく、キュー受信待ちは含まない。
`host_drain_wait_ns` はキュー満杯を観測した後の送信完了までの経過時間。
これらは並行するため加算して処理時間にはできない。また記録セッション全体の値であり、
性能ターゲットが計測したアプリ内区間と同一ではない。満杯観測ゼロだけでボトルネックを
断定せず、イベント欠落、Ring の状態、実アプリ区間と合わせて判断する。

`host_merged_event_commands` は別のイベントコマンドに結合できたコマンド数。
`host_commands` は結合前の受理コマンド数を保持する。結合上限、文脈の切り替え、
既存の環境更新・Loss 境界、低速 Writer のキュー満杯も回帰テストで確認する。

手動の部品測定は `cargo test -p shirusu-host --release --lib
trace_pipeline::tests::measure_queued_conversion -- --ignored --nocapture`。
2026-11-13 の Linux 実測では128イベント×2000バッチを事前生成し、送信から
Finalization まで測ると、結合なし102–121ms、結合あり68–74ms（各5回）。
結合を再度有効化した別の5回では71–91msだった。
同じ試作コードの結合回数だけをゼロにした比較で、Windows アプリ全体の倍率ではない。

## 待機中のイベントがある場合の圧縮

`host_event_compression=backlog-adaptive` を capture_config に記録する。
worker がすでに届いている Events を結合した、または次の Events を先読みした場合、
今回のグループの Event Chunk は無圧縮で保存する。次のグループで待機 Events が
見つからなければ通常の Zstd 圧縮へ戻る。時間を待って判定する方式ではない。
Loss・環境更新だけが待機している場合は、それを理由に圧縮を省かない。

データの選別やサンプリングは行わず、同じイベント・引数・完全性情報を保存する。
Blob の圧縮、検証、CRC、Index、永続化規則は変えない。既存形式の無圧縮 Chunk
を使うため、Zstd と混在した Trace は既存 Reader で読める。直接使う TraceWriter
の write_batch は従来どおり圧縮を試みる。

`host_compression_bypass_requests` は無圧縮を要求した処理グループ数。
Profile / Filtered ではそのグループが Event Chunk を生成しない場合があるため、
ファイル内の無圧縮 Chunk 数ではない。CLI と性能 artifact にもこの値を残す。

Linux の同じ25.6万イベントの部品測定では46–59msとなった一方、ファイルは
約0.86MBから約4.09MBへ増加した。I/O が遅い保存先では逆効果もあり得るため、
Windows の実アプリ測定と損失数を別途確認する。倍率目標達成の証拠ではない。
