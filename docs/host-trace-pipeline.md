# Host の回収・変換パイプライン

CaptureSession は検証済み Ring バッチの所有権を、専用の Trace writer スレッドへ渡す。
回収側が次の Ring を読む間に、worker が前のバッチを変換・圧縮・書き込める。
worker は共有 Ring のポインタを受け取らない。Descriptor と Payload を Host へコピーし、
検証に成功した範囲の read cursor を公開する既存の順序は維持する。

キューはセッションごとに4コマンド。イベント、Loss、環境更新は同じ FIFO を通る。
キュー満杯時は回収側が待つ。キューからイベントを捨てるポリシーは設けない。
Agent 側の Ring が追いつかなくなれば既存の Loss 会計で記録し、欠落を隠さない。

イベントバッチの上限は Ring の Descriptor / Payload 容量に依存する。
キュー内4件に加え、worker が処理中の1件と回収側が送信待ちの1件を持ち得る。
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
