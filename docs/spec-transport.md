# Agent–Host転送仕様 v0.5

各スレッドは専用のSPSC Ringへイベントを書き、HostがWindowsのFile Mappingを介して直接取り出す。通常の記録ではプロセス共通のロックもフェンスも使わず、満杯時は既定1msまで待ってから欠落として記録する。

v0.1からの主な変更は次のとおり。

- Descriptorは64バイトで、API識別子とSchema識別子を持つ。Payloadを落としても、どのAPIが呼ばれたかは残る（v0.3）。
- 通知フラグの方式はRelease/Acquireだけでは通知を取りこぼす。Hostは既定2msの周期で再確認する（v0.2）。
- 満杯時は、まずPayloadだけを落として呼び出しの骨格を残す（v0.2）。落とした理由を値ごとに記録する（v0.3）。
- Slotが足りないときは予備Queueを使わず、Capture Coverageの欠落として記録する。予備Queueは安全性を検証できるまで保留する（v0.4）。Ringの再利用は、スレッドの終了をHostが確認してからに限る（v0.4）。
- Hostと共有する値は、書き手が一人でもすべてアトミックにする（v0.3）。
- Hostは共有メモリを信頼せず、自分が知っている範囲だけを読む（v0.2、順序はv0.3で修正）。
- Hostは確定済みの範囲を自分のメモリへコピーした時点で領域を書き手へ返し、検証は後から別スレッドで行う（v0.5、「コピー後解放・後検証」）。保証の内容が変わったので、読み手の手順と保証を書き直した。
- `TerminateThread`で終わったスレッドの検出はAgentがスレッドのHandleで行い、記録の途中で止まった書き手のRingを隔離する（v0.5）。書き手の所有権とHazard Slotの非対称同期の契約を明記し、TLA+で検査する（v0.5）。
- 新しいイベントが無くても欠落カウンタが進んだらHostへ渡す（v0.5）。

リングの容量、Slot数、待機上限、復帰の閾値は測定で調整する値であり、変えても安全性やイベントの意味は変わらない。

## 共有メモリとRingの構造

Hostが`CreateFileMapping`で共有メモリを作り、そのHandleを`DuplicateHandle`で対象プロセスへ渡す。名前付きの共有メモリは使わない。

各Ringは、書き手を対象スレッド1本、読み手をHostのDrain Worker 1本とする。Drain Workerを複数にしてもよいが、1つのRingを同時に複数の読み手が扱わないようにする。

| 領域 | 初期容量（スレッドごと） | 用途 |
| --- | --- | --- |
| Descriptor Ring | 256KiB（4096件） | APIの開始・終了、参照情報、Sequence |
| Payload Ring | 1MiB | 引数、文字列、メモリSnapshot |
| Control | キャッシュライン単位で分離 | Cursor、状態、欠落数、Generation |

書き手が更新する値（`write_cursor`など）と読み手が更新する値（`read_cursor`など）は別のキャッシュラインに置き、偽共有を避ける。

```rust
#[repr(C, align(64))]
pub struct EventDescriptor {
    pub kind: u16,
    pub flags: u16,            // Payloadを落とした理由など
    pub payload_len: u32,
    pub sequence: u64,
    pub timestamp_qpc: u64,
    pub call_id: u64,
    pub parent_call_id: u64,
    pub payload_position: u64,
    pub api_id: u32,           // AgentとHostの間の内部ID
    pub schema_id: u32,        // 公開TraceのSchema IDへ変換する
    pub global_order: u64,     // L11: 全スレッド共通の観測順序番号（0 = 未割当）
}
// size = 64 bytes（x86とx64で同じ）
```

- 固定幅整数と明示的なアラインメントだけを使い、32bit Agentと64bit Hostが同じレイアウトで読めるようにする。`size_of`と`offset_of`を両ターゲットで静的に検査する。
- Process IDとThread IDはRingの管理情報に持ち、イベントごとには持たない。
- `payload_position`は対象プロセスのポインタではなく、Payload Ring内の単調増加する論理オフセットである。
- PayloadはAgent–Host間で独立したIDを持たない。Hostは検証済みのRing識別情報、Generation、Sequence、Payloadの論理オフセットから内部管理用の一時キーを生成する。HostがPayloadのBLAKE3を計算してBlobを保存した後、公開TraceではBlob IDを参照する。一時キーは公開形式に含めない（A72 の確定仕様）。一時キーは shirusu-host の `TemporaryPayloadKey`（`process_id: ProcessInstanceId`、`ring_id: RingId`、`generation: u64`、`sequence: u64`、`payload_position: u64`）として実装する。`ring_id` と `generation` は Host が管理する値を用い、Capture Session 内で使う（別 Session と統合する場合は Session ID も含める）。欠落した Payload には一時キーを生成せず、欠落理由を Loss として保持する。~~`reserved` は 0 のままで、検証も維持する。~~（2026-11-11 L11 による修正：64B 中の唯一の空き 8B だった `reserved` を `global_order` に転用した。A72 の中核——Payload ID を持たない・Host 生成の一時キー・公開 Trace は Blob ID——は不変。`global_order` は Payload の識別子ではなく、per-thread `sequence` のプロセス全体版の順序番号である。検証は条件付きで維持する：セッションが全体順序を有効にしていない場合、非 0 は拒否する。詳細は下記「全体順序（L11）」）
- Cursorは64bitの単調増加値とし、8バイト境界に置く。i686での64bitアトミック操作（`cmpxchg8b`等で実現される）のコストが問題になれば、32bitの折り返しカウンタに切り替える。

### 全体順序（L11、2026-11-11）

overview「転送形式とディスク形式」節：`--order=global`を付けると、フックの観測点ごとに全スレッド共通の番号を振る。この番号はアトミックカウンタを更新した順序であり、API処理の完了順やメモリ操作全体の順序を保証しない。別のPCで取ったTraceどうしは時刻の原点が異なるので、時刻だけで対応づけない。

- Agent はプロセス全体で 1 個の `AtomicU64` カウンタ（1 始まり）を持ち、`Agent::record()` 内、書き込み確定の直前（DETACH チェック後）に採番して Descriptor の `global_order`（オフセット 56、64B レイアウト維持）に刻む。書き込みが確定しなかったイベントは番号を消費しない（欠落したイベントの分は欠番になり、Sequence の欠番と同じ扱い）。
- `global_order` は順序番号であって Payload の識別子ではない。A72 の「Payload は Agent–Host 間で独立した ID を持たない」は不変であり、Host の一時キー生成には使わない。
- Host は `CaptureSessionConfig.order_global` が真のセッションでのみ非 0 を受け入れる。無効なセッションで非 0 の Descriptor は `GlobalOrderNotAllowed` として拒否する（旧 `ReservedNonZero` から改名。条件付き検証）。
- Agent DLL への受け渡しは Bootstrap v4 の `order_global: u32` フィールド（0 = 無効。v3 の末尾パディング 4B を埋めたため総サイズ 584 のまま）。
- 公開 Trace 側は `TraceEvent.global_order: Option<u64>`（0 → None）。詳細は trace-format.md「全体順序 (--order=global)」参照。

## イベントの確定とPayloadの管理

Descriptorの公開が、そのDescriptorが参照するPayloadの公開も兼ねる。公開点は`write_cursor`一つだけである。

```
書き手（Agent）
  1. read_cursorをAcquireで読み、DescriptorとPayloadの両方に空きがあるか確かめる
  2. Payloadをコピーする（終端をまたぐ場合は末尾と先頭に分けて書く）
  3. Descriptorを書く
  4. write_cursorをReleaseで更新する

読み手（Host、回収スレッド: CommittedRangeCollector）
  1. write_cursorをAcquireで読む（欠落カウンタも読む）
  2. 確定済みのDescriptorと、それらが参照するPayloadの終端までをHost側へコピーする
     （範囲はHostが知っている容量でだけ制限し、共有メモリの値は信用しない）
  3. payload_read_positionとread_cursorをReleaseで更新する（領域を書き手へ返す）
  4. コピーをTrace Workerへ渡す

読み手（Host、Trace Worker: DrainWorker::ingest_chunk）
  5. コピーしたDescriptorとPayloadを検証し、イベントとして受け入れる
  6. 矛盾があればRingを止め、Event Integrityを失ったとして記録する
```

PayloadはDescriptorと同じ順に確保されるので、Hostは最後に読んだDescriptorのPayload終端までをまとめて解放できる。格納位置は`payload_position % payload_capacity`で求める。

### コピー後解放・後検証の保証（v0.5）

v0.4までは「Hostが検証を終えるまで、書き手はその領域を再利用できない」だった。v0.5では「Hostがコピーを終えれば書き手はその領域を再利用でき、検証は後から行う」になる。高負荷時に検証と変換が回収を遅らせ、Ringが溢れてイベントを失っていたためである（`docs/performance.md`）。

この方式で保証すること:

- Hostが受け入れるイベントは、書き手が公開したイベントの先頭からの並びに一致する。検証はHost自身のコピーだけを読むので、解放後に書き手や対象プロセスが共有メモリを書き換えても、受け入れた内容は変わらない。
- 解放するのはコピーした範囲だけである。Payloadは最後にコピーしたDescriptorが参照する終端までしか解放しない。その先のPayloadは未確定のDescriptorのものかもしれないからである。
- 検証で矛盾を見つけたら、そのChunkはDescriptor 1件も受け入れない。Ringを止め、以後のChunkは受け入れない。回収スレッドは次の回収の前にRingの停止を確かめ、それ以上領域を解放しない。
- 検証が遅れている間に書き手が書いたイベントは、矛盾より後のものとして捨てる。Event IntegrityはLostになり、Traceを完全として確定しない。

保証しないこと: 矛盾を見つけるまでに解放した領域へ、書き手が次のイベントを書くことは止められない。Hostはそれらを受け入れないので、Traceの正しさには影響しない。

欠落カウンタ（`dropped_events`など）だけが進み、新しいDescriptorが無い場合も、回収スレッドはControlだけのChunkを渡す。Ringが溢れた後に何も公開しないまま終わったスレッドや、記録の途中で強制終了した書き手の欠落を、Traceへ確実に残すためである。

この手順は`crates/shirusu-host/tests/deferred_validation_dst.rs`（コピー・解放・遅れた検証・未コピーDescriptorの破壊を混ぜた操作列のDST）と、`crates/shirusu-host/tests/recorder.rs`の`corruption_found_after_release_stops_ring_and_loses_integrity`（解放後に破損が見つかる間も書き手が書き続けるE2E）で検査する。

終端をまたぐコピーを無くしたければ、同じ領域を仮想アドレス上で二重に並べて割り当てる方法がある（`VirtualAlloc2`と`MapViewOfFile3`、Windows 10 1803以降）。Windows 7対応と両立しないので、初版は分割コピーとし、後から最適化として検討する。

### 大きなメモリSnapshot

Payload Ringより大きいPayloadは、Fragmentに分けてそれぞれ独立に公開し、最後に`SnapshotComplete`を書く。最後まで取れたときだけ`Captured`とし、途中で容量不足や読み取りエラーが起きたら、取得済みのFragmentを残して`Truncated`または`Unreadable`で終える。

Fragmentの取得中に別スレッドが元のメモリを書き換えた場合、Snapshot全体が同じ時点の内容である保証はない。この制約もSnapshotに記録する。

## 通知

プロセスをまたぐ通知にはWindowsのEvent Objectを使う。`WaitOnAddress`は同じプロセス内にしか通知できないため使わない。

| Event | 向き | 単位 | 役割 |
| --- | --- | --- | --- |
| `data_ready` | Agent→Host | プロセス | 新しいイベントが公開された |
| `space_available` | Host→Agent | Ring | Ringに空きができた |

### 取りこぼしの問題

v0.1は「Hostが待機前にフラグを立ててRingを再確認し、書き手は公開後にフラグを見て通知する」方式だった。これは両側が「書いてから相手の値を読む」形であり、Release/Acquireだけでは正しく動かない。x86でも書き込みの後の読み出しは前に追い越され得るので、書き手は「フラグが立っていない」を、Hostは「新しいイベントがない」を同時に観測し得る。その結果、Hostは通知が来ないまま待ち続ける。

正しくするには両側に全順序のフェンスが要るが、書き手側ではイベントごとにフェンスを打つことになり、高頻度APIで重い。

### 採用する方式

- `data_ready`はAuto-reset Eventとする。待つDrain Workerは一つで、待っていない間の通知はSignal状態として残る。
- Hostは`data_ready`を時間制限付きで待ち、既定2msの周期でRingを再確認する。通知を取りこぼしても無期限には待たない。ただし、待機が終わった後にすぐ実行されるとは限らないので、2ms以内の回収は保証しない。
- 書き手は公開後にフラグをフェンスなしで読み、立っていれば`SetEvent`する。通常経路にフェンスは入らない。
- Ringの使用率が閾値（例：50%）を下から上へ越えたときに、フラグに関係なく一度だけ`SetEvent`する。閾値を超えている間にイベントごとに繰り返さない。
- 書き手が空きを待つ経路はまれなので、待機の意思を示した後に全順序のフェンスを打ってから空きを再確認する。待機は上限で切れるので、取りこぼしても無限には止まらない。

## 満杯時のポリシーと欠落の記録

満杯になったら、まず上限付きで待ち、それでも空かなければOverflow状態に入る。Overflow中は待たず、十分な空きが戻るまで段階的に劣化させる。

| 状態 | 入る条件 | 動作 | 抜ける条件 |
| --- | --- | --- | --- |
| NORMAL | — | すべて記録する | 容量不足 |
| BOUNDED\_WAIT | 容量不足 | 上限（既定1ms、危険な経路や0ms）まで待つ。Payload Ring 全体より大きい Payload は待っても入らないため待たない | 空いた→NORMAL、時間切れ→OVERFLOW |
| OVERFLOW | 待機の時間切れ | 待たずに下の順で劣化させる | Descriptor と Payload の使用率が両方とも復帰閾値（例：50%）を下回った→NORMAL |

Overflow中の劣化の順序は次のとおりとする。Payload Ringの方が先に埋まりやすいので、Descriptorだけは書けることが多い。

1. Payloadだけを落とし、Descriptorは記録する。値は`Truncated`となり、Semantic Completenessは下がるが呼び出しの構造は残る。
2. Descriptorも書けなければイベントを捨てる。`CallEnter`を捨てた呼び出しは、対応する`CallLeave`も捨てる。`CallEnter`を記録した呼び出しの`CallLeave`が捨てられた場合、Hostはその呼び出しを「欠落により終了不明」として扱う。

Overflow中に待機を繰り返さないのは、Hostが継続的に追いつかないとき、満杯のたびに1ms待つとアプリが秒単位で遅れるからである。待機時間はQPCで実測して記録する。スピン、Yield、Eventでの待機のどれがよいかはベンチマークで選ぶ。

Loader Lockを持っているかは常に判定できるとは限らない。既知の初期化・Loader関連の経路は明示的に待機禁止とし、判定できない場合に0msへ切り替える設定も用意する。

### 欠落の記録

- Sequence番号は、保存に失敗したイベントにも割り当てる。保存されたイベントの欠番が、欠落の根拠になる。
- RingごとのControl領域に、捨てたイベント数、捨てたPayloadバイト数、劣化したイベント数を持つ。書き手が一人でもHostが並行して読むので、すべて`AtomicU64`とし`Relaxed`で更新する。x86 Agentでも値が途中の状態で読まれない。
- カウンタはリセットせず単調増加させる。Hostは前回読んだ値との差分を取る。
- 値ごとの取得結果に、失敗の理由を残す：`MemoryUnreadable`（対象のメモリを読めない）、`CaptureLimitExceeded`（設定した上限を超えた）、`DroppedByBackpressure`（転送が追いつかず捨てた）。Payloadを落とした呼び出しはL1としては扱わない。
- Hostは欠落を公開TraceのLoss Eventとして保存する。Hostが突然終了した場合、最後に回収した以降の欠落情報は失われ得る。その場合はFinalizationが無いことから、完全性を確定できないTraceとして扱う。

## Ringの生成・破棄、再入、Host停止

### 生成

Hostが共有メモリとRing Slotをあらかじめ用意し、Agentは初めて記録するスレッドのために空き SlotをCASで取得する（`FREE`→`CLAIMED`→`ACTIVE`）。共有のアトミック操作が要るのはこの取得時だけである。

- 初期Poolは32 Slotとし、総メモリ上限を設定できるようにする。Slotごとに約1.25MiBなので、32 Slotで約40MiB、256 Slotで約320MiBになる。ページファイルを元にしたFile Mappingは既定でMapping全体のCommitを消費するので、システム全体のCommit使用量にも注意する。
- 空きが低水位（例：残り8）を下回ったらAgentは待たずにHostへ知らせ、Hostが非同期に新しいMappingを作る。MappingのHandleと情報をAgentへ渡し、Agentの管理スレッドが登録を完了して初めて使える。この登録はHookの中では行わない。Mappingの追加中にHostが止まっても、Agentは既存のRingで続ける。
- それでもSlotが無いスレッドの呼び出しは記録せず、Capture Coverageの欠落としてプロセス共通のカウンタ（`fetch_add`のみ）を更新して元のAPIへ戻る。
- プロセス間ではこのカウンタをHostが直接読めないため、Agentは累計を全MappingのControl（Reserved line のオフセット200、`fetch_max`）へ掲示し、Hostは全Ringの最大値をCapture Coverageの欠落として扱う（2026-11-14 レビュー P1-1）。Slotを取れなかったスレッドは、SlotがFREEに戻る（free epochが進む）まで取得を繰り返さず、欠落だけを数える。
- 現行のCLIは低水位時のMapping追加（A70の非同期拡張）を対象プロセスへ結線していない。代わりに起動時のRing本数を既定32本（burstは16本）とし、`--rings`で選べる。

### 予備Queue（保留）

v0.3の予備Queueは、確定しないセルをHostが10msで放棄して再利用する方式だった。これは安全ではない。書き手がセルへデータを書く操作と確定のCASは別なので、止まっていた書き手Aが再開したとき、すでに別の書き手Bが使っているセルを上書きしてからCASに失敗する。CASが保証するのは状態遷移の勝者が一人であることだけで、古い書き手の書き込みが終わったことではない。時間の経過だけでは、遅い書き手と止まった書き手を区別できない。

初版では予備Queueを実装せず、Slot不足はCapture Coverageの欠落とし、Hostの非同期拡張を優先する。将来導入する場合の候補は次のとおりで、TLA+で検証してから採用する。

- 書き手は、セルへの書き込み区間の前後で自分のエポック番号を進める。
- Hostは放棄したセルをすぐには再利用せず隔離し、予約した書き手のエポックが書き込み区間を抜けたこと、またはそのスレッドが終了したことを確認してから戻す。
- 書き手が永久に止まった場合、そのセルは隔離されたままになる。失われるセルは止まったスレッドの数までに限られる。

### 破棄

スレッドが終わってもRingはすぐには再利用せず、`ACTIVE`→`DRAINING`→`RECLAIMABLE`→`FREE`と進める。Hostが未処理のイベントとPayloadをすべて回収してから`FREE`に戻す。

- RingにはGeneration番号を持たせ、同じThread IDを再利用した新しいスレッドと古いRingを混同しない。
- Agentは`DLL_THREAD_DETACH`でRingの状態だけを変える（Loader Lock中なので待たない）。`TerminateThread`などで通知なしに終わったスレッドは、Agentがスレッドの複製Handle（`SYNCHRONIZE`）の終了で検出する（v0.5、下記「強制終了した書き手」）。Hostが公開済みデータを回収し終えるまで、SlotのGenerationを変えて再利用しない。
- 対象プロセスがクラッシュしても、Hostが共有メモリのHandleを持っていれば公開済みのイベントを回収できる。
- 再利用時、AgentはControlをゼロクリアしてから新しいGenerationとMagicを公開する。Hostの回収側は、Magicが0の間やGenerationが変わった後のControlを矛盾として扱わず、何も回収せずに次の回収で世代交代として旧Workerを外す（2026-11-14 レビュー P2-4）。旧Workerの確定（終了不明の確定、完全性報告、Loss の記録）は、その Worker 宛ての回収分を検証し終えた時点で行い、変換キュー全体の完了は待たない。

Ringを再利用できるのは、スレッドの終了をThread HandleのSignal（または終了通知）で確認し、Hostが公開済みデータを回収し終えた後だけである。`DLL_THREAD_DETACH`はDRAININGへの移行の合図にすぎない。DETACHの後も、他のDLLの終了処理がそのスレッドでHook対象のAPIを呼ぶことがあるためである。DETACH後の呼び出しは記録せず欠落として数える。

### 強制終了した書き手（v0.5）

記録の通常経路は書き手の所有権をMutexではなく非対称の同期で取る（下記「非対称同期の契約」）。所有者のスレッドは`owner_busy`を立てて書き、終わったら下ろす。`TerminateThread`はRustの`Drop`もFLSデストラクタも走らせないので、書き手の途中で終了すると`owner_busy`は立ったまま残る。v0.4の実装では、そのRingの排他取得（スレッド終了の処理や、終了したスレッドのIDを再利用した新しいスレッドの記録）が永久に待った。

時間切れで`owner_busy`を下ろすのは安全ではない。一時停止していただけの所有者が再開すると、所有権が重複する。v0.5では次のようにする。

- 所有者は最初に高速経路を取るとき（冷えた経路で1回）、自分のスレッドの複製Handle（`SYNCHRONIZE`のみ）を取る。Handleを持つ間はスレッドIDが再利用されないので、別のスレッドと取り違えない。
- 排他取得は、所有者が生きている間は待つ。待つ間に所有者のHandleがSignal状態（終了済み）になったら待つのをやめる。終了したスレッドは二度と実行されず、その書き込みはすべて完了している。
- 記録の途中で終了していた書き手は「放棄」とし、以後だれも使わない（書きかけのイベントの途中かもしれない）。`remote`を立てたままにして高速経路も閉じる。公開済みのイベントはそのままHostが回収し、書きかけの1件は`dropped_events`に数える。未公開のPayloadは公開しない。回収判定は公開済みDescriptorを読み終えたことだけで行う（Payloadの書き込み位置だけが先に進んでいることがあるため）。
- 所有者は、重い側の操作（Hostが送るRingごとの通知の結び付けなど）が来ている間は、高速経路を降りて排他取得の経路で書く。この経路の排他ロックはMutexではなく、持ち主のスレッド識別子を記録する原子変数とする。所有者がロックを持ったまま終了すると、Mutexではロックが永久に解放されず、そのRingの以後の排他取得（スレッド終了の処理）がすべて止まるためである（v0.5の最初の実装で、WindowsのE2Eが停止した）。ロックを待つ側は、持ち主が所有者で、そのHandleが終了済みを示すときだけ待つのをやめ、書き手を放棄する（`remote`も立てる）。所有者でない持ち主は、生きている限り待つ。
- 新しいスレッドの初回記録で、同じスレッドIDの登録が残っていて所有者が終了済みなら（OSがIDを再利用した）、そのRingを先に退役させてから新しいRingを取る。死んだ所有者の書き手を引き継がない。スレッドの終了で登録をやり直すのは、そのIDと同じ区分のスレッドだけとする。記録中のスレッドが他のスレッドの終了のたびに登録表のロックを取ると、そこで強制終了されたときにロックが残るためである。
- 終了の検出は、新しいスレッドの初回記録でSlotが足りないとき、他のスレッドの終了通知のとき（50msに1回まで）、Shutdownのときに行う。生きているスレッド（一時停止中を含む）のRingには触れず、待ちもしない。
- Hazard Slotも同様に所有者の複製Handleを持つ。終了したスレッドのHazardは走査時に取り下げてSlotを空ける。終了したスレッドはRuntimeを二度と参照しないので、Runtimeを解放してよい。

限界: Hazard Slotを持たないスレッド（Slot表が満杯、TLSの破棄中）は参照カウントと進行中カウンタを使うので、記録の途中で強制終了すると進行中のまま残り、Shutdownは期限切れでINCOMPLETEを返す（Runtimeは解放しないので安全側）。Heapや登録表のロックを持ったまま強制終了したスレッドは、どのWindowsプログラムでも回復できない（`TerminateThread`の既知の制約）。

検査: `crates/shirusu-agent/src/writer_cell.rs`と`crates/shirusu-hook/src/hazard.rs`の単体テスト、`terminated_writer_is_isolated_and_reclaimed`、Windows E2E `scripts/ci/terminate-writer.ps1`（x86/x64、記録中のスレッドを`TerminateThread`で止め、新しいスレッドを作り続ける。ウォッチドッグ付き）。

### 非対称同期の契約（v0.5）

書き手の所有権（`WriterCell`）とHazard Slotは、通常経路の不可分な読み書き更新命令を無くすため、Dekker型の非対称な手順を使う。

| | 軽い側（通常経路） | 重い側（管理経路） |
| --- | --- | --- |
| WriterCell | `owner_busy=true` → コンパイラフェンス → `remote`を読む | `remote=true` → `FlushProcessWriteBuffers`＋全順序フェンス → `owner_busy`が下りるまで待つ |
| Hazard Slot | Runtimeのポインタを置く → コンパイラフェンス → Revisionとゲートを読み直す | Revisionかゲートを変える → 同上 → 全Slotを走査する |

前提:

1. 軽い側のコンパイラフェンスは命令を出さない。軽い側の書き込みは、後続の読み出しの時点でまだStore Bufferにあり得る（Store→Loadの並べ替え）。x86/x64のTSOが許すのはこの並べ替えだけで、手順はこれに耐える必要がある。
2. `FlushProcessWriteBuffers`が戻った時点で、このプロセスのスレッドを実行しているすべてのプロセッサが全順序のバリアを実行している。したがって、それ以前に軽い側が発行した書き込みはすべて重い側から見える。重い側の書き込みは全順序フェンスの後に読み出す。
3. ARM64でも、IPIが軽い側のプログラム順のある点にバリアを入れるという同じ論法が成り立つ。モデルが扱うのはStore→Loadの並べ替えだけであり、ARM64の実機検証は未実施である。
4. Windows以外では軽い側も全順序フェンスを使う。したがってLinuxのテストやloomはWindowsの手順そのものを検査しない。

性質（`tla/AsymmetricHandshake.tla`、TLCで検査）: 所有者と重い側が同時に書き手を使わない（MutualExclusion）、途中で止まった書き手を使わない（NoPoisonedUse）、放棄した書き手の高速経路は閉じたまま（AbandonedStaysClosed）、参照中のRuntimeを解放しない（HazardSafe）、所有者やHazardの持ち主が強制終了しても待ちは終わる（RemoteProgress、ReclaimProgress）。重い側のフラッシュを外した変種、時間切れで奪う変種、終了状態を見ない変種（v0.4の実装）、排他ロックの持ち主の終了を見ない変種（v0.5の最初の実装）では、それぞれ反例が出ることも`scripts/ci/tla.sh`で確かめる。Windows x86/x64の実機では、記録・Shutdown・再Attachを繰り返すストレステスト（`record_shutdown_reattach_stress`、最適化ビルド）を実行する。

### 再入

アプリ由来の入れ子呼び出し（例：`CreateWindowExW`中のWndProcからのAPI呼び出し）はすべて記録し、Agent自身が引き起こした呼び出しは記録しない。イベントを公開している間だけ短い再入ガードを張り、元のAPIを呼ぶ前には外す。これで、元のAPIからのコールバック中の呼び出しも記録できる。

### Hostの停止

AgentはHostのProcess Handleを持ち、容量不足などの異常経路でだけ終了を確認する。Hostの終了を確認したら記録を無効にし、以後のHookは元のAPIへそのまま渡す。Hostへの再接続は初版では扱わない。

## Hostによる共有メモリの検証

共有メモリは対象プロセスの中から書き換えられる。バグのあるアプリがメモリを壊すことも、解析を妨害するアプリが意図的に書き換えることもあり得る。Hostはその中身を信頼しない入力として扱う。

共有メモリ上の値を使ってコピーする前に、必ず範囲を確かめる。例えば`payload_position`が`0xFFFFFFFFFFFFFFFF`、`payload_len`が`0xFFFFFFFF`のままコピーすると、範囲外アクセスや巨大なメモリ確保が起きる。処理の順序は次のとおり。

1. Hostが自分で持っているMappingの大きさとRingの設定から、Descriptor領域の有効範囲を決める。共有メモリ上の設定値は使わない。
2. Cursorをアトミックに読み、後退していないか、占有量が容量を超えていないかを確かめる。
3. 範囲が確定した固定長のDescriptorだけをHost側へコピーする。
4. コピーしたDescriptorの長さ、オフセット、Sequence、Generationを確かめる。
5. 有効な範囲に限ってPayloadをコピーし、内容を確かめる。

確かめた直後に対象プロセスが内容を書き換えることもあり得る。Hostは、一度確かめた値をコピーしたものだけを使い、共有メモリを読み直さない。内容が途中で変わってもメモリ安全性を失わない設計にする。内容が一貫していることまでは保証しない。

矛盾を見つけたらそのRingを止め、Event Integrityを失ったとして記録する。共有メモリを扱う低レベルのコードは小さなモジュールに閉じ込め、正常な書き手との同期と、壊れた入力への耐性を別々にテストする。

共有メモリのセクションには、Hostと対象プロセス以外から開けないアクセス制御を付ける。Host側の解析処理は`cargo-fuzz`の検査対象に含める。

## 不変条件と最初のテスト

APIのHookより先に、複数プロセス間で動くRingと、Agent・Hostの強制終了を含むストレステストを作る。次の不変条件をテストで保証する。

1. Hostは公開前のDescriptorやPayloadを読まない。
2. 書き手はHostが回収していない領域を上書きしない。
3. 通常の記録では、プロセス共通のロックも全順序のフェンスも使わない。
4. AgentはHostを無期限に待たない。Hostも通知を無期限に待たない。
5. イベントを失ったTraceを完全なものとして扱わない。
6. スレッド終了後も、Hostが回収するまでRingを再利用しない。
7. 32bit Agentと64bit Hostが共有メモリを同じレイアウトで解釈する。
8. 対象アプリのクラッシュ時に、確定済みのイベントだけを回収する。
9. 共有メモリが壊されても、Hostは崩れずに欠落として報告する。

| テスト | 確認する内容 |
| --- | --- |
| 1スレッドで大量書き込み | 順序・重複・破損がない |
| 64スレッド同時書き込み | Ring間でデータが混ざらず、Slot不足はCapture Coverageの欠落として記録される |
| 書き手がPayloadを書いた直後に停止 | 公開前のDescriptorをHostが読まない |
| 書き手がDescriptorの公開直前にクラッシュ | 未確定のイベントが回収されない |
| Hostを一時停止 | 待機上限の後、Payloadだけ落とす劣化を経て欠落を記録する |
| Payloadだけが容量不足 | API識別子とCall IDが残り、値は`DroppedByBackpressure`になる |
| Enterを捨てた後にLeaveが発生 | 対応関係を壊さずに欠落を記録する |
| HostがLoss Counterを読む最中に更新 | カウンタが壊れない（x86 Agentでも） |
| DLL\_THREAD\_DETACH後にHook対象のAPIが呼ばれる | スレッドの終了を確認するまでRingが再利用されず、その呼び出しは欠落として数えられる |
| Hostを強制終了 | 対象アプリが続行できる |
| Mappingの追加中にHostが停止 | Agentが既存のRingで続けられる |
| Agentを記録途中で終了 | 確定済みのイベントだけ回収できる |
| 通知の取りこぼし | 通知を意図的に落としても、Hostの再確認で回収される |
| Payloadの終端をまたぐ書き込み | 折り返し後も正しく復元できる |
| 大きなSnapshot | Fragmentの結合と欠落の検出ができる |
| Thread IDの再利用とSlotの再利用 | Generationを越えてイベントが混ざらない |
| x86 Agent＋x64 Host | レイアウトとアトミック操作の動作が一致する |
| Hookの入れ子 | アプリ由来の呼び出しを正しく記録できる |
| 共有メモリの破壊、異常なCursor | 範囲外コピーをせず、Hostが崩れない |
| 解放後の検証で破損が見つかる間も書き手が書き続ける（v0.5） | 破損より後のイベントを受け入れず、Ringを止め、Traceを完全として確定しない |
| 記録中のスレッドを`TerminateThread`で止める（v0.5） | 管理処理が永久に待たず、他のスレッドの記録が続き、放棄した書き手を再利用しない |
| 欠落カウンタだけが進む（v0.5） | 新しいイベントが無くても欠落がTraceに残る |

メモリ順序は、実際のWindowsのプロセス間共有メモリでのストレステストで確かめる。単一プロセス内のユニットテストでは、Handleの寿命やプロセス終了時の挙動は確かめられない。単一プロセス内の並行性は`loom`で網羅的に検査できる。

## クレート構成

最初の実装対象は`shirusu-transport`のSPSC Ringと状態遷移に限る。Hook、公開Traceへの変換、COMはまだ実装しない。

| クレート | 内容 | Windows依存 |
| --- | --- | --- |
| `shirusu-transport` | 共有メモリのレイアウト、SPSC Ring、Payload、Ringの状態遷移、Overflow | なし |
| `shirusu-transport-win` | File Mapping、Handleの受け渡し、Eventによる通知 | あり |
| `shirusu-agent` | 書き手側。スレッドごとのRingの取得と書き込み | あり |
| `shirusu-host` | 読み手側。取り出し、検証、プロセスの監視 | あり |

- 正常な書き手とのRing操作と、壊れた共有メモリを読むHostの検証処理は、同じ抽象APIにまとめない。前者は同期を前提にし、後者は壊れた入力を前提にする。
- 並行性は`loom`で、x86 Agentとx64 Hostの組み合わせは実際のプロセス間ストレステストで検証する。
- Hostの検証処理はWindowsに依存しない関数に分け、`cargo-fuzz`でLinux上でも検査できるようにする。
