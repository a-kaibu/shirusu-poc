# Agent–Host転送仕様 v0.4

各スレッドは専用のSPSC Ringへイベントを書き、HostがWindowsのFile Mappingを介して直接取り出す。通常の記録ではプロセス共通のロックもフェンスも使わず、満杯時は既定1msまで待ってから欠落として記録する。

v0.1からの主な変更は次のとおり。

- Descriptorは64バイトで、API識別子とSchema識別子を持つ。Payloadを落としても、どのAPIが呼ばれたかは残る（v0.3）。
- 通知フラグの方式はRelease/Acquireだけでは通知を取りこぼす。Hostは既定2msの周期で再確認する（v0.2）。
- 満杯時は、まずPayloadだけを落として呼び出しの骨格を残す（v0.2）。落とした理由を値ごとに記録する（v0.3）。
- Slotが足りないときは予備Queueを使わず、Capture Coverageの欠落として記録する。予備Queueは安全性を検証できるまで保留する（v0.4）。Ringの再利用は、スレッドの終了をHostが確認してからに限る（v0.4）。
- Hostと共有する値は、書き手が一人でもすべてアトミックにする（v0.3）。
- Hostは共有メモリを信頼せず、自分が知っている範囲だけを読む（v0.2、順序はv0.3で修正）。

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
    pub reserved: u64,
}
// size = 64 bytes（x86とx64で同じ）
```

- 固定幅整数と明示的なアラインメントだけを使い、32bit Agentと64bit Hostが同じレイアウトで読めるようにする。`size_of`と`offset_of`を両ターゲットで静的に検査する。
- Process IDとThread IDはRingの管理情報に持ち、イベントごとには持たない。
- `payload_position`は対象プロセスのポインタではなく、Payload Ring内の単調増加する論理オフセットである。
- Cursorは64bitの単調増加値とし、8バイト境界に置く。i686での64bitアトミック操作（`cmpxchg8b`等で実現される）のコストが問題になれば、32bitの折り返しカウンタに切り替える。

## イベントの確定とPayloadの管理

Descriptorの公開が、そのDescriptorが参照するPayloadの公開も兼ねる。公開点は`write_cursor`一つだけである。

```
書き手（Agent）
  1. read_cursorをAcquireで読み、DescriptorとPayloadの両方に空きがあるか確かめる
  2. Payloadをコピーする（終端をまたぐ場合は末尾と先頭に分けて書く）
  3. Descriptorを書く
  4. write_cursorをReleaseで更新する

読み手（Host）
  1. write_cursorをAcquireで読む
  2. 確定済みのDescriptorとPayloadをHost側へコピーし、検証する
  3. read_cursorとpayload_read_positionをReleaseで更新する
```

PayloadはDescriptorと同じ順に確保されるので、Hostは最後に読んだDescriptorのPayload終端までをまとめて解放できる。格納位置は`payload_position % payload_capacity`で求める。

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
| BOUNDED\_WAIT | 容量不足 | 上限（既定1ms、危険な経路や0ms）まで待つ | 空いた→NORMAL、時間切れ→OVERFLOW |
| OVERFLOW | 待機の時間切れ | 待たずに下の順で劣化させる | 使用率が復帰閾値（例：50%）を下回った→NORMAL |

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

### 予備Queue（保留）

v0.3の予備Queueは、確定しないセルをHostが10msで放棄して再利用する方式だった。これは安全ではない。書き手がセルへデータを書く操作と確定のCASは別なので、止まっていた書き手Aが再開したとき、すでに別の書き手Bが使っているセルを上書きしてからCASに失敗する。CASが保証するのは状態遷移の勝者が一人であることだけで、古い書き手の書き込みが終わったことではない。時間の経過だけでは、遅い書き手と止まった書き手を区別できない。

初版では予備Queueを実装せず、Slot不足はCapture Coverageの欠落とし、Hostの非同期拡張を優先する。将来導入する場合の候補は次のとおりで、TLA+で検証してから採用する。

- 書き手は、セルへの書き込み区間の前後で自分のエポック番号を進める。
- Hostは放棄したセルをすぐには再利用せず隔離し、予約した書き手のエポックが書き込み区間を抜けたこと、またはそのスレッドが終了したことを確認してから戻す。
- 書き手が永久に止まった場合、そのセルは隔離されたままになる。失われるセルは止まったスレッドの数までに限られる。

### 破棄

スレッドが終わってもRingはすぐには再利用せず、`ACTIVE`→`DRAINING`→`RECLAIMABLE`→`FREE`と進める。Hostが未処理のイベントとPayloadをすべて回収してから`FREE`に戻す。

- RingにはGeneration番号を持たせ、同じThread IDを再利用した新しいスレッドと古いRingを混同しない。
- Agentは`DLL_THREAD_DETACH`でRingの状態だけを変える（Loader Lock中なので待たない）。`TerminateThread`などで通知なしに終わったスレッドは、HostがThread Handleの終了で検出する。Hostが公開済みデータを回収し終えるまで、SlotのGenerationを変えて再利用しない。
- 対象プロセスがクラッシュしても、Hostが共有メモリのHandleを持っていれば公開済みのイベントを回収できる。

Ringを再利用できるのは、HostがThread HandleのSignalでそのスレッドの終了を確認し、公開済みデータを回収し終えた後だけである。`DLL_THREAD_DETACH`はDRAININGへの移行の合図にすぎない。DETACHの後も、他のDLLの終了処理がそのスレッドでHook対象のAPIを呼ぶことがあるためである。DETACH後の呼び出しは記録せず欠落として数える。

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
