# トレーサビリティ / 網羅チェックリスト

この文書が進捗の分母である。各項目の状態は次で数える。

- `未着手`: コードもテストも無い。
- `実装済み未検証`: コード（またはテスト）はあるが、ローカル＋CI（Windows 項目は GHA windows-latest）の両方で通過を確認していない。
- `検証済み`: ローカルと CI の両方で通過を確認した。

進捗率 = 検証済み項目数 ÷ 全項目数。項目を追加したら分母が増えたことをここに記録する。
現時点の自己申告: 全体で約 3%（仕様読解・接続・CI 配置・push 疎通・骨格着手まで。検証済みはまだほぼ無い）。

最終更新: 2026-11-09（A73 を実装: 調整値の掃引測定（shirusu-tuning-bench）で全既定値を維持と決定。4096 件 / 1MiB、1ms、2ms、50%、32 スロット・低水位 8。Linux VM で 3 回測定し同じ傾向を確認。A72 の修正実装は 10:10 の記録を参照）

## A. spec.md（Agent–Host 転送仕様 v0.4）条項

| ID | 項目 | 実装 | 状態 |
|---|---|---|---|
| A01 | EventDescriptor 64B 固定・repr(C, align(64))・フィールド配置が spec 通り | transport/descriptor.rs | 実装済み未検証 |
| A02 | size_of / offset_of の静的アサーション（x86/x64 同一レイアウト） | transport/descriptor.rs | 実装済み未検証 |
| A03 | Process/Thread ID をイベントごとに持たず Ring 管理情報に持つ | transport/layout.rs (owner_thread_id) | 実装済み未検証 |
| A04 | payload_position は生ポインタでなく単調論理オフセット、位置 = position % capacity | transport/layout.rs, ring.rs | 実装済み未検証 |
| A05 | Cursor は 64bit 単調増加・8 バイト境界 | transport/layout.rs | 実装済み未検証 |
| A06 | Control: writer 更新値と reader 更新値を別キャッシュライン (64B) に分離 | transport/layout.rs | 実装済み未検証 |
| A07 | Descriptor Ring 初期容量 4096 件 / Payload Ring 1MiB（本番既定） | RingConfig::PRODUCTION | 実装済み未検証 |
| A08 | 容量可変（テスト用に容量 2 等の小さい構成が可能） | RingConfig::new | 実装済み未検証 |
| A09 | 公開契約: Payload コピー→Descriptor 書込→write_cursor Release 更新の単一公開点 | transport/ring.rs publish() | 実装済み未検証 |
| A10 | 読取契約: write_cursor Acquire→確定分だけコピー→検証→read_cursor/payload_read_position Release 更新 | transport/ring.rs drain() | 実装済み未検証 |
| A11 | Payload の終端またぎ分割コピー | transport/ring.rs copy_payload_write/read | 実装済み未検証 |
| A12 | 大きな Snapshot: Fragment 分割・個別公開・SnapshotComplete | transport/snapshot.rs | 実装済み未検証 |
| A13 | Snapshot は全部取れたときだけ Captured、途中不足/読取エラーは取得分を残し Truncated/Unreadable | transport/snapshot.rs | 実装済み未検証 |
| A14 | Snapshot の同時点性が保証されない制約を型/フィールドで記録 | SnapshotOutcome.simultaneity_guaranteed | 実装済み未検証 |
| A15 | data_ready はプロセス単位 auto-reset 前提の通知ロジック（OS 非依存部） | transport/notify.rs | 実装済み未検証 |
| A16 | Host は既定 2ms 周期で再確認する（ReCheckPolicy） | transport/notify.rs | 実装済み未検証 |
| A17 | 書き手は公開後にフラグをフェンスなしで読み、立っていれば通知 | notify + ring publish | 実装済み未検証 |
| A18 | 使用率が閾値 (50%) を下から上へ越えたときだけ一度通知 | PublishNotifyTracker | 実装済み未検証 |
| A19 | 通常経路に全順序フェンスを入れない（コード構造） | ring.rs / notify.rs | 実装済み未検証 |
| A20 | space_available は Ring 単位（transport-win 側 Event） | transport-win | 実装済み未検証 |
| A21 | 状態機械 NORMAL→BOUNDED_WAIT→OVERFLOW の遷移条件 | transport/ring.rs | 実装済み未検証 |
| A22 | BOUNDED_WAIT 上限既定 1ms、0 = 待たない | WriterPolicy.max_wait | 実装済み未検証 |
| A23 | Loader Lock 等の危険経路は待機禁止フラグ | WriterPolicy.no_wait_dangerous_path | 実装済み未検証 |
| A24 | OVERFLOW 復帰は使用率が復帰閾値（例 50%）を下回るまで | WriterPolicy.resume_threshold_percent | 実装済み未検証 |
| A25 | Overflow 劣化 (1): Payload だけ落として Descriptor を残す | ring.rs degrade() | 実装済み未検証 |
| A26 | Overflow 劣化 (2): Descriptor も無理ならイベントを捨てる | ring.rs degrade() | 実装済み未検証 |
| A27 | CallEnter を捨てた呼出の CallLeave も捨てる（writer 側追跡） | ring.rs dropped_enter_calls | 実装済み未検証 |
| A28 | Enter あり Leave 欠落は Host 側で「欠落により終了不明」として扱う | host | 実装済み未検証 |
| A29 | Sequence は失敗したイベントにも割り当て、欠番を欠落根拠にする | ring.rs write() / drain gaps | 実装済み未検証 |
| A30 | 待機時間は QPC 相当を Clock 抽象で実測・記録（仮想時計差替え可能） | clock.rs + ring last_wait_ns | 実装済み未検証 |
| A31 | Loss カウンタ群 (dropped_events / dropped_payload_bytes / degraded_events) 単調増加・Relaxed・リセットなし | layout.rs LossCounters | 実装済み未検証 |
| A32 | 値ごとの取得結果 6 状態 (Captured/MemoryUnreadable/CaptureLimitExceeded/DroppedByBackpressure/Truncated/Unsupported) を区別 | CaptureState | 実装済み未検証 |
| A33 | Payload を落とした呼出は L1 扱いしない旨を型で表す | CaptureState::is_l1_eligible | 実装済み未検証 |
| A34 | Host は欠落を Loss Event として生成する | host | 実装済み未検証 |
| A35 | Slot 状態遷移 FREE→CLAIMED→ACTIVE→DRAINING→RECLAIMABLE→FREE、取得時のみ CAS | transport/slot.rs | 実装済み未検証 |
| A36 | Slot は Generation 付き、古い handle は無効 | transport/slot.rs | 実装済み未検証 |
| A37 | 初期 Pool 32、低水位（残り 8）で拡張要求だけ立てる（Hook 中で登録しない） | SlotPool | 実装済み未検証 |
| A38 | Slot 不足時は記録せずプロセス共通カウンタ (fetch_add のみ) を更新し Capture Coverage 欠落 | SlotPool.process_missing_calls | 実装済み未検証 |
| A39 | DETACH は DRAINING 移行のみ。再利用は Host がスレッド終了確認＋回収完了した後だけ | slot.rs host_confirm_ended_and_drained | 実装済み未検証 |
| A40 | DETACH 後の呼出は記録せず欠落カウント | slot.rs note_call_after_detach | 実装済み未検証 |
| A41 | 予備 Queue は実装しない（v0.4 の判断を README に明記） | README | 実装済み未検証 |
| A42 | 再入ガードは公開区間だけの短いガード、元の API 呼出前には外す | transport/context.rs PublishGuard | 実装済み未検証 |
| A43 | Agent 自身の呼出は記録しない／アプリ由来の入れ子は記録する (writer context) | context.rs should_record | 実装済み未検証 |
| A44 | Host 停止は異常経路でのみ生存確認し、停止確認後は記録無効化して素通し | context.rs HostMonitor | 実装済み未検証 |
| A45 | Host 再接続は初版対象外と明記 | README | 実装済み未検証 |
| A46 | Host 検証: 共有メモリ上の設定値を信用せず Host 既知の範囲だけを読む | transport/validate.rs KnownConfig | 実装済み未検証 |
| A47 | Host 検証: Cursor 後退・容量超過を検出する（Payload 位置の前像に対する後退も validate_control で弾く。D57 の fuzz が発見） | validate_cursor_pair / validate_control | 実装済み未検証 |
| A48 | Host 検証: コピーしてから検証し、読み直さない | ValidatingReader | 実装済み未検証 |
| A49 | Host 検証: 矛盾したら Ring 停止＋Event Integrity 喪失として報告 | ValidatingReader.stopped / host | 実装済み未検証 |
| A50 | Host 検証: 範囲外コピーを絶対にしない | decode_payload | 実装済み未検証 |
| A51 | writer 用 API と Host 検証モジュールを分離する（同じ抽象 API にまとめない） | ring.rs vs validate.rs | 実装済み未検証 |
| A52 | CRC32C 実装とテストベクタ | transport/crc32c.rs | 実装済み未検証 |
| A53 | 名前付きでない File Mapping を Host が作り DuplicateHandle で渡す前提の API 形 | transport-win | 実装済み未検証 |
| A54 | MapView と Event Object (data_ready: プロセス単位 auto-reset / space_available: Ring 単位) | transport-win | 実装済み未検証 |
| A55 | transport-win の 2ms 再確認付き待機 | transport-win | 実装済み未検証 |
| A56 | Agent: スレッド毎 Ring 取得・書込、再入ガード適用、Host 生存確認、DETACH 通知 API | agent | 実装済み未検証 |
| A57 | Host: Ring 毎に単一 Drain Worker 前提の取出し | host | 実装済み未検証 |
| A58 | Host: Enter/Leave 対応付けと終了不明判定 | host | 実装済み未検証 |
| A59 | Host: スレッド終了確認後の Slot 解放 | host | 実装済み未検証 |
| A60 | Host: 完全性（Capture/Event/Semantic 相当の transport 範囲）報告 | host | 実装済み未検証 |
| A61 | 空き待ち経路: 待機の意思表示（Control の writer_waiting フラグ）→全順序フェンス→空き再確認。Host は回収で空きができ書き手が待機中なら space_available を SetEvent（`drain_with_space_notify` / `notify_space_if_writer_waiting`） | transport/layout・ring・host・transport-win | 実装済み未検証 |
| A62 | 共有メモリセクションのアクセス制御: Host と対象プロセス以外から開けない DACL（現在ユーザーの SID にだけ GENERIC_ALL を許可）を付けて File Mapping を作成（`SharedMapping::create_restricted`） | transport-win | 実装済み未検証 |
| A63 | Slot Pool の総メモリ上限を設定できる（`with_memory_limit` / `total_memory_bytes` / `can_add_slot`） | transport/slot.rs | 実装済み未検証 |
| A64 | Host 突然終了時: Finalization が無い Trace は完全性を確定できないものとして扱う（`IntegrityLevel::Unknown` / `IntegrityReport::finalized` / `mark_unfinalized`。既知の Degraded/Lost は残す） | host | 実装済み未検証 |
| A65 | 待機方式（スピン / Yield / Event）のベンチマークによる選定 | e2e/src/bin/shirusu-wait-bench.rs（50 ラウンドで Event を選定。中央値 14µs / p95 24µs） | 実装済み未検証 |
| A66 | Host プロセス側の RingNotify–DrainWorker 配線：回収と space_available 通知の結線を `NotifyingDrainWorker` に集約し、E2E シナリオ `space_available_notify` で書き手の待機→回収→再開を end-to-end で確認する | host（NotifyingDrainWorker）・e2e | 実装済み未検証 |
| A67 | 待機方式の選定結果（Event）を書き手が使える形にする：`space_available` を待つ `EventClock`（`Clock` 実装）。Linux スタブの EventObject は 1ms ポーリングだったため condvar ベースの真のブロッキング待機に変更 | transport-win（EventClock・stub EventObject） | 実装済み未検証 |
| A68 | Agent が Host から space_available ハンドルを受け取り EventClock で書く（プロセス間受け渡し。Windows 実機＋GHA で確認） | agent（attach_space_available / attach_space_available_notify）・transport-win（EventObject/RingNotify の duplicate_to_process）・host（NotifyingDrainWorker::duplicate_space_to_process）・e2e（agent_space_available_handoff: event_waits=3・16/16・4.4ms） | 実装済み未検証 |
| A69 | Loader Lock 保持の判定不能時に待機上限を 0ms へ切り替える設定（spec:「判定できない場合に0msへ切り替える設定も用意する」。A23 は既知の危険経路の待機禁止フラグのみで、判定不能時の自動切替設定は WriterPolicy に無い） | transport/ring.rs WriterPolicy::zero_wait_when_loader_lock_unknown（既定 true）＋ LoaderLockState（NotHeld/Held/Unknown）＋ RingWriter::set_loader_lock_state。Held は常に待機せず、Unknown はポリシーに従い 0ms へ（既定で待たない）。Windows の Agent 側からの申告呼び出しは Hook 実装時（PoC 第1スコープ外）に接続する | 実装済み未検証 |
| A70 | 低水位時の非同期 Mapping 追加フロー（Host が非同期に新しい Mapping を作り、Handle と情報を Agent へ渡し、Agent の管理スレッドが登録を完了して初めて使える。Hook の中では登録しない。A37 は低水位フラグ立てのみ、C11 は追加中の Host 停止時の継続のみ） | agent・host・transport-win | 実装済み未検証 |
| A71 | コピー済み Descriptor のフィールド検証（長さ・オフセット・Sequence・Generation。spec Host 検証手順 4。現状 decode_descriptor は Kind/reserved/payload_len のみ検証し、Sequence/Generation の照合が無い） | transport/validate.rs decode_descriptor_checked / DescriptorExpectation / ValidatingReader。Sequence は下限照合（欠番は許す。書き手は 1 から振るため確定済みスロットの 0 は SequenceRegressed）。オフセットは payload_write_position による上限＋前件終端との連続性を照合（落とした Payload は格納長 0 で位置を再利用）。Generation は EventDescriptor にフィールドが無く（spec の Descriptor 定義にも無い）、Control 領域の世代として validate_control / ValidatingReader で照合済み | 実装済み未検証 |
| A72 | 転送用の一時 Payload ID の扱いの決定（設計決定済み、kota 2026-11-09。当初案「`payload_position` を一時 ID とする」を修正: Payload は Agent–Host 間で独立した ID を持たない。Host は検証済み Descriptor と Ring 情報から内部管理用の一時キー `TemporaryPayloadKey { process_id: ProcessInstanceId, ring_id: RingId, generation: u64, sequence: u64, payload_position: u64 }` を回収時に生成する。ring_id と generation は Host が管理する値で、Capture Session 内で使う。欠落した Payload にはキーを生成せず、欠落理由を保持する。一時キーは Host 内部だけで使用し公開 Trace には含めず、Blob 保存後は公開 Trace で Blob ID を参照する。EventDescriptor の 64B レイアウト変更なし、`reserved = 0` の検証も維持） | host（TemporaryPayloadKey / RingIdentity / ProcessInstanceId / RingId、DrainWorker・ValidatingHost の配線）・Unit 5 件（要素ごとの区別・決定的生成・欠落時非生成・再利用時の非衝突）・PBT/DST（host/tests/proptest_keys.rs: 複数 Ring・再利用・位置折り返しでの一意性と参照整合性、Host 再起動混入）・docs/spec-transport.md・overview.md（確定文の記録） | 実装済み未検証 |
| A73 | 転送の調整値（Ring 容量・Slot 数・待機上限・再確認周期・復帰閾値）の測定による決定と根拠の記録（spec 冒頭「測定で調整する値」。A65 は待機方式の選定のみで、他の調整値の測定決定を追跡する項目が無かった） | e2e/src/bin/shirusu-tuning-bench.rs（S1 容量掃引・S2 待機上限・S3 再確認周期・S4 復帰閾値・S5 Slot 数）・README「調整値の測定による決定」節。結論は全既定値を維持（4096 件 / 1MiB、1ms、2ms、50%、32 スロット・低水位 8）。Linux VM で 3 回測定し同じ傾向を確認。通知閾値は掃引対象外として記録。Windows 実機分は CI 待ち | 実装済み未検証 |
| A74 | i686 での 64bit アトミック操作のコスト測定と、問題があれば 32bit の折り返しカウンタへの切替判断（spec Cursor 節:「i686での64bitアトミック操作（cmpxchg8b等で実現される）のコストが問題になれば、32bitの折り返しカウンタに切り替える」。現行は 64bit Cursor のままコスト未測定） | Windows i686 実機・CI での測定 | 未着手 |
| A75 | Payload 終端またぎ分割コピーの最適化検討（VirtualAlloc2＋MapViewOfFile3 による同一領域の二重マッピング。spec:「Windows 7 対応と両立しないので、初版は分割コピーとし、後から最適化として検討する」。初版対象外・将来検討。検討自体が未実施） | 検討記録 | 未着手 |

## B. spec.md 不変条件 9 項目

| ID | 項目 | 検証方法 | 状態 |
|---|---|---|---|
| B01 | Host は公開前の Descriptor/Payload を読まない | Unit/PBT/loom/TLA | 実装済み未検証 |
| B02 | 書き手は Host が回収していない領域を上書きしない | PBT/loom/TLA | 実装済み未検証 |
| B03 | 通常の記録ではプロセス共通ロックも全順序フェンスも使わない | コード構造レビュー＋テスト | 実装済み未検証 |
| B04 | Agent は Host を無期限に待たない。Host も通知を無期限に待たない | Unit (bounded wait / recheck) | 実装済み未検証 |
| B05 | イベントを失った Trace を完全なものとして扱わない | host 完全性報告 | 実装済み未検証 |
| B06 | スレッド終了後も Host が回収するまで Ring を再利用しない | Unit/PBT/TLA | 実装済み未検証 |
| B07 | 32bit Agent と 64bit Host が同じレイアウトで解釈する | 静的アサーション＋GHA WoW64 | 実装済み未検証 |
| B08 | 対象アプリのクラッシュ時に確定済みのイベントだけを回収する | E2E | 実装済み未検証 |
| B09 | 共有メモリが壊されても Host は崩れず欠落として報告する | Fuzz/統合テスト | 実装済み未検証 |

## C. spec.md テスト表 19 項目

| ID | テスト | 状態 |
|---|---|---|
| C01 | 1 スレッドで大量書き込み（順序・重複・破損なし） | 実装済み未検証 |
| C02 | 64 スレッド同時書き込み（Ring 間混線なし、Slot 不足は Coverage 欠落） | 実装済み未検証 |
| C03 | 書き手が Payload を書いた直後に停止（公開前を読まない） | 実装済み未検証 |
| C04 | 書き手が Descriptor 公開直前にクラッシュ（未確定を回収しない） | 実装済み未検証 |
| C05 | Host を一時停止（待機上限後、Payload 劣化を経て欠落記録） | 実装済み未検証 |
| C06 | Payload だけ容量不足（API ID/Call ID が残り値は DroppedByBackpressure） | 実装済み未検証 |
| C07 | Enter を捨てた後に Leave が発生（対応関係を壊さず欠落記録） | 実装済み未検証 |
| C08 | Host が Loss Counter を読む最中に更新（カウンタが壊れない） | 実装済み未検証 |
| C09 | DLL_THREAD_DETACH 後に Hook 対象 API（再利用されず欠落カウント） | 実装済み未検証 |
| C10 | Host を強制終了（対象アプリが続行できる） | 実装済み未検証 |
| C11 | Mapping 追加中に Host が停止（既存 Ring で継続） | 実装済み未検証 |
| C12 | Agent を記録途中で終了（確定済みだけ回収） | 実装済み未検証 |
| C13 | 通知の取りこぼし（再確認で回収） | 実装済み未検証 |
| C14 | Payload の終端をまたぐ書き込み（折り返し復元） | 実装済み未検証 |
| C15 | 大きな Snapshot（Fragment 結合と欠落検出） | 実装済み未検証 |
| C16 | Thread ID 再利用と Slot 再利用（Generation 越え混線なし） | 実装済み未検証 |
| C17 | x86 Agent ＋ x64 Host（レイアウトとアトミック動作の一致、GHA WoW64 で実行） | 実装済み未検証 |
| C18 | Hook の入れ子（アプリ由来を正しく記録） | 実装済み未検証 |
| C19 | 共有メモリの破壊・異常な Cursor（範囲外コピーせず Host が崩れない） | 実装済み未検証 |

## D. test.md 手法別項目

| ID | 項目 | 状態 |
|---|---|---|
| D01 | Unit: Cursor 計算 | 実装済み未検証 |
| D02 | Unit: 容量判定 | 実装済み未検証 |
| D03 | Unit: Descriptor | 実装済み未検証 |
| D04 | Unit: CRC32C | 実装済み未検証 |
| D05 | Unit: 状態遷移（Overflow / Slot） | 実装済み未検証 |
| D06 | PBT: Ring 操作列と VecDeque 参照モデル比較 | 実装済み未検証 |
| D07 | PBT: Fragment | 実装済み未検証 |
| D08 | PBT: Overflow | 実装済み未検証 |
| D09 | PBT: Slot 再利用 | 実装済み未検証 |
| D10 | PBT/DST: 故障操作（仮想時計進行・Host 停止再開・通知欠落・スレッド終了）を混ぜた操作列 | 実装済み未検証 |
| D11 | PBT: 失敗 Seed 保存の方針を文書化 | 実装済み未検証 |
| D12 | loom: 公開/回収の Release/Acquire 網羅検査（小容量、実行して通す） | 実装済み未検証 |
| D13 | loom: 通常メモリも UnsafeCell で追跡するモデル | 実装済み未検証 |
| D14 | Kani: Cursor 演算 harness | 実装済み未検証 |
| D15 | Kani: Host 範囲検証 harness | 実装済み未検証 |
| D16 | Kani を実際に実行する（導入できなければ CI 設定＋未実行の明記） | 実装済み未検証 |
| D17 | Fuzz target: validate_control | 実装済み未検証 |
| D18 | Fuzz target: decode_descriptor | 実装済み未検証 |
| D19 | Fuzz target: decode_payload | 実装済み未検証 |
| D20 | Fuzz: シードコーパスを用意する | 実装済み未検証 |
| D21 | Fuzz を短時間でも実際に実行する（無理なら CI 設定＋未実行の明記） | 実装済み未検証 |
| D22 | Fuzz 対象外 (decode_compact / recover_trace は Trace Reader 対象) の理由を文書化 | 実装済み未検証 |
| D23 | TLA+: SPSC Ring ＋ Slot 再利用＋スレッド終了モデル（容量 2、書手 1〜2、読手 1） | 実装済み未検証 |
| D24 | TLA+: セルの所有/状態/Generation/公開有無を扱う | 実装済み未検証 |
| D25 | TLA+: DETACH 後呼出をモデルに含める | 実装済み未検証 |
| D26 | TLA+ 不変条件 NoUnpublishedRead | 実装済み未検証 |
| D27 | TLA+ 不変条件 NoOverwriteBeforeRelease | 実装済み未検証 |
| D28 | TLA+ 不変条件 ExclusiveCellOwnership | 実装済み未検証 |
| D29 | TLA+ 不変条件 NoStaleProducerWrite | 実装済み未検証 |
| D30 | TLA+ 不変条件 SequenceConsistency | 実装済み未検証 |
| D31 | TLA+ 不変条件 NoPermanentBlocking（進行性: 容量不足なら欠落として前に進む） | 実装済み未検証 |
| D32 | TLA+/TLC を実際に実行する（無理なら週次 CI 設定＋未実行の明記） | 実装済み未検証 |
| D33 | Windows E2E: Test Supervisor が専用プログラムを起動する実コード | 実装済み未検証 |
| D34 | Windows E2E: 同期ポイントはテスト用に有効化でき本番では無効 | 実装済み未検証 |
| D35 | Windows E2E: x86 Agent ＋ x64 Host の別プロセス間 File Mapping 実テスト（GHA） | 実装済み未検証 |
| D36 | Windows E2E: 強制終了シナリオ（Host/Agent/書き手） | 実装済み未検証 |
| D37 | Windows E2E: 通知欠落シナリオ | 実装済み未検証 |
| D38 | Windows E2E: Ring 再利用シナリオ | 実装済み未検証 |
| D39 | CI PR: fmt/clippy/unit/PBT/短 loom/Kani 主要/Fuzz 短/Windows x86・x64 E2E のジョブ構成 | 実装済み未検証 |
| D40 | CI Nightly/週次: 長時間版・多数 Seed・TLA+ のジョブ構成 | 実装済み未検証 |
| D41 | CI を push して全ジョブの結果を確認し、失敗を直すフィードバックループ | 未着手 |
| D42 | Mutation 的観点: テストが本当に検出できるかの確認（任意の弱体化で落ちること） | 実装済み未検証 |
| D43 | テスト大増強: カバレッジ測定 (cargo-llvm-cov) と中核モジュール行 90% 以上化、未達行の理由明記 | 実装済み未検証 |
| D44 | テスト大増強: 境界スイート (Cursor/Payload/Descriptor/BOUNDED_WAIT/容量の体系的境界、tests/boundary.rs) | 実装済み未検証 |
| D45 | テスト大増強: PBT 増強 (主要 1024 cases・DST 512、保存則/Snapshot 故障/通知意味論/Slot 影モデル/Enter-Leave の新規 6 プロパティ) | 実装済み未検証 |
| D46 | テスト大増強: loom 増強 (11 件: Claim 競合・再利用・世代ガード・Dekker 回復性モデル等) | 実装済み未検証 |
| D47 | テスト大増強: Kani 増強 (14 harness: Payload 範囲/Fragment 境界/Cursor 占有/損失差分/Descriptor 安全性) | 実装済み未検証 |
| D48 | テスト大増強: Miri 実行 (transport lib + boundary) と検出 UB の修正 (SharedRegion provenance、画像整列) | 実装済み未検証 |
| D49 | テスト大増強: cargo-mutants 全件実行 (554 件) と中核サバイバーの kill・等価 mutant の理由明記 | 実装済み未検証 |
| D50 | テスト大増強: Fuzz 増強 (4 target × 600 秒、Snapshot Fragment 列の 4 本目追加、成長コーパスの hex 種書き戻し) | 実装済み未検証 |
| D51 | テスト大増強: E2E 増強 (Host 再起動/Producer 公開途中 kill/32 スレッドストーム/100 万ソーク会計/破壊注入/DETACH ストーム、全 16 シナリオ) | 実装済み未検証 |
| D52 | テスト大増強: Stress 増強 (release 1000 万 ops ソーク、env で規模可変) | 実装済み未検証 |
| D53 | DST/PBT 失敗時の証跡保存と縮小ケースの回帰テスト化（verification.md: 失敗時に Seed・リビジョン・テスト構成・操作列・注入故障を保存し、縮小したものを回帰テストに加える。D11 は方針の文書化のみ、loom 失敗スケジュールの回帰化も未実施。Fuzz の最小入力も含む） | 未着手 |
| D54 | Application Verifier の併用（verification.md E2E 節・CI 表リリース前。D33〜D40 に言及なし。Windows E2E での併用と CI への組み込み） | 未着手 |
| D55 | 異なる Windows 環境での確認（verification.md CI 表リリース前「異なる Windows 環境での確認」。D39/D40 は windows-latest のみ） | 未着手 |
| D56 | TLA+ モデルと PBT 参照モデルの実装の独立性（verification.md: 両者は同じ不変条件を共有するが実装は独立させ、実装のバグを参照モデルに写し込まない。D06/D23〜D31 には独立性の担保・確認項目が無い） | 未着手 |
| D57 | Fuzz で受理したデータの不変条件チェック（verification.md: クラッシュしないことに加え、受理したデータが公開 Trace の不変条件を満たすかも確かめる。validate_control: 占有量上限（Descriptor・Payload 両 Ring）＋前後像の単調性（Cursor・Payload 位置・Loss カウンタ）。decode_descriptor: 既知 Kind・reserved 0・長さ上限・64B 像への忠実な再符号化。decode_payload: 落とした Payload は空、それ以外は長さどおりで折り返しを考慮した領域コピーとバイト単位で一致。実装中に fuzz が validate_control の Payload 位置後退の受理という本物の穴を発見し、validate_control に前像との Payload 位置の単調性チェックを追加して回帰テスト化。修正後の短時間 fuzz: validate_control 約 1,060 万 runs / decode_descriptor 約 540 万 runs / decode_payload 約 490 万 runs、クラッシュなし） | 実装済み未検証 |
| D58 | Host 検証ロジック（純粋関数）の macOS での実行（verification.md: 検証ロジックは純粋関数に分け、Linux や macOS でも実行する。CI に macos-latest ジョブ `macos-validation` を追加し、`cargo test -p shirusu-transport` を回す。transport クレートは OS 依存コードを持たない。ローカル VM は Linux のため macOS での実行確認は CI 待ち） | .github/workflows/ci.yml | 実装済み未検証 |
| D59 | Miri で spec_table c01/c08 を小規模で実行する（2026-11-09 08:29 に原因判明・解決: Miri は既定でホストの環境変数を転送しないため `SHIRUSU_SPEC_TABLE_C01_OPS=1 cargo +nightly miri test` は既定の 100,000 件で回っており、「OPS=1 でも 100 秒超」は測定アーティファクトだった。`-Zmiri-env-forward` で転送すると c01 は OPS=200 で 1.86 秒・c08 は OPS=20 で 0.52 秒で通過し、UB 検出なし。誤解を招く doc コメントも修正済み） | 実装済み未検証 |
| D60 | テスト拡充第2弾・算術行列（2026-11-09、kota 指示「local のテストを 1000 件規模に」）: crc32c を長さ 0..=256 でビット単位参照実装と長さごとに照合＋分割更新の等価性 (matrix_crc32c 290 件)。Cursor 演算は容量 {2,4,8} × (write,read) 全順序対を占有量・空きの定義式と照合し、slot/payload_index・usage_percent・RingConfig 配置・LossCounters 差分まで含め matrix_layout 507 件 | crates/shirusu-transport/tests/matrix_crc32c.rs, matrix_layout.rs | 実装済み未検証 |
| D61 | テスト拡充第2弾・Descriptor/検証行列: EventKind 値域、フィールド極値の往復と独立性、CaptureState 全 128 フラグ組合せの優先順位 (matrix_descriptor 163 件)。検証は validate_cursor_pair のちょうど/±1、decode_descriptor の検査順序、decode_payload の回転全剰余、validate_control の像変異、A71 の decode_descriptor_checked の連続性境界 (matrix_validate 92 件) | crates/shirusu-transport/tests/matrix_descriptor.rs, matrix_validate.rs | 実装済み未検証 |
| D62 | テスト拡充第2弾・Ring/Snapshot/Slot/通知行列: 満杯会計・復帰閾値の境界・Enter/Leave 追跡・折り返し分割コピー (matrix_ring 62 件)、Fragment 分割・読み取り故障位置・容量不足・再構成 (matrix_snapshot 55 件)、Slot 状態×操作の遷移表・低水位・メモリ上限 (matrix_slot 27 件)、閾値越え・再確認周期・時刻換算・再入ガード (matrix_notify_clock 60 件) | crates/shirusu-transport/tests/matrix_ring.rs, matrix_snapshot.rs, matrix_slot.rs, matrix_notify_clock.rs | 実装済み未検証 |
| D63 | テスト拡充第2弾・Host/Agent 行列と変異スポットチェック: TemporaryPayloadKey の 5 要素直積 32 通りの分離、Enter/Leave 対応付けパターン、Loss カウンタの段階差分 (matrix_host 25 件)。Agent の record 分岐優先順位・detach/forget・Payload サイズ境界 (matrix_agent 20 件)。変異スポットチェック 3 件（occupancy の被減数入替、decode_descriptor の `>`→`>=`、復帰判定の `<`→`<=`）を入れ、いずれも新規行列が検出することを確認して復元した | crates/shirusu-host/tests/matrix_host.rs, crates/shirusu-agent/tests/matrix_agent.rs | 実装済み未検証 |
| D64 | レビュー R3 (P0): Slot host_reclaim 競合の修正。RECLAIMING 状態を導入し、Generation 加算と所有者クリアを回収排他下で行ってから FREE を Release で最後に公開する。docstring の記述順序と実装を一致させた | crates/shirusu-transport/src/slot.rs、crates/shirusu-transport/tests/regression_r3.rs (実 SlotPool の並行ストレスで同一世代の二重発行を検出)、D71 の loom 転写モデルと対 | 実装済み未検証 |
| D65 | レビュー R2 (P0): Host 回収経路の検証統一。通常の DrainWorker が無検証の RingReader::drain を使っていたのを廃し、像へコピー → ValidatingReader で検証 → 検証が通った分だけ共有 Cursor を前進させる方式に統一した (snapshot の drain_image が通常経路そのものになった)。RingReader はテスト専用/信頼済み内部用に格下げ (doc 明示)。drain_shared (実 File Mapping ビュー) と resume_from_shared を追加。Sequence 欠落の数え上げは ValidatingReader へ一元化。A72 の TemporaryPayloadKey 発行は統一後の経路でも維持 (回帰テストで確認) | crates/shirusu-host/src/lib.rs、crates/shirusu-transport/src/validate.rs (drain_image_up_to / resume_from_image / take_sequence_gaps)、crates/shirusu-host/tests/regression_r2.rs (破損 Descriptor 注入で旧経路は素通り・新経路は停止) | 実装済み未検証 |
| D66 | レビュー R1 (P0): Agent の全体 Mutex 除去。record は TLS 高速経路で自 Ring の状態へ直接進み、ロックは Ring ごとの writer Mutex のみ。登録・回収は RwLock 管理パスに分離し、thread_detach も全体ロックを取らない。満杯 Ring で BOUNDED_WAIT に入ったスレッドが他スレッドの record を止めないことを時間で測る回帰 | crates/shirusu-agent/src/lib.rs、crates/shirusu-agent/tests/regression_r1.rs | 実装済み未検証 |
| D67 | レビュー R7 (P1): space_available の Ring ごと化。RingNotify + EventClock を Ring 作成時に writer へ束縛する形にし、attach API はスレッド単位にした (開始後でも当該 Ring だけ差し替え可)。RingWriter::set_clock を追加。旧 API は「Ring ごとに束ねる」こと自体を表現できず修正前コードでの再現テストは不可能だったため、新 API の結線テストで担保する (正直な限界として記録) | crates/shirusu-agent/src/lib.rs、crates/shirusu-transport/src/ring.rs、crates/shirusu-agent/tests/regression_r7.rs | 実装済み未検証 |
| D68 | レビュー R6 (P1): decode_descriptor の劣化イベント誤拒否の修正。PAYLOAD_DROPPED は格納長 0 として検証し、元の長さは容量と比べない。元の長さの受理上限は MAX_DROPPED_ORIGINAL_LEN = u32 最大値と明示し、writer は元の長さを u32 へ切り捨てず飽和させる (payload_len_u32)。正確な欠落バイト数は u64 の Loss カウンタが持つ。decode_descriptor_checked も基底修正で追随。matrix_validate の性格付けは誤った振る舞いを固定していたのではなく境界値のケースだったため、dropped の受理ケースを明示追加して契約を固定した | crates/shirusu-transport/src/validate.rs、crates/shirusu-transport/src/ring.rs、crates/shirusu-transport/tests/regression_r6.rs、crates/shirusu-transport/tests/matrix_validate.rs、fuzz/fuzz_targets/decode_descriptor.rs、Kani 証明の不変条件 | 実装済み未検証 |
| D69 | レビュー R4 (P1): transport-win wait_with_recheck のビジーループ修正。累積経過を ReCheckPolicy::wait_timeout に渡してスライスが 0 になっていたのを、反復ごとのスライス = min(interval, total − waited) に変更。通知なし・total 100ms で再確認回数が約 50 回に収まる回帰 (修正前は 1748 回) | crates/shirusu-transport-win/src/lib.rs、crates/shirusu-transport/src/notify.rs (wait_timeout の doc に用途の限定を明記) | 実装済み未検証 |
| D70 | レビュー R5 (P1): MSRV を 1.77 へ引き上げ (offset_of! の要件)。workspace の rust-version を 1.77 にし、従来どのクレートも継承しておらず宣言が無効だった点も含め、全メンバークレートに rust-version.workspace = true を追加した。.github/workflows/ci.yml は stable 指定で固定が無いため変更不要。1.77 ツールチェーン自体でのビルド確認は手元に該当環境が無く CI 待ち | Cargo.toml、crates/*/Cargo.toml、e2e/Cargo.toml | 実装済み未検証 |
| D71 | 実装対応 loom 追加: Slot 回収の原子操作列を 1 ステップずつ転写したモデル 2 件。旧順序では loom が「回収完了後に旧世代が見える」実行を検出し、修正順序では全実行が不変条件を満たす。複数 reclaimer の排他 (世代はちょうど 1 回だけ進む) も確認する。転写は実装の写しであり実装そのものではないため、実 SlotPool のストレス (D64) と併用する | crates/shirusu-loom-tests/src/lib.rs (loom 11→13 件) | 実装済み未検証 |
| D72 | E2E 追加: 実 Agent → 複数 Ring → 独立した検証 Host の統合テスト 2 件。8 スレッドが実 Agent::record で書き、全 Ring を検証付き Host が回収して件数・Enter/Leave 対応付け・A72 一時キーが閉じること、および 32 Producer が書く間に独立 Host が 32 Ring を同時回収すること (従来の 32 スレッドストームは自 Ring の読み書きだった)。Windows のプロセス間経路は従来の e2e クレートと CI が担い、こちらは同一プロセスで Linux でも回る範囲 | crates/shirusu-host/tests/agent_validating_e2e.rs、crates/shirusu-host/Cargo.toml (dev-dependency に shirusu-agent) | 実装済み未検証 |
| D73 | メタ指摘の文書化: TLA+ は抽象遷移の検証であり NoPermanentBlocking は状態述語として限定的、loom には最小再現モデルと実装転写モデルの二種がある、DST は PBT 内の故障操作であり独立した決定性スケジューラではない、という役割分担と各手法の限界を verification.md に明記した | docs/verification.md「役割分担の限定」 | 実装済み未検証 |
| D74 | レビュー第2回・項目8: Clock の責務分離。待機実測用の Clock (差し替え可能・インスタンス相対原点) が Descriptor の timestamp_qpc の刻印を兼ねていたのを分離し、イベント時刻専用の TimestampSource (now_qpc / frequency) を新設。RingWriter の刻印は時刻源から取り、既定実装 SystemTimestampSource は原点をプロセス全体で 1 つの OnceLock に固定する。transport-win に本物の QPC 実装 QpcTimestampSource (QueryPerformanceCounter/Frequency の FFI) を追加し、Agent は with_timestamp_source で差し替え可能に。A30 (待機時間の QPC 実測) の意味は不変。matrix_ring の ts_* ケースは旧性格付け (刻印＝待機 Clock) を時刻源差し替えへ意図的に追随 | crates/shirusu-transport/src/clock.rs・ring.rs、crates/shirusu-transport-win/src/lib.rs (QpcTimestampSource)、crates/shirusu-agent/src/lib.rs (with_timestamp_source)、crates/shirusu-transport/tests/regression_clock_split.rs (原点共有・単調性・周波数一貫性・Clock 差替え不変。旧 API のみの行動回帰は HEAD で赤を確認)、crates/shirusu-agent/tests/regression_clock_split.rs | 実装済み未検証 |
| D75 | レビュー第2回・項目6: TLA+ モデルの Slot 再利用を段階分割。Reclaim を ReclaimBegin (RECLAIMING の間に Generation 加算と終了フラグのクリア) と PublishFree (FREE 公開) に分け、Claim が観測した Generation を slotClaimGen に記録。不変条件 ClaimedGenerationIsCurrent を追加。TLC 結果 (2026-11-09、tla2tools v1.8.0): 主モデルは全 7 不変条件が成立 (990,889 状態生成 / 310,249 相異 / 深さ 28)。旧順序 (FREE 公開 → Generation 更新) の変種モデル ShirusuTransportBuggy では TLC が ClaimedGenerationIsCurrent の違反を 924 状態で検出し、モデルが競合を表現できることを実証。scripts/ci/tla.sh は両方向を主張する | tla/ShirusuTransport.tla・ShirusuTransport.cfg、tla/ShirusuTransportBuggy.tla・ShirusuTransportBuggy.cfg、scripts/ci/tla.sh、docs/verification.md「Slot 再利用の段階分割と旧順序の変種」 | 実装済み未検証 |
| D76 | レビュー第2回・項目5 (後半): RingReader::drain の多層防御。本番経路は検証付きに統一済みで RingReader はテスト専用に格下げ済みだったが、drain 自体は payload_len / payload_position を検証せずコピーしていた。コピー前に ValidatingReader と同等の最小検証 (種別・予約領域・格納長と容量・Payload 位置の範囲と連続性・Sequence 後退) を行い、失敗時はコピーせず Cursor も進めず、DrainBatch::integrity_error で破損として報告し Reader は停止する。格下げ表記は維持 | crates/shirusu-transport/src/ring.rs (check_descriptor)、crates/shirusu-transport/tests/regression_reader_hardening.rs (破損 len/position/連続性の回帰 4 件、赤→緑)、crates/shirusu-host/src/lib.rs (DrainBatch 構築の追随) | 実装済み未検証 |
| D77 | レビュー第2回・項目7 の残り: Windows 実プロセス間で、本番経路そのもの (実 Agent::record → 共有メモリ → data_ready Event での待機 → 検証付き Host の回収・Slot 再利用) を end-to-end で確認する E2E。現行の D35 は File Mapping と生 RingReader によるプロセス間確認、D72 は同一プロセス (Linux) の API 経路、A68 は space_available 受け渡しに留まるため、本番経路の組み合わせは未登録だった。Windows 実機と CI が必要なため未着手 | e2e (supervisor シナリオ追加)・CI | 未着手 |

## E. ドキュメント

| ID | 項目 | 状態 |
|---|---|---|
| E01 | docs/ に元仕様 3 ファイルを保持 | 実装済み未検証 |
| E02 | README（日本語）: 概要・構成・使い方・テストの回し方 | 実装済み未検証 |
| E03 | README: 検証状況表（ローカル未実行／CI windows で実行の区別、未検証は未検証と書く） | 実装済み未検証 |
| E04 | README: 「実装して感じたこと」を dated エントリで複数残す | 実装済み未検証 |
| E05 | 本チェックリストの状態を実装の節目ごとに更新する | 実装済み未検証 |

## 集計

- 全項目数: A 75 + B 9 + C 19 + D 77 + E 5 = **185 項目**（固定。追加したらここを更新する）
  - 2026-11-09 01:39 に A61〜A65 を追加し、分母が 135→140 に増えた。理由: 仕様再読でチェックリストの漏れ（空き待ちフェンス、セクション ACL、総メモリ上限、Finalization 不在の扱い、待機方式のベンチマーク選定）を発見したため。
  - 2026-11-09 02:52 に A66〜A68 を追加し、分母が 140→143 に増えた。理由: A61 の配線がライブラリ単位に留まっていたこと（A66）、ベンチ選定の結果を書き手が使う手段が無かったこと（A67）、Agent への space_available 受け渡しが未設計だったこと（A68）。
  - 2026-11-09 に D43〜D52 を追加し、分母が 143→153 に増えた。理由: ユーザーから「テストが全然足らない」との指摘を受け、カバレッジ・境界・PBT・loom・Kani・Miri・ミューテーション・Fuzz・E2E・Stress の各手法の増強を個別項目として追跡するため。いずれもローカルでは実施・通過済みだが、CI 未実施のため状態は「実装済み未検証」とする。
  - 2026-11-09 07:29 に A69〜A73・D53〜D58 を追加し、分母が 153→164 に増えた。理由: 仕様 3 文書の再読監査で見つけた漏れ（Loader Lock 判定不能時の 0ms 切替設定、非同期 Mapping 追加フロー、Descriptor の Sequence/Generation 検証、一時 Payload ID の文書間不整合、調整値の測定決定、DST/PBT 失敗証跡の回帰化、Application Verifier、異なる Windows 環境での確認、TLA+/PBT モデルの独立性、Fuzz 受理データの不変条件チェック、macOS での検証ロジック実行）。いずれも未着手。
  - 2026-11-09 07:29 の Miri 調査で D59 を追加し、分母が 164→165 に増えた。理由: spec_table c01/c08 の Miri 実行がテスト大増強の D48（lib + boundary）に含まれておらず、c01 は現行 VM で小規模でも異常に遅いため個別に追跡する必要があるため。
  - 2026-11-09 08:29 に A69・A71 を実装し、D59 を解決したため、未着手が 13→10 項目に減った（残りは D41、A70、A72、A73、D53〜D58）。あわせて集計行の「0/164」という D59 追加後の記載漏れを「0/165」に修正した。分母は 165 のまま変わらない。
  - 2026-11-09 09:29 に A72・D57 を実装し、未着手が 10→8 項目に減った（残りは D41、A70、A73、D53〜D56、D58）。D57 の実装中に fuzz が validate_control の Payload 位置後退の受理という本物の穴を発見し、修正して回帰テスト化した。分母は 165 のまま変わらない。
  - 2026-11-09 09:29 に D58 も実装し、未着手が 8→7 項目に減った（残りは D41、A70、A73、D53〜D56）。CI に macos-latest ジョブ `macos-validation` を追加。分母は 165 のまま変わらない。
  - 2026-11-09 にテスト拡充第2弾として D60〜D63 を追加し、分母が 165→169 に増えた。理由: kota 指示「local のテストを 1000 件規模に」を受け、行列スイート 10 ファイル・1301 件（ローカル総数 211→1512 件、通常実行 約 30 秒）を追加し、領域ごとに追跡するため。いずれもローカル通過済みだが CI 未実施のため「実装済み未検証」。
  - 2026-11-09 10:10 に A72 を kota の確定仕様で修正実装した（項目の追加ではないため分母は 165 のまま、未着手も 7 のまま）。当初決定「`payload_position` を一時 ID とする」を覆し、Host 内部キー `TemporaryPayloadKey`（process_id / ring_id / generation / sequence / payload_position）に変更。旧 `EventDescriptor::temporary_payload_id()` は撤去し、検証を Unit 5 件＋ PBT/DST（host/tests/proptest_keys.rs）に置き換えた。ローカルテスト総数は 204→211 件。
  - 2026-11-09 に外部コードレビュー (対象は remote main 6005c4c、P0 3 件 + P1 4 件 + E2E/検証手法のメタ指摘) の修正ワークストリームとして D64〜D73 を追加し、分母が 169→179 に増えた。いずれの指摘も現行コードで実在を確認し、回帰テスト先行 (赤→緑) で修正した。ローカルテスト総数は 1512→1530 件。すべてローカル通過済みだが CI 未実施のため「実装済み未検証」。
  - 2026-11-09 に A73 を実装し、未着手が 7→6 項目に減った（残りは D41、A70、D53〜D56）。新規ベンチ shirusu-tuning-bench で Ring 容量・BOUNDED_WAIT 上限・再確認周期・復帰閾値・Slot 数を掃引測定し、全既定値を維持と決定（4096 件 / 1MiB、1ms、2ms、50%、32 スロット・低水位 8）。Linux VM で 3 回測定し同じ傾向を確認。通知閾値は掃引対象外として README に記録。分母は 179 のまま変わらない。
  - 2026-11-09 11:29 に A74・A75 を追加し、分母が 179→181 に増えた。理由: 仕様再読で見つけた漏れ（A74: i686 の 64bit アトミック操作コスト測定と 32bit 折り返しカウンタへの切替判断、A75: VirtualAlloc2 二重マッピング最適化の将来検討。いずれも spec の条件・将来条項で、チェックリストに項目が無かった）。なお同 run で候補とした「64 スレッド同時書き込み」は C02 として既にあり、spec_table.rs の c02_64_threads テストが実在するため項目追加は見送った。
  - 2026-11-09 に A70 を実装し、未着手が 8→7 項目に減った（残りは D41、A74、A75、D53〜D56）。transport に ExpansionRequest / ExpansionDelivery と受け渡しトレイト、SlotPool::add_slot（追加 Slot は generation 0・FREE、上限超過時は追加しない）を追加。agent に ExpansionManager（管理スレッド: 要求フラグの消費・Host への要求・配送の登録。進行中 1 件の間は新規要求を出さない。Host 停止時は要求を破棄）、host に ExpansionService（非同期に SharedMapping を作成して配送。target_pid 付き要求には duplicate したハンドル値を配送）を追加。テストは新規 19 件（transport 4 + agent 9 + host サービス 4 + 往復 E2E 2）で、ローカル総数は 1530→1549 件。分母は 181 のまま変わらない。
  - 2026-11-09 に中間レビュー第2回 (対象は remote main 6005c4c、静的レビューのみ) の未対応デルタとして D74〜D77 を追加し、分母が 181→185 に増えた。D74 (Clock 責務分離)、D75 (TLA+ の Reclaim 段階分割と旧順序変種での違反検出)、D76 (RingReader::drain の多層防御) は回帰テスト先行で実装し、ローカルテスト総数は 1549→1559 件。D77 (Windows 実プロセス間での本番経路 E2E) は既存の D35/D72/A68 と重複しない組み合わせとして新規登録し、CI 依存のため未着手。いずれも CI 未実施のため、D74〜D76 は「実装済み未検証」。
- 検証済み: 0 項目（2026-11-09 時点。ローカル通過のみの項目は検証済みに数えない）
- 実装済み未検証: 177 項目 / 未着手: 8 項目（D41 CI フィードバックループ、A74、A75、D53〜D56、D77）
- 進捗率: 検証済み 0 / 185 = 0%。作業量ベースの自己申告は約 3%（仕様読解等の前段を含む）。
