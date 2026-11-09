# トレーサビリティ / 網羅チェックリスト

この文書が進捗の分母である。各項目の状態は次で数える。

- `未着手`: コードもテストも無い。
- `実装済み未検証`: コード（またはテスト）はあるが、ローカル＋CI（Windows 項目は GHA windows-latest）の両方で通過を確認していない。
- `検証済み`: ローカルと CI の両方で通過を確認した。

進捗率 = 検証済み項目数 ÷ 全項目数。項目を追加したら分母が増えたことをここに記録する。
現時点の自己申告: 全体で約 3%（仕様読解・接続・CI 配置・push 疎通・骨格着手まで。検証済みはまだほぼ無い）。

最終更新: 2026-11-09 18:29 の定時実行で D78 を追加し、分母は 255 になった（expansion_e2e のタイミング依存 2 件の決定的修正。ローカルテスト総数 1773 件は不変）。前回: 2026-11-09（コードレビュー第4回の対応として J01〜J11 を追加し、分母は 254 になった。CI 終了コード伝播＋カナリア、x86 ビルド、E2E 型、production_path 世代ゲート、Slot 公開順序、Blob ハッシュ検証、サイズ契約、ValueKind 正規化、フック 0 件の継続、終了時フック解除。ローカルテスト総数 1773 件、Windows 実動部は CI 待ち。前回: 転送層の残項目 A74・A75・D53〜D56・D77 を実施し、未着手は D41 のみになった。測定ハーネス・検討記録・証跡/回帰化・モデルの独立性実証・本番経路 E2E と、D54/D55 の CI 配線。詳細は集計の残項目ワークストリーム記録を参照。前回: Phase 3（フック＋レコーダ）を実装し G01〜G14 を追加。IAT フック基盤 shirusu-hook、Agent DLL、Capture Session（recorder）と Windows 起動ドライバ、引数付き変換、Windows E2E シナリオと CI 配線。ローカルテスト総数 1673 件。Windows 実動部は CI 待ち。前回: Phase 2（Trace 永続化）を実装し F01〜F16 を追加。公開 Trace 形式 v1 の確定（docs/trace-format.md）、shirusu-trace の新設、Host 変換（A72）、fuzz 2 件、Windows 両ターゲット check 通過。ローカルテスト総数 1637 件。詳細は集計の F 追加記録を参照。さらに前回: A73 を実装: 調整値の掃引測定（shirusu-tuning-bench）で全既定値を維持と決定。4096 件 / 1MiB、1ms、2ms、50%、32 スロット・低水位 8。Linux VM で 3 回測定し同じ傾向を確認。A72 の修正実装は 10:10 の記録を参照）

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
| A74 | i686 での 64bit アトミック操作のコスト測定と、問題があれば 32bit の折り返しカウンタへの切替判断（spec Cursor 節:「i686での64bitアトミック操作（cmpxchg8b等で実現される）のコストが問題になれば、32bitの折り返しカウンタに切り替える」） | e2e/src/bin/shirusu-atomic-bench.rs（fetch_add/load/store/CAS の単スレッドレイテンシ、SPSC Cursor パターン、4 スレッド競合を U64/U32 同条件で測定。切替判断の基準: fetch_add が 32bit の 2 倍超、または SPSC が 32bit の 70% 未満なら検討開始）。CI 配線: windows.ps1 で x64 対照値、windows-x86.ps1 で i686 (WoW64) 実測を実行。ローカル参考値 (Linux x86_64、10M ops × 3 rounds): 全項目の比率 0.90〜1.00 で同等。この VM は 32bit ローダ/開発ファイルが無く i686 の実行・リンク自体が不能なため、i686 実測は CI 待ち | 実装済み未検証 |
| A75 | Payload 終端またぎ分割コピーの最適化検討（VirtualAlloc2＋MapViewOfFile3 による同一領域の二重マッピング。spec:「Windows 7 対応と両立しないので、初版は分割コピーとし、後から最適化として検討する」） | docs/double-mapping-review.md に検討記録を作成し、結論は **条件付き保留**（現行の分割コピーを正とする）。理由: Win7 対応という前提を変える製品判断が無く、利得はコピー呼び出し回数の削減のみで記録経路のボトルネックでもなく、フォールバックを含むと複雑さは増える。再検討の条件は (1) Win7/8/8.1 をサポートから外す決定 (2) 実測で有意な割合 (目安 5% 超) の実証 (3) 単一経路化または二重経路の維持コスト受容、の全てが揃うこと | 実装済み未検証 |

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
| D53 | DST/PBT 失敗時の証跡保存と縮小ケースの回帰テスト化（verification.md: 失敗時に Seed・リビジョン・テスト構成・操作列・注入故障を保存し、縮小したものを回帰テストに加える） | 実装済み: 証跡形式と決定的再実行器を tests/common/evidence.rs に置き、DST (dst_fault_mix_invariants) を TestRunner 化して失敗時に証跡 JSON (リビジョン・構成・操作列・注入故障) を保存する。マクロ版 PBT の Seed/縮小は proptest regressions が担い (実績: recorder の 1 件が保存・再実行中)、縮小済み回帰ケース 2 件を tests/failure_evidence.rs に固定。loom の失敗スケジュールは R3 旧順序モデルを should_panic で回帰化 (loom 13→14 件)。Fuzz の最小入力は seeds への書き戻し運用 (fuzz/README) で、D57 の実例は単体テストで固定済み。手順の全体は verification.md「失敗時の証跡と回帰化」に明文化 | 実装済み未検証 |
| D54 | Application Verifier の併用（verification.md E2E 節・CI 表リリース前） | 配線済み: windows.ps1 の capture-e2e 実行で対象プロセス shirusu-hook-target.exe に Application Verifier (Heaps/Handles/Locks) を有効化し、finally で設定解除とログ削除を行う。appverif.exe が無い環境では注記して従来どおり実行する。実走確認は CI 待ち | 実装済み未検証 |
| D55 | 異なる Windows 環境での確認（verification.md CI 表リリース前「異なる Windows 環境での確認」。D39/D40 は windows-latest のみ） | 配線済み: matrix.json に windows-x64-win2022 ジョブ (os: windows-2022、windows-x64 と同じ windows.ps1) を追加し、windows-latest (2025 世代) と異なる環境で x64 のテスト+E2E を回す。plan.sh の射影に含まれることを確認 (ci 9→10 ジョブ)。実走確認は CI 待ち | 実装済み未検証 |
| D56 | TLA+ モデルと PBT 参照モデルの実装の独立性（verification.md: 両者は同じ不変条件を共有するが実装は独立させ、実装のバグを参照モデルに写し込まない） | 担保済み: 監査で、参照モデル群 (VecDeque / Slot 影 / A72 キー照合) が期待値計算に実装の validate を使わず公開 API の観測可能な出力だけを見ることを確認。唯一の弱い依存 (通知閾値テストの layout::usage_percent 流用) を切り離し仕様の定義式へ変更。独立性の実証として scripts/ci/model-independence.sh を新設 (nightly 配線): 実装への mutation 2 件 (占有量の被減数入替、回収時の Generation 静止) がいずれも対象 PBT の失敗として検出されることを、無変更での成功と併せて確認する。2026-11-09 ローカルで実証済み。根拠は verification.md「モデルの独立性の担保と確認」 | 実装済み未検証 |
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
| D77 | レビュー第2回・項目7 の残り: Windows 実プロセス間で、本番経路そのもの (実 Agent::record → 共有メモリ → data_ready Event での待機 → 検証付き Host の回収・Slot 再利用) を end-to-end で確認する E2E | 実装済み: capture-e2e との突き合わせでは、capture-e2e は Hook + Recorder + Trace の経路で本項目の組み合わせを含まず、cross_arch は生 RingWriter + 生 RingReader + ポーリングだった。新規シナリオ production_path_interprocess を追加: producer は実 Agent を DLL と同じ手順で構築して record ごとに data_ready を通知し、supervisor は wait_with_recheck (2ms 再確認) で待ちながら検証付き DrainWorker (A72 identity 付き) で回収する。DETACH と回収完了の確認後にだけ Slot 再利用を許可し (reclaim-ok はテスト用同期ポイント)、次 Generation での再記録までを通す。両フェーズで内容の連番一致・payload_keys 数・integrity_lost 無しを検証。CI: windows-x64 の --all (x64 同士) と windows-x86.ps1 の --production-path (x64 Host × i686 Producer) で実行。Windows 実走は CI 待ち | e2e (supervisor シナリオ追加)・CI | 実装済み未検証 |
| D78 | expansion_e2e のタイミング依存 2 件の決定的修正（レビュー第4回ワークストリームが「観測記録に留める」とした負荷時 1 回の失敗を、定時実行で再現・原因特定・修正）。(1) host_stop_during_expansion: 管理スレッドを claim の前に起動すると、claim 2 で立った要求フラグを claim 3 の前に消費され、claim 3 がフラグを再び立てる（slot.rs の再ラッチは仕様どおり）。破棄後に 2 件目の要求が送られ requested が 2 になる。起動を claim の後にして要求をちょうど 1 件に決めた（再現: claim 間に 10ms を挟むと requested=2/discarded=2 で赤になることを確認）。(2) agent_to_host_round_trip: 待機が容量 (Slot 数) を見ていたが、J06 の PREPARING 導入後は add（容量に数える）と publish（FREE）の間に窓があり、その間に待機が抜けると thread_begin が None を返す。取得可能性 (free_count > 0) を待つように変更。修正後は expansion_e2e を 30 回連続で全通過。残る 100ms の待ちはポーリング 5ms の 20 回分の余裕で、従来のタイミングテストと同程度の仮定 | crates/shirusu-host/tests/expansion_e2e.rs | 実装済み未検証 |

## E. ドキュメント

| ID | 項目 | 状態 |
|---|---|---|
| E01 | docs/ に元仕様 3 ファイルを保持 | 実装済み未検証 |
| E02 | README（日本語）: 概要・構成・使い方・テストの回し方 | 実装済み未検証 |
| E03 | README: 検証状況表（ローカル未実行／CI windows で実行の区別、未検証は未検証と書く） | 実装済み未検証 |
| E04 | README: 「実装して感じたこと」を dated エントリで複数残す | 実装済み未検証 |
| E05 | 本チェックリストの状態を実装の節目ごとに更新する | 実装済み未検証 |

## F. Phase 2: Trace 永続化（公開形式 v1、docs/trace-format.md）

| ID | 項目 | 実装 | 状態 |
|---|---|---|---|
| F01 | 公開 Trace 形式仕様 v1 の確定（Container / Schema の二重バージョン、前方参照禁止、Index / Finalization 省略可、回復意味論と上限の決定） | docs/trace-format.md | 実装済み未検証 |
| F02 | Block Container: 32B 固定ヘッダー、CRC32C（CRC 欄 0 化したヘッダー＋payload）、stored_len 512MiB / raw_len 256MiB 上限、未知 block_type の読み飛ばし、未知 compression の破損扱い、File Header の二重 Magic | trace/container.rs | 実装済み未検証 |
| F03 | Protobuf メタデータの手書きワイヤ形式（prost / protoc 非依存、未知フィールド読み飛ばし、proto3 既定値省略、CaptureEnvironment / SchemaSet / BatchHeader / LossRecord / BlockIndex / Finalization の全メッセージ往復） | trace/proto.rs | 実装済み未検証 |
| F04 | Compact Binary 値列: 全 13 型タグ、LEB128 / zigzag、取得状態 5 種、NaN ペイロード保持、未知タグ Schema での復号拒否、個数・型不一致と末尾余剰の検出 | trace/compact.rs, schema.rs | 実装済み未検証 |
| F05 | Compact Binary イベント列: Batch Header 長先行、seq / ts 差分符号化、payload_tag 4 種（None / Blob / Inline / Dropped＋理由）、args_tag、event_count 不一致・末尾余剰・未知タグの破損検出 | trace/compact.rs | 実装済み未検証 |
| F06 | チャンク単位 Zstd: 純 Rust ruzstd、符号化は Fastest / Uncompressed のみ、展開後長と raw_len の照合と読み取り打ち切り、圧縮で膨らむ場合は無圧縮格納、辞書なし | trace/container.rs | 実装済み未検証 |
| F07 | Blob ストア: BLAKE3 ID、`<root>/<先頭2hex>/<全体hex>` 配置、重複排除、再オープン時の走査による既出集合の再構築、get_verified のハッシュ照合 | trace/blob.rs | 実装済み未検証 |
| F08 | Schema レジストリと正規化ハッシュ: content_hash 検証、schema_id 0 の拒否、異なる内容の再定義拒否、同一内容の再登録冪等（Checkpoint 複製）、別 Trace 間同一性は ID 非依存のハッシュで判定 | trace/schema.rs | 実装済み未検証 |
| F09 | Trace Writer: Header / Environment の先行書出し、Blob の前方参照禁止（参照 Event Chunk 直前へのフラッシュ）、セッション内重複排除、Event / Blob Chunk の 256KiB 目安分割、Index と Finalization の書出し、finish しない場合は未完 Trace として読める、sequence 後退・未追加 Blob 参照・セッション不一致の拒否 | trace/writer.rs | 実装済み未検証 |
| F10 | 依存判断の実測記録: blake3 は `pure` フィーチャ必須（既定では Windows ターゲットで ml64.exe を要求し check 不能。当初の「cc 経路は既定で無効」という記録は誤りとして訂正）、zstd-sys 不採用（lib.exe 要求）、ruzstd 採用と符号化レベルの制約、prost 不採用（protoc 依存）、CRC32C は transport の検証済み実装を再利用 | docs/trace-format.md「依存クレートの判断」、trace/Cargo.toml | 実装済み未検証 |
| F11 | Trace Reader 回復意味論（recover_trace）: 先頭 Header 不成立は全体拒否、末尾切断は TruncatedTail、CRC 不一致は payload 長を信用せず再同期（SBLK 探索＋完全検証でのみ受理）、Zstd / Protobuf / Compact の失敗は Block 単位で隔離、重複 Blob の報告、欠落 Blob の明示（イベントは保持）、Index 不一致時は走査結果を正とする、Finalization 無しは完全性不確定、Block 100 万 / イベント 1 億 / Blob 1000 万の上限 | trace/reader.rs | 実装済み未検証 |
| F12 | Host 変換と A72: 公開 Trace は Blob ID のみ（TemporaryPayloadKey は変換の入出力に現れず、payload_position の LE 表現が Trace バイト列に無いことをテストで確認）、欠落 Payload は Dropped { 元長, 理由 } のみ、Loss 全種の写像、IntegrityReport 3 指標の Finalization 写像、実 Agent → 検証付き Host → Recorder の通し経路 | host/trace_convert.rs | 実装済み未検証 |
| F13 | fuzz ターゲット decode_compact: SchemaSet + 値列、復号成功時の再符号化冪等性を主張。2026-11-09 ローカル 75 秒 5,843,310 runs、クラッシュ 0 | fuzz/fuzz_targets/decode_compact.rs | 実装済み未検証 |
| F14 | fuzz ターゲット recover_trace: 任意バイト列の回復読み、受理時の不変条件（Batch 内 sequence 単調性、上限、Payload 解決の安全性）を主張。2026-11-09 ローカル 75 秒 1,120,017 runs、クラッシュ 0 | fuzz/fuzz_targets/recover_trace.rs | 実装済み未検証 |
| F15 | 言語非依存テストベクター: 最小 Trace を Writer / Protobuf 実装を経由せずバイト列で手組みし、期待復号結果と突き合わせる（Header のみ / 最小 Trace / CRC 破損の 3 件） | trace/tests/test_vectors.rs | 実装済み未検証 |
| F16 | Windows ターゲット check: shirusu-trace と shirusu-host が x86_64-pc-windows-msvc / i686-pc-windows-msvc の両方で check 通過（この VM から stable cargo で実測） | trace, host | 実装済み未検証 |

## G. Phase 3: フック＋レコーダ（「使える」最低線）

| ID | 項目 | 実装 | 状態 |
|---|---|---|---|
| G01 | フック方式の決定: IAT フックを採用（overview の実装順序 1）。根拠: 初期 API セットは通常インポート経由で足り、命令デコードや巻き戻しが不要で安全、計画がプラットフォーム非依存で単体テスト可能。限界（GetProcAddress 経由・DLL 内直接呼び出しは捕捉できない）は Capture Coverage の欠落として扱う（G05） | crates/shirusu-hook（api/plan）、本節 | 実装済み未検証 |
| G02 | 対象 API 表と決定的スキーマ ID: CreateFileW(1) / ReadFile(2) / WriteFile(3) / CloseHandle(4)、Schema ID は enter=2n−1・leave=2n（1–8）、Schema へ観測レベルの注釈を付け SchemaSet として Trace Writer へ登録。DLL 名照合は大文字小文字と拡張子を吸収、関数名は完全一致 | hook/api.rs | 実装済み未検証 |
| G03 | 引数キャプチャ意味論: パスは UTF-16（上限 1024 ユニット、超過は Truncated、NULL は Unreadable、ユニット単位のサルベージ）、バッファ上限 4096 バイト。WriteFile は Enter で入力バッファ、ReadFile は Leave で実データと実バイト数、OVERLAPPED は Unsupported、失敗時はデータを付けない。全 Leave の末尾に last_error（U32） | hook/capture.rs | 実装済み未検証 |
| G04 | PE パーサ: 境界検査付きでインポート（IAT RVA 付き）/ エクスポート / SizeOfImage / PE32+ 判定、ファイル→イメージ写像（セクション変換）。合成 PE での単体テスト | hook/pe.rs | 実装済み未検証 |
| G05 | フック計画 build_plan: 名前照合で対象を選び IAT RVA で重複排除、表にあってモジュールに無い API は missing として返す（Coverage の明示） | hook/plan.rs | 実装済み未検証 |
| G06 | フックエンジンと Detour（Windows）: VirtualQuery による可読性判定で安全に読む ProcessMemory、IAT 書き換え（VirtualProtect）と復元、原関数ポインタの保持、GetLastError の透過性（原関数復帰直後に取得し、呼び出し側へ戻る前に復元）。A69 の WriterPolicy は Agent 既定（ローダーロック下ゼロウェイト）のまま記録経路に適用 | hook/engine.rs | 実装済み未検証（Windows 実動は CI 待ち） |
| G07 | Bootstrap 受け渡し構造: repr(C) 568 バイト、バージョン検証、Ring 本数上限 32。ハンドル値は対象プロセス内で有効な値として Host が複製して渡す（同一ビットネス前提を明記） | hook/bootstrap.rs | 実装済み未検証 |
| G08 | Agent への外部 Mapping 登録口 register_slot_mapping（ExpansionDelivery の公開ラッパ）と、登録した Mapping へ記録して Host 側で読み戻す往復テスト | agent, agent/tests/bootstrap_mapping.rs | 実装済み未検証 |
| G09 | Agent DLL: cdylib。DllMain は DisableThreadLibraryCalls のみ（Loader Lock 遵守、実初期化は Host 駆動の shirusu_agent_init エクスポート）、ステータスコード、Host プロセス生存監視による自己停止、QPC タイムスタンプ。制約: スロットは 1 回限り（プロセス間 再確保チャネルは Phase 3 の範囲外。枯渇は Agent 内カウントのみで Host から不可視） | crates/shirusu-agent-dll | 実装済み未検証（Windows 実動は CI 待ち） |
| G10 | Host の引数付き変換 record_batch_with_args: 登録済みフック Schema の Payload だけを Compact Binary から復号して Args 化し、未登録・復号失敗時は Blob のまま保全する（統計 args_attached / args_fallback_blob）。セッション総括ではフォールバック有無を Semantic Completeness へ反映 | host/trace_convert.rs | 実装済み未検証 |
| G11 | Capture Session 中核: 状態機械（Created→Recording→Stopped、違法操作は InvalidTransition）、Ring の遅延 Worker 化（Magic 確認まで保留し、初期化されない Ring はエラーにしない）、破損検出時の Ring 停止と Event Integrity Lost、対象途中終了でも回収済み分は Trace に残る、終了不明呼び出しの Loss 化。Unit（全通し/破損/終了不明/未初期化）＋ 状態機械 PBT | host/recorder.rs, host/tests/recorder.rs | 実装済み未検証 |
| G12 | Windows 起動ドライバ: CREATE_SUSPENDED 起動とアタッチ、Mapping・イベントの作成と対象への複製、Bootstrap 書き込み＋ shirusu_agent_init のリモート呼び出し（x86 の stdcall 名デコレーション対応）、init_done 確認、終了まで回収ループ、起動失敗時の対象後始末 | host/recorder_launch.rs, transport-win プロセスヘルパ | 実装済み未検証（Windows 実動は CI 待ち） |
| G13 | Windows E2E シナリオ: 対象プロセス（4 API を直接 FFI で呼ぶ）が書き読みする内容・パス・ハンドル相関を、生成 Trace の復号で検証。windows-x64 ジョブで実行（scripts/ci/windows.ps1）、i686 は hook テストと agent-dll ビルド（windows-x86.ps1）、check 対象へ hook / agent-dll を追加（matrix.json）。workflow ファイルは不変更 | e2e（shirusu-hook-target / shirusu-capture-e2e）, scripts/ci | 実装済み未検証（CI 待ち） |
| G14 | 観測レベルの到達点: CreateFileW / ReadFile / WriteFile = L2（型付き引数＋バッファ内容）、CloseHandle = L1（ハンドル値の相関まで。Object ID 未導入のため L3 は部分的）、GetLastError は全 Leave で捕捉。L3 の完全到達（Object ID 導入）と L4 は後続 Phase の範囲 | hook/api.rs の注釈、本節 | 実装済み未検証 |

## H. Phase 4: 解析 CLI＋差分エンジン＋shirusu-test 基礎

| ID | 項目 | 実装 | 状態 |
|---|---|---|---|
| H01 | 解析系の構成決定: 共有ビュー `shirusu-analysis`、検査 CLI `shirusu-cli`（バイナリ `shirusu`）、差分 `shirusu-compare`、期待ルール `shirusu-test` の 4 クレートに分離（overview のコンポーネント表: 記録と解析は本体、比較とテスト生成は別コンポーネント）。解析側は OS 非依存で、Windows ターゲット（x86_64 / i686）でも check 通過 | crates/shirusu-{analysis,cli,compare,test} | 実装済み未検証 |
| H02 | ビュー層: ReadTrace の平坦化、Schema レジストリによる引数復号、値の決定的表記（浮動小数点はビット列、U64 は 16 進）。取得できなかった値はダミー本体ではなく取得状態で表示し、復号失敗は args_error として隠さず残す | analysis/view.rs | 実装済み未検証 |
| H03 | `shirusu inspect`: セッションメタデータ（CaptureEnvironment）、三つの完全性指標＋裏付け内訳（Loss Record 種別、落ちた Payload、劣化イベント、欠落 Blob、回復 issue、Index 照合）、Finalization 欠落時は「確定できない」と明示。API 別 Enter/Leave 集計。人間可読＋JSON | cli/main.rs | 実装済み未検証 |
| H04 | `shirusu dump` / `export`: フィルタは CLI オプションの組（--api / --kind / --seq / --thread / --text / --limit。独自クエリ言語は作らない＝ overview の方針）。dump は人間可読＋JSON、export は JSONL。出力はゴールデンテストで固定 | cli/main.rs、cli/tests | 実装済み未検証 |
| H05 | compare 正規化ルール（normalize.rs のモジュール文書が正）: (1) タイムスタンプ絶対値は不比較 (2) PID/プロセス/スレッドは出現順の序数化 (3) ハンドルは生成相関で ObjectKey 化 (4) 非相関ポインタは中身を消去（0 と全ビット1 は区別を残す） (5) 未取得値は取得状態で比較 (6) Payload は内容で比較し Inline/Blob の表現差を吸収 (7) 戻り値・last_error・意味値は正規化しない | compare/normalize.rs | 実装済み未検証 |
| H06 | オブジェクト同一性: 生成は「CallLeave の return（U64・取得成功・0/INVALID 以外）」と定義し、同一性は (生成 API 名, 生成序数)。生値の再利用（Close 後の再生成）は参照位置より前の最新生成へ解決。生成帰属はイベント位置で正確に引く（既存ハンドルを返す API を生成と誤認しない）。（2026-11-09 の J09 で精緻化: Schema に ValueKind がある場合は生成判定を意味種別で決め、本項の定義は種別の無い旧 Schema へのフォールバックとして残る） | compare/normalize.rs | 実装済み未検証 |
| H07 | 状態遷移の比較: オブジェクトごとに対応づけ、「そのオブジェクトへの操作列」を整列して欠落/追加を検出。両側に同じ多重集合が残る場合は欠落+追加ではなく順序相違の候補 1 件にまとめる | compare/diff.rs | 実装済み未検証 |
| H08 | オブジェクト非関与の呼び出しはスレッド（出現順対応）ごとに整列比較。Enter/Leave の揃い方の相違は CallShapeDifference、取得状態の相違は CaptureDifference として別種別で出す | compare/diff.rs | 実装済み未検証 |
| H09 | 完全性メタデータの別枠比較: 三指標・Loss Record 内訳・落ちた Payload 数・欠落 Blob 数が片側だけ違う場合を IntegrityDifference とする（「比較以前に観測できていない」可能性の提示） | compare/diff.rs | 実装済み未検証 |
| H10 | 「候補」の線引き: 出力種別は MissingCall / ExtraCall / ArgumentDifference / ReturnDifference / PayloadDifference / ObjectStateDifference / IntegrityDifference / CaptureDifference / CallShapeDifference。重要度は候補の分類であって違反判定ではない。CANDIDATE_NOTICE（断定ではない旨）を人間向け・JSON の両出力に常時付帯し、CLI 終了コード（0=候補なし / 1=候補あり / 2=エラー）も「違反確定」を意味しないことを文書化 | compare/diff.rs、compare/report.rs、bin | 実装済み未検証 |
| H11 | compare の検証: シナリオ 10 件（完全一致→0、引数 1 つの変更→その候補のみ、全体の再番号付け→0、欠落→ MissingCall、戻り値失敗→ ReturnDifference（High）、操作順序違い→状態候補 1 件、完全性差分ほか）、再番号付け不変性と反射性の PBT（各 128 ケース）、CLI 統合（終了コード・JSON） | compare/tests | 実装済み未検証 |
| H12 | shirusu-test 基礎: 期待ルールは言語非依存 JSON を正規形式（version 1）。ルールは api-called（フィールド equals/contains 条件つき）、no-integrity-loss、object-closed、event-count。JSON パーサは自前（整数のみ、位置つきエラー）。object-closed は compare の相関を再利用し、生成ゼロを空虚な真にせず失敗とする。評価は記録の範囲内の判定である旨を文書化（Phase 5 の Probe 生成の土台） | test/{spec,eval,json_parse}.rs、bin | 実装済み未検証 |
| H13 | 整列の劣化経路: LCS の DP は積 4,000,000 セルを上限とし、超過時は貪欲整列へ切り替える（巨大 Trace でのメモリ爆発回避。結果が変わりうる劣化であることをここに明記する） | compare/diff.rs | 実装済み未検証 |

## I. Phase 5: ippai 連携（shirusu 側基盤。契約の正は docs/ippai-integration.md）

前提の明記: ippai / sake のリポジトリはこのワークスペースに無く、本節の成果物は「shirusu 側で用意できる半分」と「ippai 側実装者が従う契約」である。sake との統合が実在するかのような記述はしない。最終統合は kota が ippai 側で行う。

| ID | 項目 | 実装 | 状態 |
|---|---|---|---|
| I01 | エミッタキット shirusu-emit: TraceWriter の上に薄く乗り、セッション管理（CaptureEnvironment の構築）と Finalization の必須化を担う。3 指標の値は記録側が決め、キットは値を発明しない。finish はオープン中の呼び出しが残っていれば失敗する | crates/shirusu-emit | 実装済み未検証 |
| I02 | キットが肩代わりする規約: sequence はスレッドごとに 1 から単調増加で自動採番、call_id の自動採番と CallToken による Enter/Leave 対応（非同期完了のため end は非 LIFO を許容）、begin 時点のオープン中呼び出しからの parent_call_id 引継ぎ、終了しない呼び出しは Leave を捏造せず abandon_call で明示破棄（痕跡は Loss Record が正） | emit/emitter.rs | 実装済み未検証 |
| I03 | 引数の Schema 照合: begin/end の値列は登録済み Schema の型列と個数・型を encode_values で照合してから符号化し、不一致（個数・型・未知 API・未知トークン・二重 end）はエラーとして返す | emit/emitter.rs | 実装済み未検証 |
| I04 | 共有 API セット ApiSet: 登録順に api_id 1..=N、Schema は enter=2n−1 / leave=2n（本体フック表と同一規約）。基準形 file_io_api_set（CreateFileW / ReadFile / WriteFile / CloseHandle）は本体 API_TABLE と名前・フィールド列が一致し、Schema の content_hash 一致をテストで常時照合する（本体側の表が drift したら落ちる） | emit/api_set.rs | 実装済み未検証 |
| I05 | エミッタの検証: 実セッション（開く→書く→読む→閉じる）の往復で Schema 登録・sequence 列・Blob 解決・Finalization 整合・ビュー層での API 名/値復元を確認。ネストとスレッド混在、エラー経路（未知 API、型/個数不一致、対応なし end、オープン中 finish）も単体で固定 | emit/tests/roundtrip.rs | 実装済み未検証 |
| I06 | 適合性チェッカ shirusu-conformance: 9 項目（clean-scan / environment / finalization / finalization-counts / schemas-registered / sequence-monotonic / enter-leave-pairing / blob-refs-resolvable / integrity-consistent）。合否は Fail の有無で決め、sequence 重複は Warn に留める。各項目には「壊れると誰が困るか」をモジュール文書に明記。Capture Coverage の真偽は Trace 内から検証不能である旨も明記 | crates/shirusu-conformance | 実装済み未検証 |
| I07 | 適合性チェッカの検証: エミッタ製 Trace は全項目パス。規約違反を注入した Trace（未登録 Schema、sequence 後退、対応しない Leave、未終了 Enter、欠落 Blob、Finalization 欠落/総数不一致、Complete 申告と損失記録の矛盾、匿名 environment）が該当項目でのみ落ちる。実バイト列（TraceWriter 製・切断 Trace）と CLI 終了コード（0/1/2）も固定 | conformance/{check.rs の単体, tests/bytes.rs, tests/cli.rs} | 実装済み未検証 |
| I08 | ルール生成（差分→Probe の中核）: 種別ごとの戦略（MissingCall→api-called、Argument/ReturnDifference→左側の実値での equals、IntegrityDifference→no-integrity-loss、ObjectState/CallShape→object-closed、汎用フォールバックに api-called / event-count）を両 Trace で実際に評価し、「左 pass・右 fail」が成立した最小の 1 ルールを採用。推測でルールを作らない。JSON パーサの整数正規化（正数→U64）のため不変条件は構造一致ではなく読み戻し後の識別成立とする | probe/rules.rs、probe/bundle.rs | 実装済み未検証 |
| I09 | ルール化の限界の正直な記録: v1 ルール形式で表現できない候補（Payload 内容差分、Capture 差分）はブリーフのみのバンドルとし、manifest に試した戦略と棄却理由を残す。ブリーフ自体にも「識別ルール化できなかった」旨を明記 | probe/{rules,brief,bundle}.rs、シナリオテスト | 実装済み未検証 |
| I10 | Probe ブリーフ: 候補の種別/内容/関与オブジェクト/フィールド差分、関与呼び出し列（正規化済み引数つき。生ハンドル値は載せない）、両側の完全性サマリ、ルール化の結果と試した戦略、トリム結果、CANDIDATE_NOTICE、ippai 側での使い方を含む | probe/brief.rs | 実装済み未検証 |
| I11 | トリミング: 関与オブジェクト/根拠イベントの呼び出しだけを、元の Batch 文脈・sequence・引数・Payload・Blob ID のまま再構成する（抜き出しであって再解釈ではない）。オブジェクト序数を保つため先行する同種の生成呼び出しも残す。Schema は使用分だけ元の登録順で、Loss Record は全て残し、完全性 3 指標は元の申告を引き継いで notes にトリムである旨を残す。生成後に compare を再実行して同じ候補が再現するか確認し、結果を manifest に記録 | probe/trim.rs | 実装済み未検証 |
| I12 | 回帰バンドル形式 v1 と生成 CLI: ディレクトリ構成（manifest.json / brief.md / rules.json / left.trimmed.trace / right.trimmed.trace）を docs/ippai-integration.md に定義。CLI shirusu-probe の終了コードは 0=識別ルールあり / 1=候補なし / 2=使い方・入力エラー / 3=ブリーフのみ。書き出した rules.json は v1 パーサで読み戻せることを生成時に保証 | probe/{bundle.rs, bin}、docs/ippai-integration.md | 実装済み未検証 |
| I13 | 通しシナリオ（本 Phase の最終ゲート）: エミッタで作った 2 Trace（ハンドル再番号付け＋片側だけ ReadFile 失敗）→ 両側とも適合 → compare が ReturnDifference（High）を検出 → バンドル生成 → バンドル内ルールが左 pass / 右 fail を再現、トリム済みペアでも候補が再現し適合性も維持。副シナリオ: 再番号付けのみのペアは候補ゼロ、CloseHandle 欠落は MissingCall バンドル化、Payload のみの差分はブリーフのみ | probe/tests/scenario.rs | 実装済み未検証 |
| I14 | 契約ドキュメント docs/ippai-integration.md: 境界（ippai/sake のコードは本 repo に無いこと、統合は ippai 側の作業であること）を冒頭に明記し、エミッタ契約 C1〜C10（チェッカの検査 ID と対応）、共有 API セットの同一性（content_hash）と追加規則（末尾追加のみ）、バンドル形式、Probe 生成の仕組みと限界、ippai 側に残る作業 4 件を定義 | docs/ippai-integration.md | 実装済み未検証 |
| I15 | 解析系への追加と CI 配線: 新規 3 クレート（emit / conformance / probe）はいずれも OS 非依存で、windows-check-targets（x86_64 / i686）に matrix.json の最小変更で追加。既存クレートの公開 API は不変更 | Cargo.toml、scripts/ci/matrix.json | 実装済み未検証 |

## J. コードレビュー第4回（2026-11-09、対象は remote main f9600b0）の指摘対応

レビュー全文と照合メモは goals 側の hidden_files/2026-11-09-review4-findings.md。いずれの指摘も現行コードで実在を確認し、回帰テスト先行（赤→緑）で修正した。すべてローカル通過済みだが CI 未実施のため「実装済み未検証」。MSRV の決定（#2）は kota 判断のため本セクションに含めない。

| ID | 項目 | 実装 | 状態 |
|---|---|---|---|
| J01 | #3 (P0) Windows CI スクリプトの終了コード伝播: 全ネイティブコマンドを Invoke-Native ヘルパー経由にし、失敗がジョブを落とす。あわせて意図的に失敗するコマンドを踏むカナリア (canary-exit-code.ps1) を両スクリプトの先頭で実行し、伝播の仕組み自体を毎回検証する | scripts/ci/native-step.ps1, canary-exit-code.ps1, windows.ps1, windows-x86.ps1 | 実装済み未検証 |
| J02 | #3(a) golden テストの改行不安定性: .gitattributes で golden に eol=lf を固定し、比較側も改行正規化してから照合する（内容差は検出する単体テスト付き） | .gitattributes, shirusu-cli/tests/cli.rs | 実装済み未検証 |
| J03 | #1 (P0) x86 ビルド: `(len >> 32) as u32` の overflow を u64 経由の split_mapping_size に修正。i686 / x86_64 両ターゲットの build（check でなく）で確認 | transport-win/lib.rs | 実装済み未検証 |
| J04 | #4 capture-e2e の期待値型: lpNumberOfBytesRead は Schema 上 DWORD (U32)。期待値を TypedValue::U32(24) に修正 | e2e/shirusu-capture-e2e.rs | 実装済み未検証 |
| J05 | production_path 第 2 フェーズ 0/700 の切り分け: 残留 data_ready 通知で Host が世代初期化前に DrainWorker を作ると GenerationMismatch で Ring が恒久停止する機構を Host 単体テスト 3 件で再現・固定。Supervisor は期待世代への遷移を確認してから Worker を作り、タイムアウト時に停止理由（完全性喪失・停止状態・共有世代・最後の Loss）を診断出力する。Windows 実走での第 2 フェーズ通過は CI 待ち | host/lib.rs (wait_for_ring_generation), e2e/shirusu-e2e-supervisor.rs | 実装済み未検証 |
| J06 | #10 動的 Slot の公開順序: 追加 Slot は取得不能な PREPARING 状態で作り、Mapping 登録後に publish_slot で FREE を公開する。claim は PREPARING を掴めないこと、公開順序の loom モデル（新順序 + 旧順序 should_panic）を追加（loom 14 → 16） | transport/slot.rs, agent, shirusu-loom-tests | 実装済み未検証 |
| J07 | #5 Blob ハッシュ検証: Trace Reader が取り込み時に BlobId::of_content(body) == id を検証し、不一致は BlobHashMismatch として隔離する。適合性検査に blob-ids-match-content を追加（9 → 10 件）。CRC を再計算して整合させた改竄 Blob の回帰テスト付き | shirusu-trace/reader.rs, shirusu-conformance/check.rs | 実装済み未検証 |
| J08 | #6 Writer/Reader サイズ契約: Writer も raw（展開後）256MiB 上限を守り、超える単一 Payload は明示的エラーで拒否する。上限ちょうどの往復テスト含む | shirusu-trace/container.rs, writer.rs | 実装済み未検証 |
| J09 | #7 正規化の意味種別: FieldDef.flags の bit2..=4 に ValueKind (Scalar / Pointer / Handle / CreatedObject) を定義し、compare の生成判定と U64 正規化を種別駆動にした。hook API 表と emit 共有 API セットへ同時に導入し content_hash ピンを維持。スカラー戻り値 100→200 の検出等、回帰テスト 4 件。種別の無い旧 Schema は従来規約へフォールバック（限界を明記） | shirusu-trace/schema.rs, hook/api.rs, emit/api_set.rs, compare/normalize.rs | 実装済み未検証 |
| J10 | #8 フック対象 0 件の継続: NoTargets は計画を保持して返し、初期化失敗と分離。Agent DLL は 0 件設置で成功として継続し、Bootstrap v2 の書き戻し欄で設置/欠落件数を Host へ返す。Host は Capture Coverage の劣化として記録する（対象プロセスは終了させない） | hook/engine.rs, hook/bootstrap.rs, agent-dll, host/recorder.rs, recorder_launch.rs | 実装済み未検証 |
| J11 | #9 終了時のフック解除経路: HookRuntime に記録ゲート (DetourFlight) を追加し、DLL の shutdown が「記録無効化 → 進行中 Detour の完了待ち → IAT 復元」の順序を実行する。Host の finish() は対象が生きている場合のみ最終回収前に shutdown をリモートスレッドで呼ぶ（ベストエフォート、旧 DLL では省略）。ゲートは Linux 単体テストで検証、recorder_launch の順序は CI 待ち | hook/runtime.rs, hook/engine.rs, agent-dll, host/recorder_launch.rs | 実装済み未検証 |

## 集計

- 全項目数: A 75 + B 9 + C 19 + D 78 + E 5 + F 16 + G 14 + H 13 + I 15 + J 11 = **255 項目**（固定。追加したらここを更新する）
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
  - 2026-11-09 に Phase 2（Trace 永続化）の F01〜F16 を追加し、分母が 185→201 に増えた。理由: スコープ拡大（Phase 2）で公開 Trace 形式 v1 の確定・実装・回復意味論・Host 変換（A72）・fuzz 2 件・Windows ターゲット check を項目として追跡するため。いずれもローカル通過済みだが CI 未実施のため「実装済み未検証」。ローカルテスト総数は 1559→1637 件。なお F10 のとおり、blake3 の依存判断で前任の実測記録（既定で Windows check 通過）が誤っていたため pure フィーチャで是正した。
  - 2026-11-09 に Phase 3（フック＋レコーダ）の G01〜G14 を追加し、分母が 201→215 に増えた。理由: スコープ拡大（Phase 3）で「実際に記録できる」最低線（IAT フック、Agent DLL、Capture Session、Windows E2E）を項目として追跡するため。プラットフォーム非依存部（API 表・キャプチャ・PE・計画・セッション中核）はローカル通過済み、Windows 実動部（エンジン実フック・DLL 注入・起動ドライバ・E2E）は CI 未実施のため、いずれも「実装済み未検証」。ローカルテスト総数は 1637→1673 件。
  - 2026-11-09 に Phase 4（解析 CLI＋差分エンジン＋shirusu-test 基礎）の H01〜H13 を追加し、分母が 215→228 に増えた。理由: スコープ拡大（Phase 4）とレビュー第3回で採用した設計指針（shirusu-compare は正規化つき差分エンジンとし、出すのは契約違反の「候補」まで）を項目として追跡するため。新規 4 クレート（analysis / cli / compare / test）は全てローカル通過済み（テスト総数 1673→1713 件、Windows ターゲット check は x86_64 / i686 とも通過）だが CI 未実施のため「実装済み未検証」。
  - 2026-11-09 に Phase 5（ippai 連携の shirusu 側基盤）の I01〜I15 を追加し、分母が 228→243 に増えた。理由: レビュー第3回で新設した Phase 5（sake 側 Trace エミッタ、差分の最小 Probe 化、ippai 回帰テストへの取り込み支援）のうち、shirusu 側で用意できる基盤（エミッタキット、適合性チェッカ、バンドル生成）と契約ドキュメントを項目として追跡するため。ippai / sake のコードは本 repo に無く、統合は ippai 側の残作業として契約文書に切り分けた。新規 3 クレート（emit / conformance / probe）はローカル通過済み（テスト総数は最終ゲートで確定し README に記録、Windows ターゲット check は x86_64 / i686 とも通過）だが CI 未実施のため「実装済み未検証」。
  - 2026-11-09 に転送層の残項目ワークストリームとして A74・A75・D53〜D56・D77 を実施し、未着手が 8→1 項目（残りは D41 のみ）になった。分母は 243 のまま変わらない。A74: 測定ハーネス shirusu-atomic-bench と CI 配線（i686 実測は CI 待ち、x86_64 参考値は全項目比率 0.90〜1.00）。A75: 検討記録を作成し条件付き保留と結論。D53: 証跡形式＋決定的再実行器＋DST の TestRunner 化と失敗時保存、縮小回帰ケース 2 件、loom 旧順序の should_panic 回帰化（loom 14 件）。D54: windows.ps1 に AppVerifier 併用を配線。D55: windows-2022 ジョブを追加。D56: 参照モデルの監査と usage_percent 依存の切り離し、mutation 実証スクリプト（nightly 配線、ローカルで両 mutation 検出を確認）。D77: production_path_interprocess シナリオを追加（x64 同士は --all、x64×i686 は windows-x86.ps1）。いずれも CI 未実施のため「実装済み未検証」。ローカルテスト総数は最終ゲートで確定し README に記録。
  - 2026-11-09 にコードレビュー第4回（対象は remote main f9600b0、P0 2 件 + P1 8 件 + E2E 仮説 1 件）の対応として J01〜J11 を追加し、分母が 243→254 に増えた。#7/#8/#9 は着手前に実在をコードで確認し、いずれも実在した。回帰テスト先行で修正し、ローカルテスト総数は 1749→1773 件。PowerShell スクリプトの実挙動・production_path の Windows 実走・recorder_launch の終了順序は CI 未実施のため、いずれも「実装済み未検証」。MSRV（レビュー #2）は kota の決定待ちで本ワークストリームでは扱っていない。
  - 2026-11-09 18:29 の定時実行で D78 を追加し、分母が 254→255 に増えた。理由: レビュー第4回ワークストリームが「観測記録に留める」とした expansion_e2e の負荷時 1 回の失敗を、定時ループが再現・原因特定して決定的に修正したため。(1) host_stop テストは管理スレッドの起動順序（claim 2 のフラグ消費と claim 3 の再ラッチのインタリーブ）が原因で、100ms の待ち時間の仮定ではなかった。(2) 往復テストは J06 の PREPARING 導入後、容量と取得可能性が分離したため待機条件が誤っていた。いずれもテスト側の修正で、仕組みの変更はない。修正後の expansion_e2e は 30 回連続で全通過し、全テスト 1773 件も維持。CI 未実施のため「実装済み未検証」。
- 検証済み: 0 項目（2026-11-09 時点。ローカル通過のみの項目は検証済みに数えない）
- 実装済み未検証: 254 項目 / 未着手: 1 項目（D41 CI フィードバックループ）
- 進捗率: 検証済み 0 / 255 = 0%。作業量ベースの自己申告は約 3%（仕様読解等の前段を含む）。
