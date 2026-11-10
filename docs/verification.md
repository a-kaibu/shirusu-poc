# 検証戦略

shirusuは、同じ不変条件を性質の異なる複数の方法で確かめる。転送では次の三つを別々に検証する。誤ったイベントを正常なものとして記録することも、クラッシュと同じく失敗として扱う。

- Safety：公開前のデータを読まず、未回収の領域を上書きせず、再利用した領域に古い書き手のデータが混ざらない。
- Liveness：Hostや書き手が止まっても、他の処理が無期限に止まらない。
- Completeness：記録が失われたら、その事実を検出してTraceに反映する。

## 手法と役割

| 手法 | 検証するもの | shirusuでの対象 |
| --- | --- | --- |
| Unit | 個別の関数と状態遷移 | Cursor計算、容量判定、Descriptor、CRC32C |
| PBT（proptest） | 操作列の組み合わせ | Ring操作、Fragment、Overflow、Slotの再利用。`VecDeque`の参照モデルと比較し、失敗した操作列を縮小する |
| loom | スレッド間の実行順序 | Release/Acquireによる公開と回収。通常のメモリも`loom::cell::UnsafeCell`で追跡する |
| Kani | 任意入力に対する逐次コードの性質 | Cursor演算、Hostの範囲検証。並行性は対象外 |
| Fuzz（cargo-fuzz） | 壊れた入力 | Hostの共有メモリ解析、Trace Reader、Compact Binary、復旧 |
| TLA+（PlusCal、TLC） | アルゴリズムの安全性と進行性 | 公開・回収・再利用の状態遷移 |
| DST | 故障と時間経過の組み合わせ | Host停止、通知の欠落、遅延、容量不足、スレッド終了 |
| Windows E2E | 実際のOSとプロセス間の動作 | x86 Agentとx64 Host、File Mapping、通知、強制終了。Application Verifierも併用する |

ShuttleとVerusは、対象が複雑になった段階で追加する。Miriは`unsafe`コードの未定義動作の検出に使うが、Windows FFIやプロセス間共有メモリは再現できない。どの手法も単独ではRing全体の正しさを証明しない。

### DSTはまずPBTの中で実現する

転送の制御ロジック（待機、Overflow、欠落、生成と回収）は、Windows APIから分けた状態機械として書く。そうすれば、PBTの操作列に「仮想時計の進行」「Hostの停止と再開」「通知の欠落」「スレッド終了」を混ぜるだけで、Seedから再現できる故障シナリオになる。専用のシミュレータは、複数のRingとHostの書き込みまで含める必要が出たときに作る。

実際のWindowsスレッドを乱数で動かすだけでは、スケジューラが実行順序を決めるのでDSTにはならない。失敗時には、Seed、コードのリビジョン、テスト構成、実際に選ばれた操作列と注入した故障を保存し、縮小したものを回帰テストに加える。

### 失敗時の証跡と回帰化（D53）

失敗の種類ごとに、保存先と回帰化の形を決めている。

| 失敗の種類 | 保存されるもの | 回帰化の形 |
| --- | --- | --- |
| PBT（proptest! マクロ版） | Seed と縮小ケースが `*.proptest-regressions` に自動保存される | そのままチェックインし、毎回の実行で先に再実行される。実績: host の recorder PBT で 1 件 (`ops = [AddRing]` への縮小) が保存・再実行されている |
| DST（TestRunner 版 `dst_fault_mix_invariants`） | 証跡 JSON（テスト名・リビジョン・Seed 参照・テスト構成・操作列・注入故障の一覧）を `SHIRUSU_FAILURE_EVIDENCE_DIR`（無ければ `target/shirusu-failure-evidence/`）へ保存する | 証跡の操作列は `tests/common/evidence.rs` の決定的再実行器 `replay_dst` でそのまま再生できる。縮小したケースは `tests/failure_evidence.rs` に固定する（実施済み: Host 停止を含む縮小ケースと溢れケースの 2 件） |
| Fuzz | クラッシュ入力は最小化のうえ `fuzz/seeds/<target>/*.hex` へ書き戻す（`fuzz/encode-seeds.sh`、形式は fuzz/README.md） | 種として CI の短時間 Fuzz で毎回通す。コードの穴だった場合は単体テストも併せて固定する。実績: D57 の Payload 位置後退の受理は `validate_control_rejects_payload_position_regression` と matrix の `vc_prev_payload_*` で固定済み |
| loom | スケジュールそのものは保存できないため、性質を破る側の実装形（旧順序モデル）を残す | 旧順序モデルが性質テストで落ちることを `#[should_panic]` で固定する。実績: `loom_slot_reclaim_old_order_is_detected`（R3 の旧順序。TLA+ 側の変種モデル D75 と対になる） |

リビジョンは `SHIRUSU_EVIDENCE_REVISION` → `GITHUB_SHA` → `git rev-parse HEAD` → `unknown` の順に解決する。証跡の保存に失敗しても、元のテスト失敗はそのまま報告される（保存は失敗の報告を隠さない）。

### 役割分担の限定（レビューでのメタ指摘を受けて、正直な範囲）

各手法が「何を保証しないか」も明記する。

- TLA+ は抽象的な状態遷移の検証であり、実装の原子操作の順序やメモリ順序は検査しない。`NoPermanentBlocking` は状態述語としては「容量不足なら待機ではなく欠落として前に進む遷移が存在する」ことしか表しておらず、実装の待機が有限時間で終わることの証明ではない。実装側の有限性は BOUNDED_WAIT の上限（既定 1ms）と、それを測るテストが担う。ただし Slot 再利用の公開順序については、実装の操作列に対応する段階分割をモデルに入れ、旧順序の変種で違反が検出できることまで確認した（後述「Slot 再利用の段階分割と旧順序の変種」）。メモリ順序そのものは依然として検査しない。
- loom のモデルには二種類ある。MiniRing 系はプロトコルの最小再現であり、実 `Slot`/`RingWriter` の操作順序そのものではない。実装の順序が問題になる箇所（Slot 回収の公開順序など）は、実装の原子操作列を転写したモデルで別に検査する（R3 で追加）。ただし転写モデルも実装そのものではなく、写し間違いの可能性は残るため、実物の並行ストレスと併用する。
- DST は本実装では PBT の操作列に故障を混ぜる方式であり、独立した決定性スケジューラではない。再現性は Seed と操作列の保存に依存し、実スレッドのタイミング依存の競合は loom とストレスが担う。

## TLA+で検証する性質

最初のモデルは、Ring容量2、書き手1〜2、読み手1の小さな構成とする。バイト列ではなく、各セルの持ち主・状態・Generation・公開済みかどうかを扱う。スレッドの終了と`DLL_THREAD_DETACH`後の呼び出しもモデルに含める。

| 不変条件 | 命題 |
| --- | --- |
| `NoUnpublishedRead` | Hostは未確定のイベントを受け取らない |
| `NoOverwriteBeforeRelease` | 書き手は未回収の領域を書き換えない |
| `ExclusiveCellOwnership` | 同じ領域に書ける書き手は同時に一人 |
| `NoStaleProducerWrite` | 再利用した後に古い書き手が書き換えない |
| `ClaimedGenerationIsCurrent` | 取得者が Claim の瞬間に観測した Generation は、その Slot の現在の Generation と一致し続ける |
| `SequenceConsistency` | 公開済みイベントの順序と欠落情報が矛盾しない |
| `NoPermanentBlocking` | Host停止や容量不足で待機が無期限に続かない |

### Slot 再利用の段階分割と旧順序の変種（レビュー第2回・項目6）

Slot の再利用は、実装の原子操作列に合わせて段階に分けてある。`ReclaimBegin` が RECLAIMING の間に Generation を進めて終了フラグを落とし、`PublishFree` が最後に FREE を公開する。Claim は FREE が公開されているときにだけ可能で、観測した Generation を `slotClaimGen` に記録する。これにより、中間状態（FREE 公開済み・Generation 未更新）がモデルに存在せず、`ClaimedGenerationIsCurrent` が「取得済み Slot の Generation が後から変わらない」ことを直接表す。

さらに、旧順序（FREE 公開 → Generation 更新）を表す変種モデル `ShirusuTransportBuggy.tla` を置き、TLC が違反を検出できることを確認した。モデルがこの競合を表現できることの証跡である。実行は `scripts/ci/tla.sh`（主モデルの成立と変種の違反検出の両方を主張する）。

2026-11-09 のローカル実行結果（tla2tools v1.8.0、MaxCursor=4、Generation<=2 の制約下）:

- 主モデル: エラーなし。990,889 状態生成 / 310,249 相異状態 / 深さ 28 / 13s。全 7 不変条件が成立。
- 変種モデル: `Invariant ClaimedGenerationIsCurrent is violated` を 924 状態生成時点で検出（期待どおりの違反）。

進行性には公平性の前提が要る。有限のバッファでは「Hostが永久に止まっても全部保存する」は成り立たないので、「容量不足なら欠落として前に進む」ことを検証する。TLA+の状態機械とPBTの参照モデルは同じ不変条件を共有するが、実装は独立させ、実装のバグを参照モデルに写し込まないようにする。

### モデルの独立性の担保と確認（D56）

独立性は宣言だけでは担保にならないため、監査と実証の両方で確認する。

監査（2026-11-09、コード再読）:

- VecDeque 参照モデル（`proptest_ring.rs`）と Slot 影モデル（`proptest_properties.rs`）、A72 のキー照合モデル（`proptest_keys.rs`）は、期待値の計算に実装の検証モジュール（`validate`）を一切使っていない。使うのは公開された書込/回収 API と、その観測可能な出力（受信イベント・カウンタ・Slot 状態）だけである。
- 影モデルは状態遷移を仕様文書の状態機械から書き起こしており、実装の内部定数や分岐を参照していない。Overflow の PBT は完全一致を要求せず不変条件だけを見る形にし、参照モデル側へ実装の劣化規則を写し込まないようにしている。
- 唯一残っていた弱い依存（通知閾値テストが割合計算に `layout::usage_percent` を流用）は切り離し、仕様の定義式をテスト側で直接計算する形に変えた。`usage_percent` 自体の正しさは算術行列（D60）が定義式との照合で別途担う。
- TLA+ モデルは PlusCal の手書きであり、実装コードからの生成ではない。実装の原子操作列を問題にする箇所だけ、段階分割として意図的に寄せている（D75）が、それは「同じ不変条件を共有する」範囲であり、遷移の書き方はモデル側の表現である。

実証（mutation、`scripts/ci/model-independence.sh`、nightly で実行）:

- 実装の占有量計算（`layout::occupancy`）の被減数を入れ替えると、`ring_matches_vecdeque_model` が失敗する。参照モデルが占有量を自前で数えていなければ検出できない。
- 実装の回収処理（`slot.rs` の `host_reclaim`）で Generation を進めなくすると、`slot_lifecycle_interleavings_match_shadow_model` が失敗する。影モデルの世代管理が独立である証跡になる。
- 2026-11-09 のローカル実行では、無変更で両モデルが成功し、2 件の mutation がいずれも対象 PBT の失敗として検出された。スクリプトは mutation の対象文字列が見つからない場合も陳腐化として失敗する。

## Fuzzの対象

| Fuzz Target | 入力 | 検証 |
| --- | --- | --- |
| `validate_control` | Cursor、容量、Generation | オーバーフローや誤った占有量の判定がない |
| `decode_descriptor` | 64バイトのDescriptor | 不明なKindや異常な長さを安全に扱う |
| `decode_payload` | DescriptorとPayload | 参照範囲と折り返しを正しく検証する |
| `decode_compact` | Schemaと引数のバイト列 | 不正な型定義やバイト列でReaderが崩れない |
| `recover_trace` | 途中で切れたBlock列 | 回収できないデータを捏造しない |

クラッシュしないことに加え、受理したデータが公開Traceの不変条件を満たすかも確かめる。検証ロジックは純粋関数に分け、LinuxやmacOSでも実行する。

## Windows E2E

Test SupervisorがAPIを大量に呼ぶ専用プログラムを起動し、HostとAgentを意図した位置で止めたり終了させたりする。`Sleep`で競合を起こすのではなく、イベント公開の前後、Payloadコピー中、Slot再利用前などにテスト用の同期ポイントを設ける。同期ポイントは本番ビルドでは無効にする。

## CIでの実行

| タイミング | 実行する検証 |
| --- | --- |
| PR | Unit、PBT（故障操作を含む）、短いloom、Kaniの主要Harness、短いFuzz、Windows x86・x64 E2E |
| Nightly | 多数SeedのPBT・DST、Host・Agentの障害注入 |
| 週次 | 拡大したloom、TLA+の状態探索、長時間Fuzz、長時間の負荷テスト |
| リリース前 | 全検証、Application Verifier、破損復旧、異なるWindows環境での確認 |

PBTとDSTで見つけたSeed、Fuzzの最小入力、loomの失敗スケジュールは回帰テストに加える。テストが本当に不具合を検出できるかは、ReleaseをRelaxedにする、Generationの確認を外す、容量計算を壊すといった変更を加えて確かめる（Mutation Test）。

## 実装の順序

1. TLA+でSPSC Ring、Slotの再利用、スレッド終了をモデル化する。
2. SPSCの最小実装を作り、容量2程度の小さなRingでUnit・PBT・loomを通す。
3. Hostの検証ロジックを分け、KaniとFuzzを通す。
4. 故障操作を混ぜたPBT（DST）でOverflowと生成・回収を検証する。
5. Windows E2Eでx86 Agentとx64 Host、強制終了、通知の欠落、Ringの再利用を確かめる。
