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

Miriは`unsafe`コードの未定義動作の検出に使うが、Windows FFIやプロセス間共有メモリは再現できない。どの手法も単独ではRing全体の正しさを証明しない。

### Shuttle / Verus の追加検討（D79・2026-11-11）

当初の「ShuttleとVerusは、対象が複雑になった段階で追加する」に対する評価。対象は当初の想定を超えて複雑化した（ワークスペース 16 メンバー・15 クレート、Phase 1〜4 実装済み）が、**両方とも当面は追加しない**と判断した。

**Shuttle（並行性の乱択スケジューリング検査、現行 0.9.10）— 不採用（当面）**
- Shuttle は loom に着想を得た乱択検査で、loom の網羅検査より大きなケースに届く代わりに sound ではない（通っても正しさを証明しない）。shirusu の並行性の核（Ring の公開・回収・再利用）は loom 18 シナリオ（転写モデル含む）＋ TLA+ 7 不変条件 ＋ PBT 参照モデル ＋ 実プロセス間ストレス（D51・A77）で多層化済みで、Shuttle は同じく「モデル」であるため、本節の「役割分担の限定」で自認するギャップ（TLA+ はメモリ順序を検査しない、loom モデルは実装そのものではない）を埋めない。そのギャップは実ストレスと Windows E2E が担っている。
- Shuttle が loom より強いのは std スレッドの高位協調（Mutex/Condvar/チャネル、async）の決定性探索だが、shirusu のスレッド協調は OS 境界に接している（DrainWorker は共有メモリ・ファイル I/O・Windows イベントと直結、hook runtime は FFI/TLS）。Shuttle は OS 呼び出し・FFI・プロセス間共有メモリを仮想化できず、適用には境界のスタブ化が要り、モデル忠実度は loom の MiniRing と同じ限界に直面する。
- 導入にはテストコードを `shuttle::thread` / `shuttle::sync` 向けに書き換える必要があり、loom モデルと重複する第二のモデルを維持することになる。特別なツールチェーンは要らない点は有利だが、上記の理由で利得が無い。

**Verus（SMT による Rust プログラム検証）— 不採用（当面）**
- Verus は仕様・証明を Rust ソース内に書く SMT ベースの検証器で、ghost permission により unsafe コードの推論も可能だが、shirusu の検証したい核（共有メモリ・FFI・プロセス間）に Windows の意味論が絡む部分は Verus の対象外で、Rust コード側の性質だけが対象になる。
- その Rust コード側の性質は既に Kani（unsafe を含む逐次コードの有界検証・14 ハーネス）＋ TLA+（プロトコル不変条件）＋ PBT/fuzz が担っている。Verus の無界の証明が Kani の有界性を上回るのは、ループ不変条件など無界の性質が求められる場合に限られるが、現行コードでその要求は具体化していない。
- 導入コストは 16 クレート全体への仕様注釈と独自ツールチェーン（verus＋Z3）の CI 導入で、MSRV 1.87・安定ツールチェーン方針とも噛み合わない。Microsoft の Brotli での実践が示す「選んだ不変条件だけを証明し、fuzz とテストを併用する」漸進形が正しい形であり、現時点では選ぶべき対象が無い。

**再検討の条件**
1. loom / TLA+ / ストレスで捉えられない実スレッド協調の不具合が実運用・CI で逃げた場合 → Shuttle を再検討する（対象は OS 境界を切り離せる Host 側協調ロジックに限定）。
2. safe Rust 中心の逐次コンポーネントで、Kani の有界検証では不十分な無界の性質（ループ不変条件等）が具体化した場合 → Verus を再検討する（対象は当該コンポーネントに限定し、漸進形で）。
3. いずれかのツールが安定ツールチェーンで使えるようになった場合 → 導入コストを再評価する。

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

### 検証用アプリ 4 種（L17）

overview 初期マイルストーン節の「まず自作の小さなプログラムを使う」に従い、4 種の検証用アプリを用意する。いずれも `VERIFY <app> <step> <value>` 行と `VERIFY_DONE <app> ok` を出し、`--verify-out <path>` 指定時は同じ内容をファイルにも書く。

| アプリ | 使う API | ステップ |
| --- | --- | --- |
| `shirusu-verify-console` | ファイル・レジストリ・スレッド | file / registry / thread |
| `shirusu-verify-gui` | USER32・GDI・DIB | file / window / gdi / dib |
| `shirusu-verify-com` | COM（ShellLink・IPersistFile） | file / com-init / shelllink / persist |
| `shirusu-verify-winrt` | WinRT（JsonObject・Uri） | file / winrt-init / activate-json / activate-factory / create-uri / absolute-uri |

`shirusu-capture-e2e --verify-apps` が各アプリを Hook なし（baseline）と Hook ありで実行し、VERIFY 出力が同じことと、Trace にファイル I/O（4 API × enter/leave ＝ 8 イベント以上）が記録されることを検証する。ステップの値は実行ごとに変わらない定数にし、pid を含む一時パスは出力に出さない。Hook ありとなしの比較が pid 差で壊れないようにするためである。

レジストリは L03 の生成表で記録されるようになり、`--verify-apps` は console アプリのレジストリ 12 イベント以上（6 呼び出し × enter/leave）も検査する。USER32・GDI・DIB の API は未記録のまま。COM は L02 で記録されるようになり、`--verify-apps` は com アプリの Factory 設置数（≥1）と COM メソッドイベント（CoCreateInstance / IShellLinkW::SetPath / GetPath / QueryInterface 各 ≥1、Release ≥2 件、COM enter ≥6 件、enter/leave 件数一致）を検査する。WinRT は L14 で記録されるようになり、`--verify-apps` は winrt アプリのアクティベーション設置数（≥1）と WinRT アクティベーションイベント（RoActivateInstance ≥1、RoGetActivationFactory ≥2、クラス名 2 種、enter ≥3 件、enter/leave 件数一致）および COM メソッドイベント（IInspectable::GetRuntimeClassName ≥2、IActivationFactory::ActivateInstance / QueryInterface 各 ≥1、IUriRuntimeClassFactory::CreateUri ≥1、IUriRuntimeClass::AbsoluteUri ≥1、Release ≥2 件、COM enter ≥10 件、enter/leave 件数一致）を検査する。`--verify-apps` はその未記録分をカバレッジ評価として報告する（失敗にはしない）。「実アプリでどこまで記録できるかを評価する」ための土台であり、フック表が増えたら評価は自動的に変わる。

### Win32 Metadata Generator（L03）

overview 初期マイルストーンの段階 4。Win32 Metadata から幅広い API の L1 定義表と汎用 Detour を生成し、対象 API を増やせるようにする。

- 入力：`Microsoft.Windows.SDK.Win32Metadata` の NuGet 固定版（`71.0.45-preview`）の `Windows.Win32.winmd`。取得は `scripts/ci/fetch-winmd.sh`（nupkg と winmd の sha256 を固定）。版は `crates/shirusu-metadata-gen/apis.toml` の `winmd_version` と同じにすること。
- 生成器：`crates/shirusu-metadata-gen`（バイナリ `win32-metadata-gen`）。設定は `apis.toml`（対象 API と `last_error` の上書き、意図的な除外）。生成物は `crates/shirusu-hook/src/api_generated.inc`（`ApiDef` の `&[...]` 式）と `engine_generated.inc`（生成 Detour と `detour_for_generated`）で、チェックインする。最新性は `scripts/ci/linux.sh` が `--check` で検査する。
- 生成範囲：L1（型付き引数・戻り値・GetLastError）のみ。文字列・バッファ・構造体の中身は取得しない（ポインタ値のみ）。L2 以上は手書きの記録仕様で API ごとに拡張する。
- 型対応：プリミティブは `Ty` へ写し（8/16bit 整数は 32bit へ拡大）、enum は基底整数型、デリゲートはポインタ値、単一フィールド構造体はそのフィールドの型（`HANDLE` 等の `*mut c_void` 1 個はハンドル、`PWSTR` はポインタ、`BOOL` は I32）。複数フィールドの値渡し構造体・COM 型・浮動小数点・可変長引数は対象外としてスキップ理由とともに報告する。
- 1 スロット制約：汎用 Detour は引数 1 個を usize 1 個で中継するため、x86 で 2 スロットを占める固定 64bit 型（I64/U64）は生成対象外（例：`SetFilePointerEx` の `LARGE_INTEGER`（I64 化）、`GetTickCount64` の U64 戻り）。ポインタ幅の型（ISize/USize/ポインタ/ハンドル）は両ターゲットで 1 スロットのため対象内。
- `LastErrorMeaning` の既定：BOOL 返しは `WhenReturnIsFalse`、HANDLE/ポインタ返しは `WhenReturnIsNull`、WIN32_ERROR/HRESULT/NTSTATUS 返し・void・その他の整数は `Never`（戻り値自体がエラーか、失敗条件が型だけでは不明なため）。既知の失敗条件は設定で上書きする（例：`WaitForSingleObject` は `minus-one`）。
- 意図的な除外（設定の `[[skip]]` に理由付きで記録）：`GetLastError` / `SetLastError`（Detour 自身が LastError を読む・戻すため自己参照になる）、`GlobalFree` / `LocalFree`（成功時に NULL を返す反転した意味のため L1 の意味条件では扱えない）。
- ID の安定性：生成 API の api_id は設定の記載順に `first_api_id`（7）から連番で割り当て、新規は末尾への追加のみ。手書き表が増えたら `first_api_id` を上げる。生成 API を手書き表へ昇格させる場合は生成表から外し、ID は再利用しない（欠番のまま残す）。

設計上の注意：GUI アプリは対話を一切せず、ウィンドウはメッセージ専用ウィンドウ（HWND_MESSAGE）で、GDI はメモリ DC 上でのみ描く。表示 DC を使わないため、ヘッドレスな CI ランナーでも動く。

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
