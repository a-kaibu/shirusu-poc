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
| Kani | 任意入力に対する逐次コードの性質 | Cursor演算、Hostの範囲検証、通知判定、CRC32C、LEB128/varint、Blob部分更新、Inlineパッチのジャンプ符号化、PEヘッダーの境界検査。並行性は対象外 |
| Fuzz（cargo-fuzz） | 壊れた入力 | Hostの共有メモリ解析、Trace Reader、Compact Binary、復旧、Traceメタデータ、PEイメージ解析、Inline Hookの命令再配置 |
| TLA+（PlusCal、TLC） | アルゴリズムの安全性と進行性 | 公開・回収・再利用の状態遷移 |
| DST | 故障と時間経過の組み合わせ | Host停止、通知の欠落、遅延、容量不足、スレッド終了 |
| Windows E2E | 実際のOSとプロセス間の動作 | x86 Agentとx64 Host、File Mapping、通知、強制終了。Application Verifierも併用する |

Miriは`unsafe`コードの未定義動作の検出に使うが、Windows FFIやプロセス間共有メモリは再現できない。どの手法も単独ではRing全体の正しさを証明しない。

### Shuttle / Verus の追加検討（D79・2026-11-11）

当初の「ShuttleとVerusは、対象が複雑になった段階で追加する」に対する評価。対象は当初の想定を超えて複雑化した（ワークスペース 16 メンバー・15 クレート、Phase 1〜4 実装済み）が、**両方とも当面は追加しない**と判断した。

**Shuttle（並行性の乱択スケジューリング検査、現行 0.9.10）— 不採用（当面）**
- Shuttle は loom に着想を得た乱択検査で、loom の網羅検査より大きなケースに届く代わりに sound ではない（通っても正しさを証明しない）。shirusu の並行性の核（Ring の公開・回収・再利用）は loom 18 シナリオ（転写モデル含む。2026-11-13 に 20）＋ TLA+ 7 不変条件 ＋ PBT 参照モデル ＋ 実プロセス間ストレス（D51・A77）で多層化済みで、Shuttle は同じく「モデル」であるため、本節の「役割分担の限定」で自認するギャップ（TLA+ はメモリ順序を検査しない、loom モデルは実装そのものではない）を埋めない。そのギャップは実ストレスと Windows E2E が担っている。
- Shuttle が loom より強いのは std スレッドの高位協調（Mutex/Condvar/チャネル、async）の決定性探索だが、shirusu のスレッド協調は OS 境界に接している（DrainWorker は共有メモリ・ファイル I/O・Windows イベントと直結、hook runtime は FFI/TLS）。Shuttle は OS 呼び出し・FFI・プロセス間共有メモリを仮想化できず、適用には境界のスタブ化が要り、モデル忠実度は loom の MiniRing と同じ限界に直面する。
- 導入にはテストコードを `shuttle::thread` / `shuttle::sync` 向けに書き換える必要があり、loom モデルと重複する第二のモデルを維持することになる。特別なツールチェーンは要らない点は有利だが、上記の理由で利得が無い。

**Verus（SMT による Rust プログラム検証）— 不採用（当面）**
- Verus は仕様・証明を Rust ソース内に書く SMT ベースの検証器で、ghost permission により unsafe コードの推論も可能だが、shirusu の検証したい核（共有メモリ・FFI・プロセス間）に Windows の意味論が絡む部分は Verus の対象外で、Rust コード側の性質だけが対象になる。
- その Rust コード側の性質は既に Kani（unsafe を含む逐次コードの有界検証・14 ハーネス。2026-11-13 に 3 クレート 33 本）＋ TLA+（プロトコル不変条件）＋ PBT/fuzz が担っている。Verus の無界の証明が Kani の有界性を上回るのは、ループ不変条件など無界の性質が求められる場合に限られるが、現行コードでその要求は具体化していない。
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
| `proto_messages` | 任意のバイト列 | Traceメタデータ全16型が panic せず、受理した値は再符号化→再復号で同じ値に戻る |
| `pe_image` | ファイル配置／メモリ配置のPE | panic せず、IATスロットとエクスポートRVAがイメージ内に収まる |
| `inline_plan` | 関数先頭のバイト列と配置先 | 盗む命令が命令境界で隙間なく並び、パッチが独立デコーダで見てDetourへ届く |

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

レジストリは L03 の生成表で記録されるようになり、`--verify-apps` は console アプリのレジストリ 12 イベント以上（6 呼び出し × enter/leave）も検査する。USER32・GDI・DIB の API は未記録のまま。COM は L02 で記録されるようになり、`--verify-apps` は com アプリの Factory 設置数（≥1）と COM メソッドイベント（CoCreateInstance / IShellLinkW::SetPath / GetPath / QueryInterface 各 ≥1、Release ≥2 件、COM enter ≥6 件、enter/leave 件数一致）を検査する。WinRT は L14 で記録されるようになり、`--verify-apps` は winrt アプリのアクティベーション設置数（≥1）と WinRT アクティベーションイベント（RoActivateInstance ≥1、RoGetActivationFactory ≥2、クラス名 2 種、enter ≥3 件、enter/leave 件数一致）および COM メソッドイベント（IInspectable::GetRuntimeClassName ≥2、IActivationFactory::ActivateInstance / QueryInterface 各 ≥1、IUriRuntimeClassFactory::CreateUri ≥1、IUriRuntimeClass::AbsoluteUri ≥1、Release ≥2 件、COM enter ≥10 件、enter/leave 件数一致）を検査する。詳細調査モードは L15 で追加され、`--verify-apps` は console アプリを詳細調査モードでもう一度記録し、内部フック設置数（≥1）と NtCreateFile / NtClose の記録（各 ≥1、enter/leave 件数一致、親が CreateFileW / CloseHandle であること）および詳細調査モードでも VERIFY 出力が変わらないことを検査する。コールバックは L16 で追加され、`--verify-apps` は gui アプリでコールバック検出フック設置数（≥1）、WM_CREATE・WM_DESTROY のコールバック enter、enter ≥2 件、enter/leave 件数一致、コールバックイベントがトップレベル（parent_call_id == 0）であることを検査する。`--verify-apps` はその未記録分をカバレッジ評価として報告する（失敗にはしない）。「実アプリでどこまで記録できるかを評価する」ための土台であり、フック表が増えたら評価は自動的に変わる。

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

## 2026-11-12 レビュー修正の検証

単体テストだけで完了とせず、次の独立した性質を検証する。

| 手法 | 対象・実行方法 | 検出する問題 |
| --- | --- | --- |
| シリアライズを含むE2E | `cargo test -p shirusu-probe --test review_regressions` | Writer→Reader→比較→Probeトリム→Reader→再比較。プロセス別HANDLE、UTF-16、別スレッドの完了イベント |
| 決定的スケジュール | `cargo test -p shirusu-hook --test lifecycle_schedules`、`late_detour_after_unregister_retains_original` | 完了先行・OVERLAPPED再利用・古い操作の取消・detach後の遅延進入。sleepのタイミングには依存しない |
| WindowsのDetour経路 | `completion_can_arrive_inside_original_read_file` | 元APIの実行中に完了する順序でも、登録済みの操作を取得できる |
| WindowsのネイティブE2E | `scripts/ci/exception-transparency.ps1` | C++のSEH捕捉がHookなし／ありで一致し、HeapAllocのCallAbortedも残る |
| Windowsの寿命・割当検査 | `deleting_fiber_does_not_end_thread_capture`、Hook単体テストの`heap_watch` | Fiber削除をThread終了と誤認しない。停止区間のRust allocatorの確保・解放・再確保を検出する |
| TLA+ / TLC | `OverlappedLifecycle.tla`、`scripts/ci/tla.sh` | OSへの発行前登録と、世代付き取消の不変条件。旧登録順のモデルでは反例を必須とする |
| Mutation | `python3 scripts/ci/review-mutations.py` | UTF-16、プロセス分離、保存順、トリム、Blob数、hex解析、操作再利用、未取得値、閉鎖失敗、再実行の初期状態・明示位置、64bit ABI、浮動小数点ビット列の13変異を隔離コピーで実行。コンパイル失敗は検出成功に数えない |
| Coverage-guided fuzz / ASan | `cargo +nightly fuzz run blob_hex` / `trace_budgets` | 不正UTF-8境界、任意バイト列、構造を保つBlob更新列に対するpanicと予算超過 |

短時間・長時間のfuzzスクリプトは、既存の`decode_compact`と
`recover_trace`も含めて実行する。新規seedは`fuzz/seeds`から再生成する。
Mutationはnightlyスイート、SEHのE2EはWindows x64スイートに含める。
fuzzは導入失敗・検出失敗を成功扱いせず、行列のallow_failureも無効にする。

TLCモデルは登録／完了／取消の小さな状態機械であり、Windows全体やRust実装
全体の証明ではない。`heap_watch`もOS内部のヒープ操作を計測するものではない。
Windowsの実行検証とLinux上のモデル・回帰テストを分けて結果を記録する。

実装上の契約:

- Inline Hookでは列挙・ハンドル取得・トランポリン生成・結果領域の確保を
  停止前に済ませ、全スレッド再開後に解放する。
- detach後も無効化済みruntimeを素通し用に保持する。再登録時には未設定の
  元関数スロットを引き継ぎ、登録の空白によってAPI呼び出しを失敗させない。
- OSへ非同期I/Oを発行する前にpendingを登録し、取消はcall IDが一致する
  操作だけに適用する。
- 比較のHANDLEと完了呼び出しの識別にはsession/processを含める。
  イベントの比較順はglobal orderが揃っていればそれを使い、それ以外はQPCを
  周波数換算する。同時刻・時計不明の順序には依然として曖昧さがあり、
  比較結果は契約違反の断定ではない。トリムは元のファイル位置を使う。
- 不正なUTF-16は比較で生コード単位を保持し、JSON exportでは
  `{"utf16":[55296,...]}`を返す。通常の有効な文字列の表現は従来通り。
- Readerの`max_blobs`は派生版にも適用する。`max_decoded_bytes`は累積展開量、
  `max_blob_bytes`は保持するBlobの合計を制限する。更新の作業コピー等があるため、
  これらはプロセス全体のRSS上限を意味しない。


再実行経路の回帰テストは `shirusu-probe/tests/replay.rs`。Emitter で作成した
Trace を読み、再実行仕様を生成・JSON 往復・実行計画検証・バンドル化する。
初期ファイル状態の欠落、矛盾した読取結果、OVERLAPPED 指定は生成失敗を確認する。
Windows では生成した独立 exe を空のディレクトリで実行し、再実行時には
既存ファイルを変更せず失敗することも検証する。この Windows 実動テストは
Linux 上の型検査だけでは代替できない。


`scripts/ci/replay-e2e.ps1` は合成 Trace を使わず、CRT に依存しない
ネイティブ Windows アプリを実際に注入・記録する。読み込む 1 バイトが異なる
2 実行から ReadFile.data の差分を選び、ルールの左 pass / 右 fail を確認し、
基準側の記録から生成した exe と JSON Runner をそれぞれ空のディレクトリで
実行して読み書き結果を検証する。windows.ps1 の必須ステップとして実行する。


API 拡張では、記録スキーマの幅とネイティブ ABI の型を別に保存する。
`generated_abi` は、生成されたラッパーを実際の型を持つ original に接続し、
void・ポインタ・i16・i64/u64・混在した f32/f64 の引数と戻り値を実行検証する。
負のゼロと NaN のペイロードは数値キャストせず `to_bits` / `from_bits` で往復する。
64bit 戻り値の上位 32bit を落とす変異、float を数値キャストする変異も
mutation スイートで検出する。Windows x86 の実行結果は Windows CI が必要。

IID カタログは Win32 Metadata 71.0.45-preview の全インターフェイスから
決定的に生成する。7,797 IID を保持し、同じ IID の別名も残す。IID の名前解決は
メソッドをフックできることを意味しない。通常の COM メソッド追跡は未対応であり、
`shirusu capabilities --json` でも明示的に false として返す。
再生成・検査には metadata-gen の
`--com-catalog crates/shirusu-trace/src/com_catalog_generated.inc` を付ける。

### COM Factoryの比較回帰検証

`com_factory`統合テストは実際のCapture SchemaからTraceを直列化し、32/64bitとアドレス配置を変えた同一操作が一致することを確かめる。CLSID・実行コンテキストの変化は差分になり、その差分から生成したルールが元のTraceで成功し変更後に失敗する。読めないGUIDは空の識別子として扱わない。ポインタをScalarに戻すmutationでアドレス差の回帰検出力を確認する。

新しいFactory SchemaはCoCreateInstanceとCoGetClassObjectで使用する。旧Schemaの生バイト列は復元できる型情報が不足するため、自動変換しない。COSERVERINFOの参照先は未展開であり、リモート認証設定の同一性までは比較できない。

## 2026-11-13 検証範囲の拡大

既存の基盤（Kani は transport のみ 14 本、loom 18 シナリオ、fuzz 8 本、TLA+ 2 モデル）を、
これまで形式検証が届いていなかった Hook の PE 解析・Inline 命令再配置、通知ロジック、
Trace のワイヤ形式、共有 COM の Module Epoch 手順へ広げた。

| 手法 | 追加したもの | 性質 |
| --- | --- | --- |
| Kani（transport） | `notify::proofs` 4 本、`crc32c::proofs` 3 本 | 除算なしの閾値判定が 128bit の定義式と全域で一致／閾値通知は上向きの縁でだけ出て、回収なしに二度出ない／Host 待機中は必ず通知／再確認の待ち時間は interval 以下。CRC 表が 256 エントリ全部でビット定義と一致、分割更新が一括と一致 |
| Kani（trace） | `compact::proofs` 4 本、`blob::proofs` 1 本 | ULEB/SLEB が任意の u64/i64 で往復し正規形で終わる／Compact の ULEB と Protobuf の varint が任意の 11 バイト以下で受理・値・消費長まで一致（二つの手書き実装の差分検査）／長さ付きバイト列の範囲／Blob 部分更新は長さを保ち範囲外を変えない |
| Kani（hook） | `inline::proofs` 5 本、`pe::proofs` 2 本 | パッチ長と実際のジャンプのバイト数が常に一致／rel32・x64 絶対・x86 絶対の各形が行き先にちょうど着く／境界検査付き読み取りはあふれ位置でも panic しない／NT ヘッダーを受理したらシグネチャとデータディレクトリがバッファ内 |
| fuzz | `proto_messages` `pe_image` `inline_plan`（短時間・長時間の両スクリプトに追加、種は `fuzz/seeds/`） | 上表 |
| PBT | `shirusu-hook/tests/pe_model.rs`（4 性質）、`inline_semantics.rs`（2 性質） | PE 仕様から書き起こした合成器で作ったインポート表・エクスポート表・セクション写像が解析結果と完全一致（PE32/PE32+、ILT 有無、名前と序数の混在、切り詰め）。任意のプロローグ命令列を任意の配置先へ再配置しても、独立デコーダで見て RIP 相対の実効アドレス・範囲外への分岐先・続きへの戻りが保たれ、±1GiB 内の配置では拒否しない |
| loom | `loom_global_order_*` 2 シナリオ | L11 の全体順序採番（Relaxed の fetch_add）が一意・密で、他スレッドの公開を観測してからの採番は必ず大きい |
| TLA+ | `NotifyLiveness.tla`、`SharedComEpoch.tla` | 下記 |

TLA+ の追加モデル（どちらも `scripts/ci/tla.sh` が主モデルの成立と、変種での反例検出の両方を必須にする）:

- `NotifyLiveness`：data_ready の進行性。閾値未満で通知の出ない公開や、Host の「空を確認 → 待機」の間に割り込んだ公開があっても、書き手が止まった後に全イベントが回収される（`Drained`、弱公平性は Host 側だけ）。期限なし待機の変種（`NotifyLivenessNoTimeout.cfg`）では反例が出る。期限付き待機（ReCheckPolicy）が進行性の唯一の担い手であることの証跡。
- `SharedComEpoch`：共有 vtable フックの Module Epoch。index の回収・再利用と、任意に遅れたアンロード通知を原子操作の単位で交互実行し、遅れた通知が新しい予約を退役させない（`NoStaleRetire`）、公開後の自モジュールの通知は失われない（`UnloadObserved`）、epoch は単調で新しい予約は常に新しい偶数（`FreshEpoch`・`EpochMonotone`）ことを検査する。CAS を通常 store に変えた変種（`SharedComEpochBlindStore.cfg`）では反例が出る。

この拡大で見つけて直した不具合（いずれも回帰テストを追加済み）:

1. **Inline パッチの変位計算のオーバーフロー（Kani）**。`jump_bytes` の rel32 変位を i64 の減算で求めていたため、二つのアドレスが 2^63 をまたぐと、変位自体は i32 に収まるのに減算があふれて debug ビルドで panic した。ユーザーモードの正規アドレスでは到達しないが、2 の補数の折り返し減算に直した。
2. **存在に意味がある Option の往復（fuzz `proto_messages`）**。`ModuleClassification.implementation_module = Some("")`、`StaticImport.name = Some("")`、`StaticImport.ordinal = Some(0)` が、proto3 の既定値省略で書き出されず、読み戻すと `None` に化けていた。存在するフィールドは常に書き出すようにした。空でない値の符号化は従来と同じバイト列のため、既存 Trace との互換は保たれる（`present_empty_optionals_survive_roundtrip`）。

分かった限界（正直な範囲）:

- loom 0.7 は変更順序を部分順序で持つため、「CAS と別スレッドの通常 store」が競合する手順で、C11 では起こり得ない結果（CAS が既に上書きされた値を読んで成功し、最終値が CAS の書いた値になる）を生成する。2 スレッドの最小リトマス（初期値 2、片方が `store(4)`、もう片方が `compare_exchange(2, 3)`、join 後の読み出しが 3）で、SeqCst を含むどの順序指定でも再現した。偽陽性の方向（実際には起きない失敗を報告する）なので既存の loom テストの合格は損なわないが、Module Epoch 手順は loom で検査できないため TLA+ で検査した。TLA+ は逐次一貫の交互実行であり、メモリ順序は検査しない。
- 2026-11-13 時点で Host は `OFF_HOST_WAITING` を立てていない（書き込み箇所はテストだけ）。そのため `NotifySignal::HostWaiting` の経路は本番では働かず、閾値未満の公開の回収は 2ms の期限付き再確認だけが担っている。`NotifyLiveness` は実装どおり `HostSetsWaiting = FALSE` でモデル化した。仕様の「Host が待機フラグを立てる」設計とずれているため、意図的かどうかの確認が要る。
- Kani の PE 証明は NT ヘッダーとデータディレクトリまでで、インポート／エクスポート表の走査（上限 4096×16384 反復のループと文字列化）は有界検証に向かないため、fuzz とモデルベース PBT が担う。CRC32C の SSE4.2 命令経路は Kani が扱えないため、ソフトウェア実装だけを証明し、両経路の一致は既存の単体テストが担う。
