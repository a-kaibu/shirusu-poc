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

## TLA+で検証する性質

最初のモデルは、Ring容量2、書き手1〜2、読み手1の小さな構成とする。バイト列ではなく、各セルの持ち主・状態・Generation・公開済みかどうかを扱う。スレッドの終了と`DLL_THREAD_DETACH`後の呼び出しもモデルに含める。

| 不変条件 | 命題 |
| --- | --- |
| `NoUnpublishedRead` | Hostは未確定のイベントを受け取らない |
| `NoOverwriteBeforeRelease` | 書き手は未回収の領域を書き換えない |
| `ExclusiveCellOwnership` | 同じ領域に書ける書き手は同時に一人 |
| `NoStaleProducerWrite` | 再利用した後に古い書き手が書き換えない |
| `SequenceConsistency` | 公開済みイベントの順序と欠落情報が矛盾しない |
| `NoPermanentBlocking` | Host停止や容量不足で待機が無期限に続かない |

進行性には公平性の前提が要る。有限のバッファでは「Hostが永久に止まっても全部保存する」は成り立たないので、「容量不足なら欠落として前に進む」ことを検証する。TLA+の状態機械とPBTの参照モデルは同じ不変条件を共有するが、実装は独立させ、実装のバグを参照モデルに写し込まないようにする。

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
| Nightly | 長時間Fuzz、多数SeedのPBT・DST、Host・Agentの障害注入 |
| 週次 | 拡大したloom、TLA+の状態探索、長時間の負荷テスト |
| リリース前 | 全検証、Application Verifier、破損復旧、異なるWindows環境での確認 |

PBTとDSTで見つけたSeed、Fuzzの最小入力、loomの失敗スケジュールは回帰テストに加える。テストが本当に不具合を検出できるかは、ReleaseをRelaxedにする、Generationの確認を外す、容量計算を壊すといった変更を加えて確かめる（Mutation Test）。

## 実装の順序

1. TLA+でSPSC Ring、Slotの再利用、スレッド終了をモデル化する。
2. SPSCの最小実装を作り、容量2程度の小さなRingでUnit・PBT・loomを通す。
3. Hostの検証ロジックを分け、KaniとFuzzを通す。
4. 故障操作を混ぜたPBT（DST）でOverflowと生成・回収を検証する。
5. Windows E2Eでx86 Agentとx64 Host、強制終了、通知の欠落、Ringの再利用を確かめる。
