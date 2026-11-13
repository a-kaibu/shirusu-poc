# Trace 形式仕様（公開形式 v1）

Phase 2 で確定した、公開 Trace ファイルの形式仕様である。Agent–Host 間の
転送形式（非公開、いつでも変更可）とは別に、こちらは公開仕様として互換性を
維持する。設計の前提は `docs/overview.md` の「Trace形式」節であり、本書は
その未決定点を実装として確定させた記録を兼ねる。判断の経緯は README の
所感（2026-11-09 Phase 2）にもある。

## バージョン管理

| 対象 | バージョン | 場所 |
| --- | --- | --- |
| Container | 1 | File Header の `container_version` |
| Schema（符号化規則） | 1 | File Header の `schema_version` と各 Schema 定義の ID |
| Compact Binary 規則 | 1（Schema バージョンに追随） | 本書 |

Container と Schema は別々にバージョンを持つ（overview の決定どおり）。
一度発行した Schema ID が表すバイナリレイアウトは変更しない。意味を足す
ときは互換のある Annotation を追加するか、新しい Schema ID を発行する。

## ファイル全体レイアウト

ファイルは Block の列である。先頭は必ず Header Block、以降は任意順で、
Blob は参照する Event Chunk より先に書く（前方参照を許さない、overview
の決定）。Writer は参照の直前に Blob をフラッシュしてこの順序を守る
（F09）。Reader は走査後に Blob を一括解決するため順序を問わず内容は
解決できるが、順序の違反は黙って通さず、前方参照を `ForwardBlobReference
{ id }` として issue に記録する（F23。内容は保持し、拒否はしない）。Index と Finalization は末尾に置き、両方とも省略可能である。
Finalization が無いファイルは「途中で終わった可能性がある」ものとして
扱い、完全性を確定できない（Event Integrity = Unknown 相当）。

| 順 | Block | 必須 | 内容 |
| --- | --- | --- | --- |
| 1 | Header | ○ | Magic、Container/Schema バージョン、Session ID、Feature Flags |
| 2 | Environment | ○（Writer は必ず書く） | Capture Environment（Protobuf） |
| 3 | Schema | 必要時 | Schema 定義の集合（Protobuf） |
| 4 | Event Chunk（繰り返し） | － | Event Batch（Batch Header は Protobuf、イベント列は Compact Binary） |
| 5 | Blob Chunk（繰り返し） | － | Blob 本体の集合（生バイト列の連結、後述） |
| 6 | Schema Checkpoint（繰り返し） | － | 途中までに必要になった Schema 定義の複製（Protobuf、Schema と同形式）。Writer は Schema Block の直後にも書く（F22） |
| 7 | Loss | － | Loss Record の列（Protobuf） |
| 8 | Index | 省略可 | Block 索引（Protobuf）。ランダムアクセス用 |
| 9 | Finalization | 省略可 | 正常終了の印と集計、完全性（Protobuf） |

## Block Container

### Block ヘッダー（32 バイト固定、little-endian）

| オフセット | サイズ | フィールド | 意味 |
| --- | --- | --- | --- |
| 0 | 4 | magic | `SBLK`（0x4B4C4253）。Block 境界の目印と再同期用 |
| 4 | 1 | block_type | 下表 |
| 5 | 1 | compression | 0 = 無圧縮、1 = Zstd フレーム |
| 6 | 2 | header_len | 常に 32（将来の拡張用に値を持つ） |
| 8 | 8 | sequence | ファイル内の Block 連番（0 始まり、欠番なし） |
| 16 | 4 | stored_len | 格納バイト数（payload の長さ） |
| 20 | 4 | raw_len | 展開後バイト数（無圧縮時は stored_len と同値） |
| 24 | 4 | crc32c | 後述 |
| 28 | 4 | reserved | 0 でなければならない（検証対象） |

チェックサムは CRC32C で、対象は「crc32c 欄を 0 にしたヘッダー 32 バイト
＋ payload 全体」（overview の決定：ヘッダーとペイロード、チェックサム欄
自身は除く）。改竄の検出は目的にしない。

判定値（決定）:

- `stored_len` の上限は 512 MiB（`MAX_STORED_LEN`）。これを超える値は
  ヘッダー破損として扱い、その Block を受理しない。
- `raw_len` の上限は 256 MiB（`MAX_RAW_LEN`）。展開後サイズの上限として
  Zstd 展開時の割り当てを縛る（overview の「展開後サイズに上限」）。
- 未知の block_type は読み飛ばす（payload 長だけ進める）。未知の
  compression は破損として扱う（展開方法が分からないため）。
- Header Block の payload にも Magic `SHIRUSU\0TR`（10 バイト）を含め、
  ファイル種別の二重確認とする。

### Block 種別

| 値 | 名前 | payload 形式 |
| --- | --- | --- |
| 1 | Header | 固定レイアウト（下記） |
| 2 | Environment | Protobuf `CaptureEnvironment` |
| 3 | Schema | Protobuf `SchemaSet` |
| 4 | EventChunk | Batch Header 長（LEB128）＋ Batch Header（Protobuf）＋ Compact Binary イベント列 |
| 5 | BlobChunk | Blob エントリの連結（下記） |
| 6 | SchemaCheckpoint | Protobuf `SchemaSet` |
| 7 | Index | Protobuf `BlockIndex` |
| 8 | Finalization | Protobuf `Finalization` |
| 9 | Loss | Protobuf `LossRecord` の repeated |
| 10 | BlobUpdate | 部分更新 1 件（下記。F18） |
| 11 | ProfileSummary | Protobuf `ProfileSummary`（L09。`profile` モードの集計） |

### Header payload（24 バイト固定）

| オフセット | サイズ | フィールド |
| --- | --- | --- |
| 0 | 10 | magic `SHIRUSU\0TR` |
| 10 | 2 | container_version = 1 |
| 12 | 2 | schema_version = 1 |
| 14 | 2 | header_flags（予約、0 でなければならない。Reader が検証する） |
| 16 | 8 | session_id |

Feature Flags は Environment / Finalization 側の Protobuf に持たせる
（拡張しやすさのため。決定）。

### Blob Chunk の payload

エントリの連結。各エントリは `blob_id`（32 バイト）＋ `len`（u32 LE）＋
本体 `len` バイト。Blob Chunk 自体が圧縮単位であり、エントリ単位の圧縮は
しない。同じ Blob ID が1ファイルに複数回現れてはならない（Writer は
セッション内で重複排除し、Reader は重複を破損として報告する）。

### BlobUpdate Block の payload（F18）

部分更新 1 件。レイアウトは次のとおり（すべて little-endian）。

| オフセット | サイズ | フィールド |
| --- | --- | --- |
| 0 | 32 | `resource_id`（基底 Blob の ID） |
| 32 | 32 | `new_version_id`（更新適用後の内容全体の BLAKE3） |
| 64 | 8 | `offset`（置き換え開始位置。u64） |
| 72 | 4 | `size`（更新内容の長さ。u32。残りバイト数と等しくなければならない） |
| 76 | `size` | `data`（置き換えるバイト列） |

`size` が残りバイト数と違う Block は破損として隔離する。Block レベル
の圧縮（Zstd）は可逆圧縮のみであり、元データに非可逆圧縮は使わない。

## 圧縮（Zstd）

- 圧縮単位は Block（= チャンク）ごと。Event Chunk / Blob Chunk に適用し、
  メタデータ系 Block（Header/Environment/Schema/Index/Finalization/Loss）
  は無圧縮で置く（決定：小さいことと、形式検査のしやすさを優先する。
  overview の「各チャンクは独立した Zstd フレーム」は Event/Blob の
  チャンクを指すと解釈する）。
- 形式は標準 Zstd フレームそのもの。実装は純 Rust の `ruzstd` を使う
  （依存判断の記録は「依存クレートの判断」節）。符号化レベルは
  `Fastest`（LZ 圧縮あり）か、展開互換を保ったままの `Uncompressed`
  （Raw ブロック）のみを使う。`ruzstd` の `Default` 等は現行版では
  `unimplemented!()` になるため使わない（決定。将来 ruzstd が実装したら
  再評価する）。
- Event Chunk の非圧縮サイズの目安は 512 KiB（overview の 256KiB〜1MiB
  の範囲内。決定：`DEFAULT_CHUNK_RAW_TARGET`。F25 のベンチ測定で
  256 KiB から変更。詳細は「チャンクサイズの決定（F25）」節）。
  Blob Chunk も同じ閾値で分割する。`WriterOptions::chunk_raw_target`
  で変更できる（0 は既定値と等価）。
- Zstd の学習済み辞書は使わない（overview の「初版では使わない」）。

## Protobuf メタデータ

符号化は標準の Protobuf ワイヤ形式（varint / length-delimited / 固定長）
そのものを使い、他言語の Protobuf 実装でも読める。ただし Rust 実装は
protoc / prost に依存せず、ワイヤ形式を手書きで符号化・復号する
（判断理由は「依存クレートの判断」節）。フィールド番号は本書が正であり、
未知フィールドは読み飛ばす（前方互換）。文字列は UTF-8、バイト列は
bytes とする。

### メッセージ定義（proto 表記は意味の定義であり、生成には使わない）

```proto
message SessionMetadata {           // Header とは別に Environment 先頭でも参照する
  uint64 session_id = 1;
  string created_by = 2;            // 例 "shirusu-host 0.1"
  uint64 qpc_frequency = 3;         // イベント時刻の周波数（0 は不明）
}
message HookEvidence {
  string module = 1;
  string function = 2;
  string method = 3;                // iat / inline
  string outcome = 4;               // installed / not-installed / unknown
  string reason = 5;                // engine reason; already-hooked != installed
  string scope = 6;                 // initialization snapshot, limited scope
  string semantic_detail = 7;       // recorder capability, not event completeness
  uint32 semantic_level = 8;
  uint32 api_id = 9;                // session API ID, also used by ProfileSummary
}
message CaptureEnvironment {
  SessionMetadata session = 1;
  string os_version = 2;
  uint32 os_build = 3;
  string cpu_arch = 4;              // "x86_64" / "x86" / "aarch64"
  uint32 pointer_width = 5;         // 32 / 64
  string capture_config = 6;        // 記録設定の要約（自由形式）
  uint64 feature_flags = 7;
  string target_description = 8;    // 対象プロセスの説明（任意）
  repeated ModuleClassification modules = 9;  // L07: モジュール分類。
                                    // 空のときは書かないので旧ファイルと同じバイト列
  repeated HookEvidence hook_evidence = 11; // 初期化時の API 別設置証拠。未記録は不明。
  repeated StaticDependency static_dependencies = 10;  // L13: 静的依存。
                                    // 空のときは書かないので旧ファイルと同じバイト列
}
message StaticDependency {          // L13: 1 DLL への静的依存
  string module = 1;                // インポートテーブルに書かれたままの DLL 名
  repeated StaticImport imports = 2; // テーブルに現れた順
}
message StaticImport {              // L13: インポートされた関数 1 件
  string name = 1;                  // 名前インポート（ある場合のみ）
  uint32 ordinal = 2;               // 序数インポート（ある場合のみ）
}
message ModuleClassification {      // L07: 1 モジュールの分類結果
  string module_name = 1;           // ロードされたままの名前・パス
                                    // （API Set 契約名の場合もある）
  uint32 class = 2;                 // 1=windows 2=runtime 3=application
                                    // 4=unknown（未知の数値は unknown）
  string reason = 3;                // 判定理由
  bool uncertain = 4;               // 真のとき分類は不確実で、
                                    // Application として観測する
  string implementation_module = 5; // API Set 契約名の解決先
                                    // （解決できた場合のみ）
  bool overridden = 6;              // 真のとき CLI の上書きによる分類
}
message SchemaSet {
  repeated SchemaDef schemas = 1;
}
message SchemaDef {
  uint32 schema_id = 1;             // ファイル内連番。0 は予約（無効）
  string name = 2;                  // 例 "kernel32!CreateFileW"
  uint64 content_hash = 3;          // 正規化内容の BLAKE3 先頭 8 バイト（後述）
  repeated FieldDef fields = 4;
  string annotation = 5;            // 互換を壊さない意味情報の追加用
}
message FieldDef {
  string name = 1;
  uint32 ty = 2;                    // 型タグ（Compact Binary の型表）
  uint32 flags = 3;                 // bit0: 入出力が両方向（inout)、bit1: 省略可能、
                                    // bit2..=4: 値の意味種別 ValueKind (0=未指定 1=scalar
                                    // 2=pointer 3=handle 4=生成オブジェクト)。種別は正規化・
                                    // 比較の入力であり、型だけからの推定はしない (レビュー #4 #7)
                                    // bit5..=7: メモリの取得タイミング CaptureTiming
                                    // (0=未指定 1=Before 2=After 3=Completion 4=Both)。
                                    // タイミングも content_hash の入力に含まれる
                                    // bit8..=11: GetLastError の意味条件 LastErrorMeaning
                                    // (0=未指定 1=常に意味あり 2=戻り値 FALSE 時のみ
                                    // 3=戻り値 INVALID_HANDLE_VALUE 時のみ
                                    // 4=戻り値 NULL 時のみ 5=意味なし 6=戻り値 -1 時のみ)。
                                    // last_error フィールドだけに付ける。条件も content_hash の入力
}
message BatchHeader {
  uint64 session_id = 1;
  uint64 process_id = 2;            // Trace 内 Process ID
  uint32 raw_pid = 3;               // OS の PID 生値
  uint64 thread_id = 4;             // Trace 内 Thread / Writer ID
  uint64 base_timestamp_qpc = 5;    // バッチ先頭イベントの QPC 値
  uint64 qpc_frequency = 6;
  uint64 first_sequence = 7;        // バッチ先頭イベントの Writer 内通番
  uint32 event_count = 8;
  bool has_global_order = 9;        // L11: 真のとき各イベントに global_order あり（false のとき書かないので旧ファイルと同じバイト列）
}
message LossRecord {
  uint32 kind = 1;                  // 1=SequenceGap 2=Counters 3=UnknownTermination 4=IntegrityLost
  uint64 count = 2;                 // SequenceGap の欠番数 / Counters の dropped_events
  uint64 dropped_payload_bytes = 3; // Counters のみ
  uint64 degraded_events = 4;       // Counters のみ
  uint64 call_id = 5;               // UnknownTermination のみ
  string reason = 6;                // IntegrityLost のみ
  uint64 process_id = 7;
  uint64 thread_id = 8;
}
message BlockIndex {
  repeated IndexEntry entries = 1;
}
message IndexEntry {
  uint64 offset = 1;                // Block 先頭のファイルオフセット
  uint32 block_type = 2;
  uint64 sequence = 3;
}
message Finalization {
  uint64 total_events = 1;
  uint64 total_blobs = 2;
  uint64 total_loss_records = 3;
  uint32 capture_coverage = 4;      // IntegrityLevel: 0=Complete 1=Degraded 2=Lost 3=Unknown
  uint32 event_integrity = 5;
  uint32 semantic_completeness = 6;
  bool finalized_cleanly = 7;       // この Block が書けたこと自体が正常終了の印。常時 true
  repeated string notes = 8;
}
message ProfileSummary {            // L09: `profile` モードの集計全体
  uint64 qpc_frequency = 1;         // 所要時間（QPC ティック）の換算用
  uint64 total_events_seen = 2;     // `record_batch` に渡された全イベント数
  repeated ApiProfile apis = 3;     // api_id の昇順
}
message ApiProfile {                // L09: API ごとの集計 1 行
  uint32 api_id = 1;
  uint64 calls = 2;                 // enter / leave が揃った呼び出し数
  uint64 enters = 3;                // 観測した enter 数（leave が無くても数える）
  uint64 leaves = 4;                // 観測した leave 数（enter が無くても数える）
  uint64 total_duration_qpc = 5;    // 揃った呼び出しの所要時間の合計
  uint64 min_duration_qpc = 6;      // calls == 0 のとき 0（「呼び出し無し」）
  uint64 max_duration_qpc = 7;      // calls == 0 のとき 0
}
```

`SessionMetadata` は Header payload の session_id と一致させる。Reader は
不一致を `SessionMismatch` として issue に記録する（回復意味論の表を参照）。
Writer は Header・Environment・各 Batch の session_id を単一源泉で一致させる。
Environment は後から完全なスナップショットを追記でき、Reader は最後に正常に
復号できたスナップショットを採用する。更新時に session_id と qpc_frequency は
変更できない。終了前に中断された Trace には初期のモジュール情報だけが残る場合がある。
`content_hash` は、正規化した Schema 定義の BLAKE3 ハッシュ先頭
8 バイト（LE）。正規化バイト列は「名前のバイト列＋区切り 0xFF＋
フィールドごとに（名前のバイト列＋区切り 0x00＋ty の u32 LE＋
flags の u32 LE）」とする（曖昧さのない連結のため区切りを入れる）。
別 Trace 間で同じ定義かを判定するために使う（overview の決定）。
完全な 32 バイトではなく 8 バイトに切り詰めるのは、衝突判定が
「同一ファイル内の重複検出と、Trace 間の目安」用途だからであり、
セキュリティ用途ではない（決定）。

### 取得タイミング（CaptureTiming）

メモリの取得タイミングは Schema で引数ごとに定める（overview
「型付きの値」節の決定。F19）。FieldDef.flags の bit5..=7 に格納する。

- `Before`（1）: 呼び出し前に取得する。入力バッファの内容はここで取る。
  enter Schema のフィールドは原則すべて Before である。
- `After`（2）: 元の API が書き込んだ後に取得する。出力バッファの内容は
  ここで取る。leave Schema のフィールドは原則すべて After である。
- `Completion`（3）: 非同期 I/O の完了時に取得する。leave 時点では完了
  していないため、完了を捕捉する仕組みが値を供給するまで取得できない。
  現行フックは OVERLAPPED 指定の leave 時点で当該フィールドを
  Unsupported として記録する（完了時の取得機構は F27 の対象）。
- `Both`（4）: 入出力が同じバッファで、前後両方のスナップショットを
  保存する。フィールドは enter と leave の両 Schema に現れ、それぞれの
  時点で別々の値として保存する。現行の 6 API には入出力共用バッファが
  無いため Both の実例は無く、L03 の API 拡張時に初めて現れる。

取得タイミングの違いは Schema の意味の違いであり、content_hash の
入力に含まれる（タイミングだけが違う Schema は別物として判定される）。

### GetLastError の区別（LastErrorMeaning）

GetLastError の生値と、API 仕様上意味のあるエラー値を区別する（overview
「型付きの値」節の決定。F20）。FieldDef.flags の bit8..=11 に格納する。

- `Unspecified`（0）: 条件を宣言しない旧来の Schema 用。利用側は生値を
  そのまま意味のある値として扱う（フォールバック）。
- `Always`（1）: 常に意味を持つ（`GetLastError` 自体など、戻り値が
  エラー値そのものである API 用）。
- `WhenReturnIsFalse`（2）: 戻り値が FALSE / 0 の場合にだけ意味を持つ
  （BOOL 戻り値の API。現行の ReadFile / WriteFile / CloseHandle）。
- `WhenReturnIsInvalidHandle`（3）: 戻り値が INVALID_HANDLE_VALUE の
  場合にだけ意味を持つ（HANDLE 戻り値の API。旧来の CreateFileW 宣言など）。
  INVALID_HANDLE_VALUE はポインタ幅依存（64bit: 全ビット 1、32bit:
  下位 32 ビットのみ 1。レビュー第5回 #5）。
- `WhenReturnIsNull`（4）: 戻り値が NULL (0) の場合にだけ意味を持つ
  （HANDLE / ポインタ戻り値の API。L03 の生成 API 用。
  CreateMutexW / VirtualAlloc 等）。
- `Never`（5）: GetLastError に意味がない（戻り値がエラーコード
  そのものである API (Reg* 等) や、失敗しない・失敗を戻り値で表さない
  API。L03 の生成 API 用）。取得側は生値を常に `Stale` として記録する。
- `WhenReturnIsMinusOne`（6）: 戻り値が -1 (全ビット 1) の場合に
  だけ意味を持つ（WAIT_FAILED / SOCKET_ERROR 等の -1 返し。L03 の
  生成 API 用）。32bit 形（下位 32 ビットのみ 1）も失敗とみなす。

- `WhenReturnIsNotNull`（7）: 戻り値が非 NULL の場合だけ意味を持つ。
  GlobalFree / LocalFree は NULL が成功、ハンドルの返却が失敗を表す。
- `DependsOnInputs`（8）: 戻り値だけでは決まらず入力条件も必要。
  CreateFileW は失敗時、または CREATE_ALWAYS / OPEN_ALWAYS の指定時に意味を持つ。
  Capture が契約を評価して Captured / Stale を保存する。戻り値だけを受け取る
  `is_meaningful` はこの条件では保守的に true を返し、値を捨てない。
  bit11 を追加使用するが既存の条件値 0〜7 と他の意味ビットは変更しない。

互換性：未知の条件値は `Unspecified` として読む
（前方互換）。値 4〜8 を知らない旧来の Reader は `Unspecified`
として読むため、生値を意味のある値として扱う（緩い読み）。値 8 は旧3ビット
mask でも 0（Unspecified）となり、値ごとの Captured / Stale は引き続き読める。

取得側は、条件を満たさない生値を `ValueCapture::Stale`（符号化 5）と
して記録する。Stale の値本体は読み取った生値を保持する（再検証のため）
が、表示では `<stale>` とし、比較では状態名だけで比較して残留値の違い
を差分にしない。条件を満たす生値は `Captured` として記録し、意味の
あるエラー値として比較する。条件の違いは Schema の意味の違いであり、
content_hash の入力に含まれる。

互換性：取得状態に `Stale`（5）を追加した。符号化 5 を含む値列は、
それを知らない旧来の Reader では復号できない（`InvalidCapture`）。
v1 形式の開発途上の追加であり、既存の符号化 0〜4 の意味は変わらない。

## Compact Binary

Schema が型と順序を定め、値ごとの型タグは持たない（overview の決定）。
各値には取得状態が付く。符号化はすべて little-endian 基準。

### 基本規則

- 符号なし整数は unsigned LEB128、符号付きは zigzag LEB128。
  LEB128 は最大 10 バイト（u64/i64 の範囲）。11 バイト以上や、最終
  バイトに継続ビットが残る入力は不正。
- 浮動小数点は生ビット列（f32 は 4 バイト、f64 は 8 バイト、LE）。
  NaN のペイロードもそのまま保持する。
- bool は 1 バイト（0 / 1 以外は不正）。
- 文字列・バイト列は長さ（LEB128）＋本体。文字列は UTF-8 を原則とし、
  UTF-16 は `Str16` 型として u16 列（LE）を長さ（要素数）付きで持つ。
- ポインタは Schema の型で幅が決まる（`Ptr32` / `Ptr64`）。
  値は生のアドレス値（LEB128 ではなく固定幅 LE。決定：アドレスは
  差分符号化しない素の値として読む場面が多いため）。アドレス空間は
  値の取得状態とは別に、イベント側ではなく Schema の Annotation で
  表す範囲とし、v1 では値そのものだけを持つ。
- NULL はポインタ値 0 で表す。読めなかった値は NULL にせず、取得状態
  `Unreadable` を付け、値スロットにはダミーの 0 を書く（overview の
  「読めなかった値を NULL として保存しない」）。

### 型タグ（FieldDef.ty）

| 値 | 型 | 符号化 |
| --- | --- | --- |
| 1 | I32 | zigzag LEB128 |
| 2 | I64 | zigzag LEB128 |
| 3 | U32 | LEB128 |
| 4 | U64 | LEB128 |
| 5 | F32 | 4 バイト LE 生ビット |
| 6 | F64 | 8 バイト LE 生ビット |
| 7 | Bool | 1 バイト |
| 8 | Str | LEB128 長＋UTF-8 |
| 9 | Str16 | LEB128 要素数＋u16 LE 列 |
| 10 | Bytes | LEB128 長＋生バイト |
| 11 | BlobRef | 32 バイト固定（Blob ID） |
| 12 | Ptr32 | 4 バイト LE |
| 13 | Ptr64 | 8 バイト LE |

未知の型タグを持つ Schema は、その Schema を使う値列の復号を拒否する
（Schema 自体の読み込みは許す。後方互換のため）。

### 値列のレイアウト

1 レコード（1 イベントの引数列など）は、Schema のフィールド数と同じ
個数の値を順に並べたもの。各値は「取得状態 1 バイト＋値本体」。
取得状態: 0 = Captured、1 = Unreadable、2 = Truncated、
3 = Unsupported、4 = LimitExceeded、5 = Stale。Unreadable / Unsupported
の場合も本体は符号化する（ダミー 0 / 空）。Stale だけは例外で、本体に
読み取った生値を保持する（再検証のため）。復号側は余分なバイト列の残りを
不正として拒否する。

### イベント列のレイアウト（Event Chunk 内）

Batch Header 長（LEB128）＋ Batch Header（Protobuf）の後に、Compact
Binary のイベント列が続く。Protobuf メッセージは後続バイト列との境界を
自己判定できないため、長さを先行させる（決定）。

```
event_count は Batch Header 側で宣言する。各イベント:
  seq_delta      LEB128   前イベントの sequence との差（先頭は first_sequence との差）
  ts_delta       zigzag LEB128  前イベントの timestamp_qpc との差（先頭は base_timestamp_qpc との差）
  kind           LEB128   転送 Descriptor の kind と同じ番号（1 = CallEnter、2 = CallLeave、7 = CallAborted、8 = CallCompleted）
  call_id        LEB128
  parent_call_id LEB128
  api_id         LEB128
  schema_id      LEB128   （0 = 引数なし / Schema 未割当）
  capture        1 バイト  イベント単位の取得状態（転送 CaptureState の番号: 下記）
  payload_tag    1 バイト
    0 = None
    1 = Blob      → 32 バイトの Blob ID
    2 = Inline    → LEB128 長＋バイト列
    3 = Dropped   → LEB128 元の長さ＋理由 1 バイト（1=Backpressure 2=TooLarge 3=Overflow 4=HostStopped 255=Other）
  args_tag       1 バイト
    0 = なし
    1 = あり → LEB128 長＋ Compact Binary 値列（schema_id の Schema で解釈）
  global_order   LEB128   Batch Header の has_global_order が真の場合のみ。
                          先頭は絶対値、2 件目以降は前イベントからの差分。
                          同一 Batch 内で厳密に増加するため差分は 1 以上。
                          0・overflow は破損として拒否。
```

イベント単位の取得状態（capture）は転送 `CaptureState` の意味を保ち、
番号は 0 = Captured、1 = MemoryUnreadable、2 = CaptureLimitExceeded、
3 = DroppedByBackpressure、4 = Truncated、5 = Unsupported とする
（転送 flags のビット位置とは別に、本形式での連番として定義する。
決定）。未知の番号は `Other(u8)` として保持し、往復で失わない。

sequence は Writer（スレッド）単位で単調増加が前提であり、seq_delta が
負になる入力（= 減少）は Batch の破損として扱う。timestamp は差分が
負になり得るため zigzag とする。

## Blob ストア

- Blob ID は内容の BLAKE3 ハッシュ（32 バイト）。ID が同じでも、
  データが同じだけで Windows オブジェクトの同一性とは無関係
  （overview の注意どおり）。
- ディレクトリ配置: `<root>/<先頭2hex>/<全体hex>` の2段。
  書き込みは「無ければ書く」。書き込み途中の不完全ファイルが残る
  可能性に備え、読み出し時に長さとハッシュを検証できる API
  （`get_verified`）を持つ。通常の `get` は存在確認＋読み出しのみ。
- Trace ファイル内の Blob は Blob Chunk に分離して持つ。Reader は
  Trace 内 Blob を Blob ID で引ける形に復元する。Blob ストアと
  Trace 内 Blob は同じ BlobId 型を共有する。
- Trace Writer は Payload を受け取るたび、セッション内の既出集合で
  重複排除する。Blob 本体は、参照する Event Chunk より前に Blob
  Chunk として書き出す（バッファし、Event Batch 書込直前と
  finalize 時にフラッシュする）。

## Blob の部分的な更新（F18）

overview「チャンク、圧縮、Blob」節は「部分的な更新は、Resource ID、
オフセット、サイズ、更新内容で表す。元データは可逆圧縮だけで保存する」
とする。v1 の決定は次のとおり。

- **Resource ID は基底 Blob の ID**（内容の BLAKE3 ハッシュ）である。
  リソースの同一性は「最初に確立した内容のハッシュ」で表し、新しい
  ID 空間は作らない。更新は基底内容の `[offset..offset+size)` を
  `data` で置き換える。長さは変わらない（範囲外の更新は無効）。
- **更新は BlobUpdate Block（種別 10）で表す**。1 Block に更新 1 件。
  payload のレイアウトは「BlobUpdate Block の payload」節のとおり。
  `new_version_id` は更新適用後の内容全体の BLAKE3 であり、呼び出し側
  （更新後の全体内容を観測した記録側）が求めて渡す。
- **Writer は基底の全体内容を保持しない**。そのため新版 ID の正しさは
  Writer では検証しない（Reader が畳み込み結果のハッシュと照合する）。
  Writer が検証するのは「リソースがこのセッションで既知であること」と
  「`offset + size` が基底長以内であること」のみで、反すれば書かない
  （`WriterInvariant` エラー）。更新は基底の Blob Chunk より後に書く
  （書出し前に未書出し Blob をフラッシュする）。新版 ID は既知として
  登録するため、後続のイベントが新版を参照できる。更新版への Payload
  参照を作るのに全体内容を改めて格納する必要はない（更新記録だけで足りる）。
- **Reader は走査後にファイル順で畳み込む**。後の更新が前の更新に重なる
  範囲は、後の更新が勝つ。`resource_id` が既に具体化された派生版を指す
  場合は、その版を起点に畳み込む。適用に成功した版は、内容をその
  BLAKE3（＝宣言された新版 ID）で `blobs` へ具体化する。そのため更新版
  を参照するイベントの Payload 解決は通常の Blob 参照と同じ経路で動き、
  `Finalization.total_blobs` の照合（格納した Blob＋派生版の合計）も
  一致する。`resource_versions`（リソース→直近の版）は読み取り結果で
  引ける。
- **失敗した更新は適用せず、issue として記録する**（内容は推測で作らない）。
  基底が無い場合は `BlobUpdateMissingBase`（リソースごとに 1 回）。
  範囲外の場合は `BlobUpdateOutOfRange`（基底の内容はそのまま残し、後続
  の正常な更新の畳み込みは続く）。畳み込み結果のハッシュが宣言と違う
  場合は `BlobUpdateHashMismatch`（Blob ID は内容ハッシュそのもの、
  という設計を更新経路でも守る）。3 件とも conformance の clean-scan
  では damaging 扱い（内容を復元できないため）。宣言サイズと実データ長
  が食い違う Block は、復号の時点で破損として隔離する。
- **元データは可逆圧縮だけで保存する**。基底 Blob と更新内容は、Block
  レベルの Zstd（可逆）または無圧縮でしか保存しない。更新内容そのものに
  非可逆圧縮や差分の再符号化はしない。更新の表現自体が差分であるため、
  全体内容の再格納は要らない。

## Event Chunk の独立デコード可能性（F22）

overview「チャンク、圧縮、Blob」節は「各 Event Chunk は、自分をデコード
するのに必要な Schema の部分集合とローカル辞書を持つ」「独立デコード
可能」（チャンク単独で型とイベントを解釈できる）とする。v1 の決定は
**Checkpoint 方式で十分とする**ことであり、字面どおりのチャンク毎の
部分集合埋め込みはしない。根拠は次のとおり。

- チャンクの構造復号（イベント境界・sequence・timestamp・api_id・kind・
  args の生バイト列）は Schema を要しない。BatchHeader は基底の
  sequence / timestamp_qpc を持ち、イベントは schema_id を不透明な
  参照として持つだけである。つまり「チャンク単独でイベント列を復号し、
  API 呼び出しを列挙・検索できる」ことは、Schema が無くても成り立つ。
- Schema が要るのは args の型付き解釈のみである。Reader はファイル
  全体を走査して Schema / Schema Checkpoint の定義を 1 つのレジストリ
  に集めるため、ファイル内のどこかに定義のコピーが 1 つ残っていれば、
  全チャンクの型付き解釈ができる。
- チャンク毎の部分集合埋め込みは、セッション全体で共有される Schema
  集合を全チャンクに重複させるだけで、新しい情報を増やさない。
  Checkpoint は Schema の変化回数に比例するコストで同じ回復性を得る。

したがって v1 の保証は二層である。

1. **構造復号と API 呼び出しの検索はチャンク単独で可能**（Schema 不要）。
   Schema Block が壊れても、イベント列は復号でき、API 呼び出しは
   `dump --api` 等で検索できる。args の生バイト列はイベントに残る。
2. **型付き解釈は、ファイル内のいずれかの Schema / Checkpoint に
   定義が残っている限り可能**。Writer は Schema Block を書くたびに、
   直後にその時点までの全定義の複製を Schema Checkpoint Block として
   書く（`TraceWriter::flush_schemas`）。これにより、単一 Block の
   破損では型付き解釈は失われない。手動の `write_schema_checkpoint()`
   は、長時間記録の途中で任意の時点に複製を追加で置くために残す。

「リソース復元可能」との区別: 独立デコード可能とは、チャンク単独で型と
イベントを解釈できることである。参照先の Blob やオブジェクト状態まで
含めて復元できる「リソース復元可能」とは別である。Blob が壊れても上記
1. は保たれる（API 呼び出し自体は検索できる）が、Blob 内容の復元は
できない。Blob 喪失は `MissingBlob` として明示され、イベントは保持
される（回復意味論の表の行どおり）。

境界: v1 の冗長性は単一 Block 破損までである。Schema Block とその
Checkpoint の両方が壊れると型付き解釈はできない（構造復号と API 検索は
残る）。周期的な Checkpoint（Schema の変化が無い長い区間での複製）は
将来の拡張とし、Host が `write_schema_checkpoint()` を任意の時点で
呼ぶことで置ける。

## チャンクサイズの決定（F25）

overview「チャンク、圧縮、Blob」節は「チャンクの大きさは非圧縮で
256KiB〜1MiBを目安に、ベンチマークで決める」とする。`e2e/src/bin/
shirusu-trace-bench.rs` で 20,000 イベントの決定的な合成ワークロード
（CreateFileW 20% / ReadFile 30% / WriteFile 30% / CloseHandle 20%、
64 種のパス Blob＋256 種のデータ Blob（512 B〜4 KiB）を参照、10,000 件
ずつの Batch）を 128 KiB / 256 KiB / 512 KiB / 1 MiB で掃引した。
測定は 2026-11-11、共有 Linux VM、release ビルド、各目標値 5 回の中央値。

| 目標値 | 総バイト数 | バイト/イベント | Event Chunk 数 | 書き込み | デコード |
| --- | --- | --- | --- | --- | --- |
| 128 KiB（対照・範囲外） | 555,459 | 27.8 | 8 | 33.0 ms | 12.6 ms |
| 256 KiB | 550,193 | 27.5 | 4 | 36.1 ms | 12.6 ms |
| 512 KiB | 542,515 | 27.1 | 2 | 36.0 ms | 12.5 ms |
| 1 MiB | 542,515 | 27.1 | 2 | 36.3 ms | 12.5 ms |

決定：**既定値は 512 KiB**（`DEFAULT_CHUNK_RAW_TARGET`）。
決定規則は、仕様の目安範囲 256 KiB〜1 MiB の中で「1 MiB に対する
総バイト数が +1% 以内で、デコード時間が最速の +5% 以内を満たす最小の
目標値」とした。256 KiB は同ワークロードで総バイト数が 1.4% 多く
（550,193 B 対 542,515 B）、512 KiB と 1 MiB は同値で最良だった。
書き込み・デコード時間は全目標値で差が無かった（1% 未満）。
大きいチャンクは同一内容の圧縮で不利にならない（窓が広がる分だけ
良化するか同値）が、1 Block の破損で失われる量が増えるため、最小の
合格値を既定とした。128 KiB は仕様範囲外の対照用で決定対象外。
注意：1.4% の差は繰り返し現れる Payload のチャンク跨ぎ圧縮によるもの
であり、Payload が全て異なるワークロードでは目標値による差はほぼ消える。
その場合でも 512 KiB が 256 KiB より悪くなることはない（同値に収束する）。

## 4 指標の分離測定（F26）

overview「転送形式とディスク形式」節は「ベンチマークでは Agent の
観測コスト、Host の処理量、ファイルサイズ、デコード速度を別々に測る」
とする。同じ `shirusu-trace-bench` で、F25 で決めたチャンクサイズ
（512 KiB）で 4 指標を分離して測った（2026-11-11、共有 Linux VM、
release ビルド、5 回の中央値）。

| 指標 | 測定方法 | 結果 |
| --- | --- | --- |
| M1 Agent の観測コスト | `Agent::record` を 50,000 件（8 B Payload、Ring 65,536 件 / 4 MiB、Host は回収しない） | **219.1 ns/イベント**（4,563,774 イベント/秒） |
| M2 Host の処理量 | 同じ 50,000 件を `DrainWorker::drain_all`（検証付き回収）＋`TraceRecorder::record_batch` で変換 | **228,517 イベント/秒**、書き出した Trace は 75.8 B/イベント |
| M3 ファイルサイズ | F25 の 20,000 イベントのワークロード（512 KiB） | **27.1 B/イベント**（542,515 B） |
| M4 デコード速度 | 同じ Trace の `read_trace` | **1,595,958 イベント/秒**（Trace バイト換算 41.3 MiB/秒） |

読み方の注意：

- M1 は記録経路（Ring 書き込みまで）のコストであり、Windows の
  Detour 自体のコストは含まない。Detour の実測は Windows 実機での
  ABI 適合性テスト（L06）の範囲。
- M2 の 75.8 B/イベントが M3 の 27.1 B/イベントより大きいのは、
  M2 のワークロードが 50,000 件すべて異なる 8 B Payload（重複排除が
  効かない）だからであり、M3 は現実的な重複のある Payload プールを使う。
  両者は別ワークロードの数値であり、直接の優劣ではない。
- M2 には `DrainWorker` の検証付き回収（共有領域の像全体のコピー。
  D65 の注記どおり Ring が大きいほど回収コストが増える）が含まれる。
  Ring 容量を変えると M2 は変わる。
- 絶対値は共有 VM の測定であり、機械によって変わる。比較の基準は
  測定方法（この節とベンチのヘッダ）とし、数値そのものを保証値としない。

## 全体順序 (--order=global) (L11)

overview「転送形式とディスク形式」節：`--order=global`を付けると、
フックの観測点ごとに全スレッド共通の番号を振る。この番号はアトミック
カウンタを更新した順序であり、API処理の完了順やメモリ操作全体の順序を
保証しない。別のPCで取ったTraceどうしは時刻の原点が異なるので、時刻
だけで対応づけない。

- 採番は Agent 側の `AtomicU64`（1 始まり）。`Agent::record()` 内、
  書き込み確定の直前に採番し、Descriptor の `global_order`（オフセット
  56、64B レイアウト維持）に刻む。書き込みが確定しなかったイベントは
  番号を消費しない。欠落したイベントの分は欠番になる（Sequence の欠番と
  同じ扱い）。
- Host は `CaptureSessionConfig.order_global` が真のセッションでのみ非 0
  を受け入れる。無効なセッションで非 0 は `GlobalOrderNotAllowed` として
  拒否する（条件付き検証。仕様は spec-transport.md「全体順序（L11）」）。
- `TraceEvent.global_order: Option<u64>`。Descriptor の 0 は None に
  変換する。`BatchHeader.has_global_order`（proto field 9）が真の Batch
  でのみ Compact Binary に符号化する（false のとき書かないので旧ファイル
  と同じバイト列）。符号化は args の後に ULEB128 を 1 個：先頭は絶対値、
  2 件目以降は前イベントからの差分（同一 Batch 内で厳密に増加するため
  差分は 1 以上。0・overflow は破損として拒否）。Writer は混在
  （Some+None）・非増加を拒否する。
- CLI：`dump --order=global` は全 Batch のイベントを global_order で
  マージして表示する。全体順序を持たないイベントが 1 件でもあれば
  「--order=global で記録されていない Trace」としてエラーにする。
  `dump` の行表示は全体順序がある場合だけ `g=<n>` を出す。
  `inspect` に有無を表示し、export の JSON にも全体順序がある場合だけ
  含める。`--order=global` は `--key=value` 形式で渡す
  （`parse_args` は `--key=value` を受け付ける）。
- shirusu-compare の正規化は `global_order` を無視する（比較は
  スレッド単位の呼び出し構造で行い、全体順序は実行ごとの観測順序で
  あって比較対象の契約ではないため）。

## 回復意味論（recover_trace）

Reader は、信頼できない入力として Trace を扱う（overview の決定）。
前提として、ファイル全体をメモリに載せる v1 実装であり、ストリー
ミング読みは将来の拡張とする（留保として明記）。

| 状況 | Reader の振る舞い |
| --- | --- |
| 先頭が Header Block でない / Magic 不一致 | 形式エラーとして全体を拒否（Trace ではない） |
| 末尾で Block ヘッダー・payload が切断 | そこまでの内容を返し、`TruncatedTail { offset }` を issue に記録 |
| Block の CRC 不一致 | その Block を破損として記録し、payload 長を信用せず再同期を試みる（後述） |
| stored_len / raw_len が上限超過 | 破損として扱い、再同期を試みる |
| Zstd 展開失敗 / 展開後長が raw_len と不一致 | その Block だけを破損として隔離し、次 Block から続行 |
| 未知の block_type | 読み飛ばして続行（破損ではない） |
| 同じ Blob ID の重複 | 破損として記録（内容が同一でも重複自体を報告） |
| 参照先 Blob がファイル内に無い | イベントは保持し、解決時に「欠落 Blob」として明示（イベント自体は検索可能） |
| Protobuf の破損 | その Block を破損として隔離（メタデータ欠落として報告） |
| Index の指すオフセットが実 Block と不一致 | Index を無視して走査結果を使う（Index は最適化であり正ではない） |
| Header と Environment / Event Chunk の session_id 不一致 | 内容は保持し、`SessionMismatch { what, expected, found }` を issue に記録（F17） |
| Blob Chunk が参照する Event Chunk より後に現れる（前方参照） | 内容は解決して保持し、`ForwardBlobReference { id }` を issue に記録（F23。Blob ごとに 1 回） |
| BlobUpdate の基底 Blob がファイル内に無い | 更新を適用せず、`BlobUpdateMissingBase { resource_id }` を issue に記録（F18。リソースごとに 1 回） |
| BlobUpdate の `offset + size` が基底長を超える | その更新を適用せず、`BlobUpdateOutOfRange { resource_id, offset, size, base_len }` を issue に記録（F18。基底の内容は残し、後続の正常な更新の畳み込みは続く） |
| BlobUpdate の畳み込み結果のハッシュが宣言された新版 ID と違う | その更新を適用せず、`BlobUpdateHashMismatch { resource_id, expected, computed }` を issue に記録（F18） |
| BlobUpdate の宣言サイズと実データ長が食い違う | その Block だけを破損として隔離する（F18。F05 の厳格さと同じ） |
| Schema Block の破損（CRC 不一致等） | その Block だけを破損として隔離。直後の Schema Checkpoint に複製があるため型付き解釈も維持される（F22）。複製も無い場合は、イベント列の構造復号（API 呼び出しの検索）までは可能だが、args の型付き解釈はできない（`schema N not registered` として残す） |
| Finalization が無い | `finalization: None` として返し、完全性は確定できないことを呼び出し側が分かる形にする |

再同期: 破損した Block の開始位置の次バイトから `SBLK` を探し、
候補位置で「ヘッダー長 32・種別既知または未知でも長さが上限内・
CRC が一致」の全てを満たす場合にだけ Block として受理し直す。
失われたイベントを推測で作ることはしない（overview の repair 方針）。
再同期で読み飛ばした範囲は `Resync { from, to }` として issue に残す。
再同期できない場合はそこで走査を止め、末尾切断と同様に扱う。

上限（決定）: ファイルサイズ自体の上限は設けないが、Block 数は
1,000,000、イベント総数は 100,000,000、Blob 総数は 10,000,000 を
Reader の既定上限とし、超過したら破損として停止する（DoS 対策の
目安値であり、設定で変更可能にする）。

## repair（L12）

`shirusu repair <trace> [--output <path>] [--json]` は、回復意味論
（recover_trace）で読めたイベントだけを新しい Trace に書き出す
CLI コマンドである。overview「完全性と復旧」節の「`shirusu repair`
は正常なチャンクと参照関係を検証して、読めるイベントを回収する。
失われたイベントを推測で作らない」に対応する。

- 入力は `read_trace`（回復読み）で読む。先頭 Header が不成立の
  入力は全体拒否となり、修復は行わない（出力ファイルは作らない）。
- 出力は `--output` で指定する。省略時は `<trace>.repaired`。
  入力そのものへの上書きは拒否する（修復元を壊さない）。
- 出力に残すもの：読めたイベント（元の Batch 順・元の内容のまま）、
  参照された Blob（内容の BLAKE3 から同じ ID を再計算する。重複排除
  済み）、Schema 定義、Loss Record。
- 回収できないもの：参照先 Blob がファイル内に無いイベント
  （MissingBlob。Blob の内容を推測して補わない）、Header と
  session_id が異なる Batch（SessionMismatch。session_id を書き換え
  て取り込まない）、同一スレッドで sequence が退行する Batch
  （Writer の不変条件に反するため、順序を並べ替えて取り込まない）、
  空の Batch。いずれも数えて報告する（`lost_events`）。
- Blob の部分的な更新（F18）は再発行しない。派生版の内容は Reader
  が `blobs` へ具体化済みで、イベントが参照する版 ID の内容を運べば
  十分なため。更新の履歴そのものは修復出力には残らない。
- Schema は同一内容の再登録は受理される。内容の違う再定義や
  content_hash の不一致は Writer が拒否するため、その定義だけ落と
  して数える（修復全体は止めない）。
- Finalization は元の Trace の三つの指標を引き継ぐ。ただし修復で
  イベントを失った場合、Complete の宣言は維持できないため
  event_integrity を Degraded（1）へ落とす。Finalization が無い入力
  は三つとも Unknown（3）とする。修復の来歴は notes に残す。
- 終了コード：0 = 修復済みファイルの書き出しに成功（イベントを
  失った場合も含む。失った分は報告に明記する）。1 = 入力が読めない・
  出力が書けない・入出力が同一。2 = 使い方の誤り。

## モジュール分類（L07）

overview「記録境界とモジュール分類」節に対応する。モジュールを
Windows / Runtime / Application / Unknown の 4 分類で扱い、判定理由
を `CaptureEnvironment.modules`（`ModuleClassification` の列）に残す。
`shirusu inspect`（人間可読・JSON）が表示する。分類と記録ポリシー
（どの呼び出しを記録するか）は分けて扱う。

分類の優先順位（上から先に当たったものを採用する）：

1. パスが空・特定できない → Unknown（不確実）。
2. API Set 契約名（`api-ms-win-*` / `ext-ms-win-*` の DLL）→ 実装
   モジュールが解決できればその分類、解決できなければ Unknown。
   論理名（契約名）と実装モジュールの両方を残す。
3. 既知の実行基盤モジュール → Runtime。対象は `msvcp*` / `msvcr*` /
   `vcruntime*` / `concrt*` と `clr.dll` / `coreclr.dll` /
   `clrjit.dll` / `mscorlib.dll` / `mscorwks.dll` / `mscoree.dll` /
   `ucrtbase.dll`。実行基盤であることはモジュール固有の性質のため、
   配置＋署名の Windows 判定より先に見る（これらは通常 System32 に
   あり Microsoft 署名付きだが、Runtime としての扱いが先。`fopen`
   経由の `CreateFileW` が記録されるのはこのため）。
4. System32 / SysWOW64 / WinSxS にあり Microsoft 署名を確認できる
   → Windows。KnownDLLs は System32 への解決、SxS は WinSxS への
   配置として同じ扱い。
5. システム配置だが署名が未確認 → Unknown（不確実として残す）。
   署名の確認そのものは Windows 側の仕事（WinVerifyTrust 等）で、
   分類器は `microsoft_signed` という証拠を受け取るだけである。
6. それ以外（EXE、同梱 DLL、サードパーティ製 DLL）→ Application。

パス比較は大文字小文字を区別せず、`\` と `/` を同じ区切りとして扱う。

- CLI からモジュール単位で分類を上書きできる：
  `shirusu capture --module-class <module>=<class> ...`（繰り返し可。
  class は windows / runtime / application / unknown）。上書きは
  ファイル名部分で突き合わせ、一致した分類を置き換えて `overridden`
  と理由に残す。一致しなかった上書きは、capture 開始時に未ロードの
  モジュールへの上書きが黙って消えないよう、上書きエントリとして
  Trace へ残す（理由は `CLI override (module not loaded at capture start)`）。
- Runtime 独自の API を記録するかは設定で選ぶ：
  `CaptureSessionConfig::record_runtime_apis`（既定は false＝記録しない）
  と CLI の `--record-runtime-apis`。設定は Bootstrap v5 で Agent DLL
  へ伝え、Detour の入口で呼び出し元の戻りアドレスからモジュールを特定
  し、分類が Runtime で設定が無効ならその呼び出しを記録しない（元の
  API だけ素通しで呼ぶ）。呼び出し元が特定できない場合は記録する
  （fail-open）。戻りアドレスは `RtlCaptureStackBackTrace` で取り、
  Agent DLL 自身のフレームを飛ばした最初の DLL 外のアドレスを使う。
  モジュール一覧は DLL 起動時に作り、呼び出し元が一覧に無い場合にだけ
  500ms に 1 回まで再列挙する（遅れてロードされたモジュールへの追随）。
  DLL 側の分類は名前だけに依存する Runtime 判定が目的のため、署名検証
  はしない（System32 のモジュールは Unknown になるが、抑制の判定は
  Runtime かどうかだけを見るため影響しない）。
- ロード済みモジュールの列挙と署名検証（L23）：capture 開始時に Host が
  対象プロセスの全モジュールを列挙する（`EnumProcessModulesEx` 等）。
  起動時は注入直後（再開前）の分と、再開後の安定化待ち（10ms 間隔・
  最大 200ms・2 回連続で同じ一覧になったら確定）の分を合成する。
  アタッチ時は安定化待ち列挙を使う（列挙の前後にロード・アンロード
  されたモジュールは含まれないことがある）。Trace と Ring 接続は起動対象
  の再開前に準備し、再開後の列挙・署名確認は別スレッドで行う。終了時に
  更新した Environment を追記するまでイベント回収を続ける。署名は `WinVerifyTrust`（失効確認なし）＋署名者証明書の
  表示名が "Microsoft Corporation" であることで確認し、
  `ModuleEvidence.microsoft_signed` へ渡す。API Set 契約名はローダ経由
  （`GetModuleHandleW(契約名)` が apisets スキーマを参照して返す実装
  モジュール）で実装モジュールへ解決する。CLI が作った既存の
  `modules`（起動対象 exe の分類と `--module-class` の未使用エントリ）
  と合成する：CLI の上書きは残し、それ以外の既存エントリは列挙の新しい
  証拠（署名確認済み）で置き換え、列挙に無かった既存エントリは末尾へ残す。
  列挙に失敗・空の場合は CLI の `modules` をそのまま使い、capture を
  失敗させない（`capture_config` に `module_scan=unavailable` と残す）。
  成功時は `capture_config` に `modules=<件数> (L23 async)` と残す。
  遅れてロードされたモジュール（capture 開始後に `LoadLibrary` された
  もの）は、この一覧には載らない。DLL 側の呼び出し元分類は再列挙で
  追随するが、Trace の `modules` は capture 開始時のスナップショット
  である。
- L01 の Inline Hook により、Runtime モジュール内の呼び出し（CRT 経由
  の `fopen` 内の `CreateFileW` 等）も Detour へ到達する。そのため抑制
  の実動（Runtime からの呼び出しを記録しないこと）は `capture-e2e
  --modules` で観測できる（`record_runtime_apis` 無効の既定では CRT
  経由の呼び出しは 0 件、有効にすると 1 件以上）。IAT フックだけの
  段階では Detour に届かず観測できなかったが、L01 で閉じた。
  `capture-e2e --modules` は列挙・署名検証・API Set 解決と、直接
  呼び出しの記録が壊れていないことも引き続き検証する。
- 性能の注記：抑制の判定は `record_runtime_apis` が無効（既定）の場合
  に全 Detour 呼び出しで走る（`RtlCaptureStackBackTrace`＋
  `VirtualQuery`＋二分探索）。有効にした場合は判定自体を飛ばすため
  追加コストは無い。L10 の性能測定は API 本体のモデルで行っており、
  Detour のコストは含まない。

## 詳細調査モード（L15）

overview「記録境界とモジュール分類」節に対応する。詳細調査モードでは、
Windows 内部の呼び出し（`CreateFileW` → `NtCreateFile` など）も記録する。

- 有効化：記録モード `detailed`（`RecordMode::Detailed`）。CLI は
  `shirusu capture --mode detailed`。`capture_config` には
  `mode=detailed` と残る。Host は Bootstrap v8 の `detailed_mode` で
  Agent DLL へ伝える。詳細調査モードでは Runtime 起源の呼び出しも
  記録するため、CLI は `--record-runtime-apis` を強制的に有効にする。
- 内部 API の表：ntdll の Nt* 7 件（api_id 79〜85。`NtCreateFile` /
  `NtOpenFile` / `NtReadFile` / `NtWriteFile` / `NtClose` /
  `NtQueryInformationFile` / `NtSetInformationFile`）。手書きの厳選表で
  あり、WinMD の生成対象ではない（Win32 公開 API ではないため）。L1
  （型付き引数・戻り値のみ。NTSTATUS を返す。Nt* は GetLastError を
  使わないため leave に `last_error` は無い）。Schema ID は表の順に
  enter = 2n-1、leave = 2n（157〜170）。設置は Inline Hook のみ
  （IAT は使わない）。詳細調査モードが無効な場合、Agent DLL は内部
  API の Inline Hook 自体を設置しない。
- 親子関係：内部呼び出しは、実際に起きた別の呼び出しとして
  `parent_call_id` に親（呼び出し元の Win32 API）の call_id を持って
  保存される。親子関係の記録自体は通常の入れ子呼び出しと同じ仕組み
  （Detour のスレッドローカルな呼び出しスタック）で、詳細調査モード
  以外の入れ子呼び出し（A43 / C18）にも同じ `parent_call_id` が付く。
- 再実行の規則：再実行・Probe 生成では、トップレベルの呼び出し
  （`parent_call_id == 0` のイベント）だけを実行し、下位呼び出し
  （`parent_call_id != 0`）を重ねて実行しない。下位呼び出しは親の操作
  の一部として既に実行されるためである。`shirusu-trace` の
  `TraceEvent::is_top_level` / `top_level_events` がこの抽出を提供する。
  親子関係が壊れた Trace（子の親が列に無い等）の扱いは、再実行側の
  判断に委ねる（ここでは決めない）。
- Coverage：内部 API は通常モードの Coverage 欠落には数えない
  （`HookPlan.missing` と Agent DLL の `missing` の両方で除外）。
  詳細調査モードでの設置数は Bootstrap の
  `result_internal_hook_count`（0〜7）で別に報告し、Host は
  `CaptureSummary.internal_hook_count` へ写す。
- 制限：対象は上記 7 件のファイル系 Nt* のみ。レジストリ・同期・
  メモリ等の内部呼び出し（`NtCreateKey` 等）は未対象。Nt* の引数は
  生値のみで、OBJECT_ATTRIBUTES 等の構造体の中身は取得しない。
  アタッチ前に存在した呼び出しの内部呼び出しは、親の Detour に
  届かないため記録されない。

## 静的依存情報（L13）

overview「観測レベル L0〜L4」節に対応する。インポートテーブル等から
分かる静的な依存は、レベル（L0〜L4）とは別の「静的依存」情報として
記録する。`GetProcAddress` で取得した関数のように、静的依存が無くても
呼ばれる API があるためで、静的依存の有無と動的解決の捕捉は別の話で
ある（動的解決の捕捉自体は L01）。

- 記録する単位は「対象 exe のインポートテーブルに現れた (DLL, 関数)」
  で、DLL ごとにまとめて `CaptureEnvironment.static_dependencies`
  （`StaticDependency` の列）に載せる。`shirusu inspect`（人間可読・
  JSON）が表示する（無い Trace では出さない）。
- 収集するのは `shirusu capture` の起動対象 exe の直接のインポート
  （通常のインポートディレクトリ）のみ。解析は `shirusu-hook` の
  `pe::parse_imports` を使い、境界検査つきで不正な入力には空を返す。
  読めない（PE でない・壊れている）場合は空のままにし、capture 自体は
  失敗させない。静的依存は診断情報であり、記録の成否を左右しない。
- 遅延ロード・インポート（delay-load）は含まない。遅延ロードは実行時
  に初めて解決される別経路で、ディスクリプタ形式が異なるため別途の
  解析が要る。
- IAT スロットの RVA は記録しない。IAT 配置はイメージ固有の詳細で
  あり、依存そのもの（どの DLL のどの関数か）ではない。フック計画には
  `shirusu_hook::pe::ImportSite` が既に持っている。
- `attach` では対象 exe のパスを解決しないため空のまま。子プロセスの
  Trace も同じ理由で空のまま。対象 exe の特定まで含むモジュール列挙は
  L23 の範囲。

## 記録モード（L09）

overview「記録モードと性能目標」節に対応する。記録モードは
`CaptureSessionConfig::record_mode`（`RecordMode`）で選び、CLI は
`shirusu capture --mode <full|profile|filtered> [--api <name> ...]`
で指定する（attach も同じ）。モードは `CaptureEnvironment.capture_config`
に `mode=full` / `mode=profile` / `mode=filtered apis=...` として明記する
（`full` でも明記し、後から Trace を見たときに間引き無しで記録された
ことが分かるようにする）。`shirusu inspect`（人間可読・JSON）が
`profile` の集計を表示する。

- `full`（既定）：対象境界の呼び出しを意図的に間引かず全て保存する。
  間引きはしないが、負荷による欠落を防ぐ保証までは無い。欠落が起きたら
  Loss Record と Finalization の三指標（H03）に残り、Trace は
  `incomplete` として扱う（`shirusu inspect` の終了ステータスも H14
  どおり 1 になる）。「間引かない」と「欠落したら incomplete」はこの
  連動で保つ。
- `profile`：個別イベントは保存せず、API ごとに呼び出し回数・分布・
  所要時間を集計して ProfileSummary Block（種別 11）として `finish`
  が Index の前に 1 回だけ書く。enter / leave の対応付けは
  (thread, call_id) で行い、Batch をまたいでも対になる（DrainWorker
  の `track_call` と同じ鍵）。対応の無い enter / leave は `calls` に
  数えず `enters` / `leaves` だけに数える。CallEnter / CallLeave 以外の
  種別（Snapshot 等）は集計の対象外だが `total_events_seen` には数える。
  所要時間は leave の QPC 時刻から enter の QPC 時刻を引いたもの
  （時計の逆行には `saturating_sub` で 0 に丸める）。このモードでは
  Event Chunk が書かれないため Finalization の `total_events` は 0 になり、
  回収したイベント数は集計の `total_events_seen` で分かる。Loss Record
  は API によらず残る。`shirusu capture` の終了時の要約にも集計を出す。
- `filtered`：指定した API 群のイベントだけを保存する。指定は CLI の
  `--api <name>`（繰り返し可。素の関数名 `CreateFileW` と
  `module!関数` 形式 `kernel32!ReadFile` の両方を受け付け、関数名は
  ケース敏感。未知の名前は使い方エラー）。Host 側で `record_batch` の
  前に落とす（Blob 化の前に落とすため、不要な Blob は書かれない）。
  落とした後空になった Batch は書かない。sequence の欠番は許容される
  （Writer の不変条件は退行の拒否だけで、欠番は Loss としても扱われない。
  欠落したイベントの Loss Record は別途残る）。Schema と Loss Record
  は API によらず残る。`--api` は `--mode filtered` のときだけ意味があり、
  それ以外での指定は使い方エラー。`filtered` に `--api` が無いのも
  使い方エラー（空の集合は何も記録しない罠になるため）。
- Agent 側での間引きはしない。`filtered` / `profile` でも Agent は
  全イベントを Ring へ書き、Host 側で落とす・集計する。Agent 側の間引きは
  Ring の圧迫を減らす将来の最適化であり、現行の対象外とする。

## 例外の透過と CallAborted（L08）

overview「Hookの透明性」節の要求：元の API が投げた例外はそのまま伝え、
中断した呼び出しを `CallAborted` として記録する。

- イベント種別：転送 `EventKind::CallAborted = 7`。CallLeave の代わりに
  記録する。戻り値が無いため引数値列は無く、`args` は None。
  `schema_id` には leave Schema の ID を入れる（どの API の leave に
  なるはずだったかが読めるようにする）。
- 機構：Detour は enter の記録と呼出スタックへの push の直後に
  `CallGuard`（RAII）を立て、元の呼び出しが正常に戻ったら
  `complete()` で武装解除する。元の呼び出しが例外（C++ 例外 / SEH /
  Rust パニック）で戻らなかった場合、巻き戻しでガードの Drop が走り、
  呼出スタックから外して `CallAborted` を記録する。例外自体は一切
  捕捉しないため、呼び出し側へ伝わる例外は Detour が無い場合と同一である。
- Windows では Rust のフレームも SEH アンワインド情報を持つため、外来の
  例外が Detour フレームを巻き戻すときにこの Drop は走る。仮に走らな
  かった場合の失敗モードは「中断の記録漏れ」だけで、例外の伝播や対象
  プロセスの挙動は変わらない（その場合は Host が「終了不明」として
  UnknownTermination で扱う）。
- Drop 中の記録は `catch_unwind` で包み、結果を捨てる。巻き戻し中の
  Drop でパニックするとプロセスが abort するため、記録の失敗が例外の
  伝播を壊すことはない。
- Host：`track_call` は CallAborted で開いた呼び出しを閉じ、
  `finalize_thread` での UnknownTermination にしない。`profile` モード
  の集計では対応付け待ちから外すだけにし、`calls` / `leaves` には数えない
  （所要時間が無いため）。
- 表示・検査：`Phase::Aborted`（表示名 `aborted`）。conformance の
  enter-leave-pairing は Aborted も Leave と同じく対応づけとみなす。
  compare は `NormCall.aborted` として保持し、中断と正常終了の違いは
  CallShapeDifference になる。ただしオブジェクト生成 API では中断で
  生成物が無いため整列で対にならず、MissingCall と ObjectStateDifference
  として出る。

## 非同期 I/O の完了時取得（F27）

overview「型付きの値」節の要求：非同期 I/O は完了時（completion）に
取得する。`CaptureTiming::Completion` は F19 で宣言だけが Schema に
載り、完了を捕捉する仕組みが無かった。ここで機構を定める。

- イベント種別：転送 `EventKind::CallCompleted = 8`。OVERLAPPED 指定
  の呼び出しの leave は未完了のためバイト数とバッファ内容が
  Unsupported のままだが、完了を観測した時点で、元の呼び出しの leave
  Schema の値列を改めて記録する。`schema_id` には元の API の leave
  Schema の ID を入れる（`args` は leave と同じ形で復号できる）。
  `call_id` は元の呼び出しと同じ。
- 完了の観測：フック対象に `GetOverlappedResult` /
  `GetQueuedCompletionStatus` を追加した（API 表の 5・6 番目。enter /
  leave Schema は通常の API と同じ規約）。この 2 API 自体も通常の
  呼び出しとして enter / leave を記録する。
- 保留中の操作：ReadFile / WriteFile の Detour は、OVERLAPPED 指定で
  `ERROR_IO_PENDING` (997) を返したときに、OVERLAPPED 構造体の
  アドレスを鍵として `PendingOverlapped`（API・call_id・バッファ・
  要求長・方向）を登録表へ登録する。完了は別スレッドで観測される
  ことがある（IOCP）ため、登録表はセッション全体で共有する。同じ
  構造体で完了前に再登録された場合は古い方を上書きする（Win32 は
  完了前の構造体再利用を禁じているため、古い操作の完了は以後対応付け
  できない）。
- 完了時の値：`GetOverlappedResult` が成功したら、転送バイト数を
  lpNumberOfBytesTransferred から（NULL なら OVERLAPPED.InternalHigh
  から）読み、バッファ内容を完了時点で取る。FALSE でも
  `ERROR_IO_INCOMPLETE` (996) 以外なら操作自体がエラーで終わった
  完了として記録する（バイト数は Unsupported、データは空）。未完了
  (996) の場合は何もしない。`GetQueuedCompletionStatus` も同じで、
  戻り値が FALSE でも取り出した OVERLAPPED が非 NULL なら完了した
  I/O の失敗として記録し、NULL（タイムアウト等）なら何もしない。
  転送バイト数がどこからも読めなければ完了は記録しない（保留エントリ
  は取り出して破棄する）。
- 同期完了：OVERLAPPED 指定でも元の呼び出しが同期完了した場合
  （戻り値が非 0）は、leave 時点で既に完了しているため、転送バイト数
  （lpNumberOfBytesRead / lpNumberOfBytesWritten、NULL なら
  OVERLAPPED.InternalHigh）とバッファ内容を leave イベント自体に
  取る。完了イベントは記録しない。読めなければ従来どおり Unsupported。
- Host：`track_call` は CallCompleted で開いた呼び出しを閉じるのは
  leave が欠落していた場合だけで、通常は数を数えるだけ（leave が既に
  閉じている）。対応する Enter が無い完了は無視する。`profile` モード
  の集計では何もしない（所要時間は leave 時点で計測済み）。
- 表示・検査：`Phase::Completed`（表示名 `completed`）。conformance
  の enter-leave-pairing は、同じスレッドでまだ開いている Enter が
  あれば完了で閉じる。leave が既に閉じている通常の場合は何もしない。
  compare は `NormCall.completed` として保持し、比較では completed
  があればそれを実効 leave として使う。非同期の呼び出しと同期の
  呼び出しは、完了の値が同じなら一致する。完了が観測されなかった
  呼び出しは leave の Unsupported 値列のままなので同期側と差分になる。
- 対象外：`WaitForSingleObject` で OVERLAPPED の hEvent を待つ経路、
  `GetOverlappedResultEx`、アラート可能待機（APC 経由の完了ルーチン）
  は完了の観測点として扱わない。これらの経路で完了した操作は
  leave の Unsupported のまま残る（将来の拡張）。

## 永続化と復旧保証（F21）

overview「完全性と復旧」節の「Host や OS がクラッシュしたら、最後に
永続化されたチャンクまで復旧する（flush と fsync の設定で保証範囲が
決まる）」に対応する。Writer の永続化設定は `Durability`（既定は
`Buffered`）で、`CaptureSessionConfig::durability` から指定する。
`finish` せずに終わったファイルは、ここでの保証範囲まで書かれた
内容を回復意味論どおりに読む（Finalization が無い Trace）。

| 設定 | Writer の動作 | 復旧保証範囲 |
| --- | --- | --- |
| `Buffered`（既定） | `flush` のみ。`sync_all` は呼ばない | プロセスのクラッシュには強い（OS へ渡した分は残る）。Host や OS のクラッシュでは、OS のページキャッシュに残った分は失われ得る |
| `SyncOnFinish` | `finish` の成功時に `sync_all` を 1 回 | 正常終了した Trace は OS クラッシュにも耐える。書き込み途中のクラッシュでは `Buffered` と同じ範囲 |
| `SyncPerBlock` | 各 Block の書き込み後に `sync_all`。`finish` の最終 flush 分も 1 回 sync する | `write_batch` 等が返った時点で、その Block までが OS クラッシュにも耐える。`sync_all` の回数が増える分、書き込みは遅くなる |

注意点:

- `sync_all` は `File::sync_all`（fsync 相当）への委譲であり、書き先が
  `Vec<u8>` 等のメモリ上の場合は何もしない（`DurableWrite` トレイト）。
- 「最後に永続化されたチャンクまで」の「チャンク」は Block 単位で数える。
  `SyncPerBlock` でも、書き込み途中で OS がクラッシュした場合に
  最後の Block が半分だけ書かれていることはあり得る。その場合は回復
  意味論の「末尾切断」として扱われ、そこまでの内容が返る。
- `Buffered` が既定なのは、記録中の性能を優先する従来の挙動を保つため。
  長時間の記録で OS クラッシュ時の損失を抑えたい場合は
  `SyncPerBlock`、正常終了だけ確実に残したい場合は `SyncOnFinish` を選ぶ。

## Host 変換（A72 の適用）

- Host は回収イベントごとに、検証済み Descriptor と Ring 識別情報から
  `TemporaryPayloadKey` を生成する（転送側の既存実装）。公開 Trace への
  変換では、キーに対応する Payload 本体を Blob 化し、Trace のイベント
  には **Blob ID だけ**を残す。キー自体は公開形式のどこにも書かない
  （型としても、公開 Trace のモデルに一時キーは存在しない）。
- 欠落した Payload（`payload_dropped`）にはキーを生成せず、Trace には
  `Dropped { original_len, reason }` として欠落理由だけを残す。
- Loss 情報（Sequence 欠番、カウンタ差分、終了不明、完全性喪失）は
  Loss Block の LossRecord として残し、Finalization には Host の
  IntegrityReport に対応する3指標を写す。

## 依存クレートの判断

2026-11-09 にこの VM で実測した結果に基づく（判断の詳細は F10）。

| 対象 | 採用 | 判断 |
| --- | --- | --- |
| BLAKE3 | `blake3` クレート（1.8.7、`pure` フィーチャ） | Linux host でビルド可。ただし既定のままでは Windows ターゲット `cargo check` でビルドスクリプトが `ml64.exe`（MSVC アセンブラ）を要求し、この VM からも CI の ubuntu ジョブ（windows-check-targets）からも失敗する（当初「cc を要する経路が既定で無効」と記録したが、実測で誤りと判明し訂正）。`pure` フィーチャで純 Rust 実装に固定すれば両ターゲットとも通過する。ハッシュ値の仕様は同一であり形式に影響しない。性能差は Blob 化用途では許容範囲 |
| Zstd | `ruzstd`（0.8.3、純 Rust） | 採用。理由は次項 |
| Zstd（`zstd` / `zstd-sys`） | 不採用（現時点） | Linux host ではビルドできるが、Windows ターゲット向けの `cargo check` で cc-rs が `lib.exe`（MSVC ライブラリアン）を要求し、この VM からも CI の ubuntu ジョブ（windows-check-targets）からも失敗する。最終ゲートを壊すため不採用。Windows ネイティブのビルド環境では動く見込みであり、将来 `zstd-sys` への差し替え自体は形式に影響しない（フレーム形式は標準） |
| ruzstd の符号化レベル | `Fastest` / `Uncompressed` のみ | `Default` 以下の指定は現行版で `unimplemented!()` になることを実測。`Fastest` は実 LZ 圧縮として動作（反復 100KiB → 14 バイトで往復確認）。復号は標準フレーム全般を受ける |
| Protobuf | 手書きワイヤ形式 | prost は protoc の事前導入（prost-build）か、protoc バイナリ同梱クレートへの依存が要り、CI の全ジョブ（特に ubuntu 上の Windows ターゲット check）で確実に通すには部品が多い。メタデータは本プロジェクトが所有する小さいスキーマであり、ワイヤ形式自体は標準なので、手書きでも他言語の Protobuf 実装から読める。生成コードとの相互運用が必要になったら .proto を正として再生成する |
| CRC32C | `shirusu-transport` の既存実装を再利用 | 転送側で検証済みの実装があり、二重実装を避ける。Trace 形式の正は本書とテストベクターであり、実装の置き場所は問わない |

## ABI 適合性テスト（L06）

overview「Hookの透明性」節：浮動小数点引数、構造体の戻り値、
コールバック、例外、`LastError` を扱う Probe を Hook ありとなしで
実行して結果を比べる。実行は `shirusu-capture-e2e --abi`
（windows-x64 CI ジョブで実行）。

- Probe 対象（`shirusu-hook-target --abi-probe`、各 Probe は
  `ABI_PROBE <name> <value>` を 1 行出す）：
  - `float`：8 個の f64 引数（x64 では先頭 4 個が XMM0-3、残りは
    スタック渡し）と f32 1 個を、フックされた呼び出しの前後で生かし、
    合計・積のビット列を出す。呼び出し規約・浮動小数点レジスタ・
    スタックの整合性が壊れれば、Hook ありとなしでビット列が変わる。
  - `struct-return`：24 B の構造体（`tag: u64`、`ratio: f64`、
    `lo: u32`、`hi: u32`）を値で返す関数の中でフックされた呼び出しを
    行い、返った構造体の各欄のビット列を出す。24 B は x64/x86 とも
    隠しポインタ経由で返る。
  - `callback`：関数ポインタ経由のコールバック中と、`CreateThread`
    のスレッドプロシージャ（Windows からアプリへ入るコールバック）中で
    フックされた API を呼び、書いたバイト数とファイル内容の往復を出す。
    スレッド版は別スレッドでの Detour と入れ子記録も見る。
  - `exception`：フックされた呼び出しの後に Rust のパニックを起こし、
    `catch_unwind` で受けたペイロードと、巻き戻し後にフックが壊れて
    いないこと（後続のファイル操作が正常なこと）を出す。
  - `lasterror-success`：`SetLastError(0x1234)` の後に成功する
    `CreateFileW` を呼び、呼び出し後の `GetLastError()` が `0x1234`
    のままであることを出す（G06 の端到達確認）。
  - `lasterror-failure`：存在しないファイルを `OPEN_EXISTING` で開き、
    失敗のエラーコードが `ERROR_FILE_NOT_FOUND`（2）であることを出す。
- 比較（`shirusu_e2e::compare_abi_probe_outputs`）：`ABI_PROBE` 行だけ
  を対象にし、名前・順序・値を位置ごとに比べる。Probe 行以外の stdout
  は無視する。`ABI_PROBE_DONE ok` 行の有無も比べる：対象が最後まで
  走り切っていない（異常終了・クラッシュ）場合に DONE 行が欠けるため、
  `LaunchedCapture` が対象の終了コードを返さない代わりの成功シグナル
  として使う。
- Trace の確認：Hook あり実行の Trace に Probe のファイル I/O が記録
  されること（25 呼び出し → 50 イベント、下限 20）、コールバックの
  別スレッド分を含めて 2 スレッド以上が現れること、4 API
  （CreateFileW / ReadFile / WriteFile / CloseHandle）の enter が
  すべてあること。
- 境界：SEH 例外が Detour の実行中に起きる経路（L08 の CallAborted の
  実動）は、現行 4 API の呼び出しでは SEH を起こす引数が作れない
  （不正なバッファはカーネルがエラーで返す）ため、ここでは扱わない。
  例外 Probe は Rust のパニックの伝播と巻き戻し後の健全性を対象とする。
  可変長引数 API は現行フック対象に無く、対象外。WoW64（i686）での
  `--abi` 実行は未配線（Probe コード自体は i686 ターゲットでコンパイル
  される。WoW64 での capture-e2e 実行は B07 / C17 / D35 の範囲）。

## COM Interception（L02）

overview「COM」節・フック実装順序 3・初期マイルストーン段階 6。
既知の Factory 関数が返したインターフェイスを起点に追跡し、その
vtable のメソッド呼び出しを記録する。

- 方式は「オブジェクト単位の vtable 複製」：追跡対象のオブジェクト
  ごとに vtable を複製し、複製のスロットを Detour へ向け、オブジェクト
  の vtable ポインタだけを複製へ向ける。共有 vtable そのものは書き換え
  ないため、同じ実装を共有する別のオブジェクトには及ばない。Proxy を
  使わないため、アプリへ返すポインタの同一性は壊れない（オブジェクトの
  ポインタ値そのものは変えない）。複製 vtable とその登録は解放しない
  （Release で寿命が終わった後も、他スレッドが呼び出し中かもしれない
  ため。プロセス終了時に OS が回収する）。そのためセッション終了後に
  アプリが COM メソッドを呼んでも、Detour は登録から元のメソッドを引いて
  素通しで呼べる（記録はしない）。
- 既知インターフェイスは IUnknown / IShellLinkW / IPersistFile の 3 つ
  （L17 の検証用 COM アプリが使うもの）。それ以外の IID は追跡対象として
  記録するが、メソッドの Detour は設置しない（型不明のカスタム
  インターフェイスは未対応として明記する）。
- 既知の Factory 関数は `CoCreateInstance` / `CoGetClassObject`
  （ole32。Inline Hook で設置）と `Direct3DCreate9`（d3d9。返す
  IDirect3D9 のメソッド表が未定義のため、この版ではフックしない）。
- 同一性は、対象アプリが実際に実行した `QueryInterface` の結果だけで
  判定する。shirusu は標準では `QueryInterface` を追加で呼ばない。
  `QueryInterface(IID_IUnknown)` の成功は同一性の確定（返す IUnknown
  ポインタを正規キーにし、そこから派生した別面も付け替える）。それ以外
  の IID への QI の成功は、呼び出し元の同一性を未確認のまま引き継ぐ。
  同一性を確定できないインターフェイスは別々に保持し、関係を未確認とする。
- `AddRef` / `Release` で寿命を追う。Release が 0 を返したら寿命終了と
  して印を付ける（記録は残し、相関に使う）。
- 診断用オプション `--diagnostic-query-interface`（既定は無効）が有効な
  場合に限り、Interceptor は新規発見のインターフェイスに対して自身で
  `QueryInterface(IID_IUnknown)` を呼んで同一性を確認する（参照カウント
  を一時的に増やすため、実行に影響し得る。呼び出しは元の QI を直接呼び、
  アプリの呼び出しとしては記録しない。成功したら Release で参照カウント
  を戻す）。
- アタッチ前に既に存在していたオブジェクトは発見できない（Factory /
  QueryInterface / メソッド戻りを観測して初めて追跡対象になる）。途中
  から発見したポインタは来歴不明として扱う。
- COM メソッドの記録は L1（引数は生のスロット値列。型付きの取得は将来
  の拡張）。メソッドの呼び出し元が Runtime の場合は L23 と同じく記録
  しない（呼び出し元が特定できない場合は記録する）。

### COM メソッドイベントの Schema

COM メソッド呼び出しは API 表とは別の予約 ID で記録する
（api_id = 1000、enter Schema = 10001、leave Schema = 10002）。
Host はセッション開始時にこの 2 Schema を登録する（未登録だと
Payload が Blob へ逃げる）。

- enter `com!method/enter`：`object` (U64, Pointer。`this`。Factory
  呼び出しでは 0)、`iid` (Bytes。16 バイトの IID。Factory では要求された
  IID。読めなければ空)、`method_index` (U32。vtable インデックス。
  Factory 呼び出しでは u32::MAX)、`method_name` (Str。
  `IShellLinkW::SetPath` / `CoCreateInstance` のような表示名)、
  `args` (Bytes。`this` を除く引数の生スロット値列。上限 4 スロット。
  ポインタの中身は読まない)、`target_iid` (Bytes。もう一方の GUID がある
  場合に 16 バイト。`QueryInterface` では要求された IID、Factory 呼び出し
  では CLSID、それ以外は空)。
- leave `com!method/leave`：`hresult` (I32。AddRef / Release では返された
  参照カウントを I32 へ写したもの)、`returned_object` (U64,
  CreatedObject。Factory 呼び出しの成功時と `QueryInterface` の成功時に
  有効で、それ以外は 0)、`refcount` (U32。AddRef / Release が返した参照
  カウント。それ以外は 0＝対象外)。
- COM の leave は GetLastError の意味条件を持たない（F20 の対象は
  Win32 API のみ）。HRESULT が誤りの経路である。ただし Detour は
  LastError の保存・復元（P1-5）も行い、透明性を保つ。
- 比較（shirusu-compare）の正規化は未対応：COM イベントの `object` /
  `args` / `returned_object` には実行ごとの生ポインタ値が載るため、別
  実行の Trace との比較では差分が出る。COM イベントの正規化（同一性の
  解決を含む）は将来の拡張。

### 検証（L02）

- `shirusu-capture-e2e --verify-apps` の com アプリで、CoCreateInstance
  の Factory イベント、IShellLinkW::SetPath / GetPath、QueryInterface、
  Release（2 件以上）、enter/leave の対応、QueryInterface が返す別ポインタ
  とその Release が返されたポインタで記録されること（同一性・寿命の実動）

## WinRT（L14）

overview「観測レベル」節・Trace 形式の API Schema 層。WinRT API は COM
を基盤とする（全インターフェイスは `IInspectable` から派生）ため、COM
と同じ「オブジェクト単位の vtable 複製」で追跡する。WinRT 固有の部分は
定義表とアクティベーション関数の検出である。

- 既知インターフェイスは `IInspectable` / `IActivationFactory` /
  `IUriRuntimeClass` / `IUriRuntimeClassFactory` / `IJsonObject` /
  `IStringable` の 6 つ（L17 の検証用 WinRT アプリが使うもの）。
  IID と vtable のメソッド順は `windows` クレート 0.61.3 / 0.62
  （Windows.winmd からの生成物）の Vtbl 構造体と照合して確認した。
  それ以外の IID は追跡対象として記録するが、メソッドの Detour は
  設置しない（型不明のカスタムインターフェイスは未対応として明記する）。
- 既知のランタイムクラスは `Windows.Foundation.Uri`
  （既定インターフェイス `IUriRuntimeClass`）と
  `Windows.Data.Json.JsonObject`（既定インターフェイス `IJsonObject`）の
  2 つ。表に無いクラスは `IInspectable` として追跡する
  （GetIids / GetRuntimeClassName / GetTrustLevel のみ記録される）。
  クラス名自体はアクティベーションイベントに残るため、後から表へ追加できる。
- 検出の起点はアクティベーション関数 `RoActivateInstance` /
  `RoGetActivationFactory`（combase.dll。Inline Hook で設置）。
  `RoActivateInstance` が返すのはクラスの既定インターフェイス、
  `RoGetActivationFactory` が返すのは `IActivationFactory` そのもの。
  HSTRING のクラス名は `WindowsGetStringRawBuffer` で読む（読めなければ
  空のまま記録する）。
- メソッドが返すインターフェイスの追跡は、表に載せた返却メソッドに限る
  （`IActivationFactory::ActivateInstance` /
  `IUriRuntimeClassFactory::CreateUri` /
  `IUriRuntimeClassFactory::CreateWithRelativeUri` /
  `IUriRuntimeClass::CombineUri`）。それ以外のメソッドが返す
  インターフェイスは、アプリが `QueryInterface` で取り直さない限り
  追跡対象にならない。
- 定義表は手書きの厳選表である。WinRT の定義は Windows.winmd にあるが、
  これは Windows SDK にしか同梱されず、NuGet パッケージとしては配布
  されていない（2026-11-12 に確認：`Microsoft.Windows.SDK.WinRTMetadata`
  は NuGet に存在せず、Microsoft.Windows.CppWinRT の nupkg にも .winmd
  は含まれない）。そのため L03 のような WinMD からの生成はできず、
  Windows.winmd を入手できる環境での生成への置き換えは将来の拡張。
- アタッチ前に既に存在していた WinRT オブジェクトは発見できない
  （L02 と同じ）。

### WinRT アクティベーションイベントの Schema

WinRT アクティベーション呼び出しは COM メソッドイベントとは別の予約 ID
で記録する（api_id = 1001、enter Schema = 10011、leave Schema = 10012）。
Host はセッション開始時にこの 2 Schema を登録する（未登録だと Payload
が Blob へ逃げる）。

- enter `winrt!activation/enter`：`object` (U64, Pointer。常に 0)、
  `class_name` (Str。HSTRING から読んだランタイムクラス名。読めなければ空)、
  `method_name` (Str。`RoActivateInstance` / `RoGetActivationFactory`)、
  `args` (Bytes。HSTRING ポインタと out ポインタの生スロット値列。
  上限 4 スロット。ポインタの中身は読まない)。
- leave `winrt!activation/leave`：`hresult` (I32。アクティベーション関数の
  HRESULT)、`returned_object` (U64, CreatedObject。成功時に返された
  インターフェイスのポインタ。それ以外は 0)、`refcount` (U32。常に 0＝対象外)。
- WinRT の leave も GetLastError の意味条件を持たない（F20 の対象は
  Win32 API のみ）。HRESULT が誤りの経路である。ただし Detour は
  LastError の保存・復元（P1-5）も行い、透明性を保つ。
- 比較（shirusu-compare）の正規化は未対応：COM イベントと同じく、
  WinRT イベントの `object` / `args` / `returned_object` には実行ごとの
  生ポインタ値が載るため、別実行の Trace との比較では差分が出る。
  WinRT イベントの正規化（同一性の解決を含む）は将来の拡張。

### 検証（L14）

- `shirusu-capture-e2e --verify-apps` の winrt アプリで、RoActivateInstance
  のアクティベーションイベント、RoGetActivationFactory（2 件以上）、
  クラス名（`Windows.Foundation.Uri` / `Windows.Data.Json.JsonObject`）、
  enter/leave の対応、IInspectable::GetRuntimeClassName（2 件以上）、
  IActivationFactory::ActivateInstance / QueryInterface、
  IUriRuntimeClassFactory::CreateUri、IUriRuntimeClass::AbsoluteUri、
  Release（2 件以上）、COM enter（10 件以上）と enter/leave の対応
  を確認する。Factory 関数の設置数は SessionSummary の
  `com_factory_count`（0〜2）で確認する。
- 方式ごとの副作用の検証：共有 vtable を書き換えないことは設計で保証する
  （設置はオブジェクトの vtable ポインタの書き換えだけで、共有 vtable
  への書き込みは行わない。`build_cloned_vtable` の単体テストは、置き換え
  るのが指定スロットだけであることを確認する）。アプリへ返すポインタの
  同一性が保たれること（Factory / QueryInterface が返すポインタ値が
  Detour 無しの場合と同じ挙動になること）は、verify-com アプリの Hook
  ありとなしの出力比較（`--verify-out` の VERIFY 行）と、Trace 上の
  ポインタ値の突き合わせ（QI の返す別ポインタと、そのポインタでの
  Release）で確認する。共有 vtable 書き換え方式と Proxy 方式は採用して
  いないため、その副作用の実測は対象外とする。同じ実装の別オブジェクト
  を並べて vtable ポインタの不変を直接確認する E2E は、まだ無い（将来の
  拡張。verify-com アプリは ShellLink を 1 個しか作らない）。

## コールバック（L16）

overview「記録境界とモジュール分類」節：Windows からアプリへ入る
コールバック（WndProc など）を、API 呼び出しとは別種のイベントとして
記録する。コールバック中の API 呼び出しの入れ子記録自体は A43 / C18
の範囲（呼出スタックによる親子関係）であり、ここはコールバック自体の
別種イベント化が対象。

- 検出は WndProc のラップで行う。`RegisterClassExW/A`（user32.dll）で
  登録されるクラスプロシージャと、`SetWindowLongPtrW/A (GWLP_WNDPROC)`
  で差し替えられるプロシージャを Inline Hook で捕捉し、shirusu の
  ラッパーへすり替える（4 関数。`CallbackHookDef` 表）。
  `RegisterClassEx` にはアプリが渡した構造体のコピーを渡す（アプリの
  構造体自体は書き換えない）。コピー内の `lpfnWndProc`（オフセット 8）
  だけをラッパーへすり替える。`SetWindowLongPtr` は以前のプロシージャを
  返すが、以前の値が shirusu のラッパーだった場合は元のプロシージャへ
  解決して返す（アプリはラッパーの存在を観測しない）。
- ラッパーはスロット表（`CallbackProcTable`、最大 32 件）で元の
  プロシージャと 1 対 1 に対応づける。ラッパー関数自体はスロット番号を
  固定で持ち、ディスパッチ時の引数だけでは判別できない「どの元の
  プロシージャを呼ぶか」がスロット番号で決まる。同じ元のプロシージャは
  同じスロットを再利用し（重複登録・二重ラップを防ぐ）、スロットが尽きた
  場合はラップせず素通しにする（fail-open。アプリの動作は変わらない）。
- ラッパーはコールバック enter を記録し、呼出スタックへ積んでから元の
  プロシージャを呼ぶ。コールバック中の API 呼び出しは、このイベントを
  親（`parent_call_id`）として入れ子に記録される。元のプロシージャが
  例外で中断したら、ComCallGuard が `CallAborted` を記録する（L08。
  例外は捕捉しない）。元のプロシージャを呼ばずに失敗値を返す経路は
  作らない（WndProc が 0 を返すとウィンドウ作成の失敗など、アプリの
  挙動が変わるため。ランタイムが無い場合も素通しで呼ぶ）。
- コールバックイベントはトップレベル（`parent_call_id == 0`）であり、
  L15 の再実行規則（トップレベルの呼び出しだけを実行する）にそのまま
  従う。
- Bootstrap は v9 になり、`result_callback_hook_count`（0〜4）が増えた。
  Host は読み戻して Coverage へ写す（SessionSummary の
  `callback_hook_count`）。

### コールバックイベントの Schema

コールバックは COM メソッドイベント・WinRT アクティベーションイベントとは
別の予約 ID で記録する（api_id = 1002、enter Schema = 10021、
leave Schema = 10022）。Host はセッション開始時にこの 2 Schema を登録する
（未登録だと Payload が Blob へ逃げる）。

- enter `callback!enter`：`hwnd` (U64, Pointer。メッセージを受け取る
  ウィンドウ)、`kind` (U32。コールバック種別コード。WndProc = 1)、
  `message` (U32。WM_* メッセージ番号)、`wparam` (U64。WndProc の
  wParam の生値)、`lparam` (I64。WndProc の lParam の生値)、`proc`
  (U64, Pointer。元の WndProc のアドレス。ラッパーではない)。
- leave `callback!leave`：`result` (I64。WndProc の戻り値 LRESULT)。
- コールバックの leave も GetLastError の意味条件を持たない（F20 の対象は
  Win32 API のみ）。Detour は LastError の保存・復元（P1-5）も行い、
  透明性を保つ。
- 比較（shirusu-compare）の正規化は未対応：コールバックイベントの
  `hwnd` / `proc` には実行ごとの生ポインタ値が載るため、別実行の Trace
  との比較では差分が出る。コールバックイベントの正規化は将来の拡張。

### 制限（L16）

- 検出は WndProc のみ。DialogProc（`DialogBoxIndirectParam` 等）、
  タイマープロシージャ、列挙コールバックは未対応。`CallbackKind` に
  種別コードを持たせてあるため、形式を変えずに追加できる。
- `RegisterClassW/A`（旧式のクラス登録）と `SetWindowLongW/A` は
  フックしない。`GetWindowLongPtrW/A` もフックしないため、アプリが
  現在のプロシージャを読み戻すとラッパーのアドレスが見える（その値を
  そのまま `SetWindowLongPtr` へ渡した場合は再利用して二重ラップしない）。
- ラップできる WndProc は最大 32 件。超えた分はラップせず、コールバックの
  記録だけが無い（アプリの動作は変わらない）。
- アタッチ前に登録されたクラスは、登録時のラップを観測できないため
  WndProc がラップされない（L02 と同じ）。そのウィンドウへのコールバックは
  記録されない。

### 検証（L16）

- `shirusu-capture-e2e --verify-apps` の gui アプリで、コールバック検出
  フックの設置数（SessionSummary の `callback_hook_count`、1 以上）、
  WM_CREATE（0x0001）・WM_DESTROY（0x0002）のコールバック enter、
  コールバック enter（2 件以上）と enter/leave の対応、コールバック
  イベントがトップレベル（`parent_call_id == 0`）であることを確認する。
  gui アプリはメッセージ専用ウィンドウを作り、WM_CLOSE を送って
  メッセージループを回す（WM_CREATE は CreateWindowExW の中で、
  WM_CLOSE / WM_DESTROY はメッセージループの中で届く）。

## テストベクター

形式の正は本書＋リポジトリのテストである。言語非依存のテストベクター
（最小 Trace のバイト列と期待復号結果）は、Reader の単体テストとして
バイト列を直接埋め込む形で保持する（F 項目のテスト群）。
