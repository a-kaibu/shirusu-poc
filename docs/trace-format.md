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
の決定）。Index と Finalization は末尾に置き、両方とも省略可能である。
Finalization が無いファイルは「途中で終わった可能性がある」ものとして
扱い、完全性を確定できない（Event Integrity = Unknown 相当）。

| 順 | Block | 必須 | 内容 |
| --- | --- | --- | --- |
| 1 | Header | ○ | Magic、Container/Schema バージョン、Session ID、Feature Flags |
| 2 | Environment | ○（Writer は必ず書く） | Capture Environment（Protobuf） |
| 3 | Schema | 必要時 | Schema 定義の集合（Protobuf） |
| 4 | Event Chunk（繰り返し） | － | Event Batch（Batch Header は Protobuf、イベント列は Compact Binary） |
| 5 | Blob Chunk（繰り返し） | － | Blob 本体の集合（生バイト列の連結、後述） |
| 6 | Schema Checkpoint（繰り返し） | － | 途中までに必要になった Schema 定義の複製（Protobuf、Schema と同形式） |
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
- Event Chunk の非圧縮サイズの目安は 256 KiB（overview の 256KiB〜1MiB
  の下限側。決定：Batch の蓄積閾値 `DEFAULT_CHUNK_RAW_TARGET`）。
  Blob Chunk も同じ閾値で分割する。
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
message CaptureEnvironment {
  SessionMetadata session = 1;
  string os_version = 2;
  uint32 os_build = 3;
  string cpu_arch = 4;              // "x86_64" / "x86" / "aarch64"
  uint32 pointer_width = 5;         // 32 / 64
  string capture_config = 6;        // 記録設定の要約（自由形式）
  uint64 feature_flags = 7;
  string target_description = 8;    // 対象プロセスの説明（任意）
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
```

`SessionMetadata` は Header payload の session_id と一致させる。
`content_hash` は、正規化した Schema 定義の BLAKE3 ハッシュ先頭
8 バイト（LE）。正規化バイト列は「名前のバイト列＋区切り 0xFF＋
フィールドごとに（名前のバイト列＋区切り 0x00＋ty の u32 LE＋
flags の u32 LE）」とする（曖昧さのない連結のため区切りを入れる）。
別 Trace 間で同じ定義かを判定するために使う（overview の決定）。
完全な 32 バイトではなく 8 バイトに切り詰めるのは、衝突判定が
「同一ファイル内の重複検出と、Trace 間の目安」用途だからであり、
セキュリティ用途ではない（決定）。

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
3 = Unsupported、4 = LimitExceeded。Unreadable / Unsupported の場合も
本体は符号化する（ダミー 0 / 空）。復号側は余分なバイト列の残りを
不正として拒否する。

### イベント列のレイアウト（Event Chunk 内）

Batch Header 長（LEB128）＋ Batch Header（Protobuf）の後に、Compact
Binary のイベント列が続く。Protobuf メッセージは後続バイト列との境界を
自己判定できないため、長さを先行させる（決定）。

```
event_count は Batch Header 側で宣言する。各イベント:
  seq_delta      LEB128   前イベントの sequence との差（先頭は first_sequence との差）
  ts_delta       zigzag LEB128  前イベントの timestamp_qpc との差（先頭は base_timestamp_qpc との差）
  kind           LEB128   転送 Descriptor の kind と同じ番号（1 = CallEnter 等）
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

## テストベクター

形式の正は本書＋リポジトリのテストである。言語非依存のテストベクター
（最小 Trace のバイト列と期待復号結果）は、Reader の単体テストとして
バイト列を直接埋め込む形で保持する（F 項目のテスト群）。
