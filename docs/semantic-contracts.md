# File I/O の意味契約

`crates/shirusu-metadata-gen/file-io-contracts.toml` は初期4 APIの Trace Schema、
引数・バッファ取得、LastError 判定を一つの宣言にまとめる。WinMD の型から副作用を
推測せず、手書きの意味情報を検証してコードへ生成する。現在の契約形式は version 3。

```sh
cargo run -p shirusu-metadata-gen -- --file-io-contracts
cargo run -p shirusu-metadata-gen -- --file-io-contracts --check
```

WinMD のダウンロードは不要。以下を生成してチェックインする。

- `api_file_io_generated.inc`: Hook と Host が共有する ApiDef / Schema。
- `capture_file_io_generated.inc`: 4 API の enter / leave 取得関数と共通の取得上限。
- `tests/file_io_boundaries_generated.inc`: 上限から生成するメモリ取得テストの境界値。

宣言は API ID、DLL、関数、観測レベル、注記、フィールド順序、型、値の意味、
LastError の有効条件、取得操作と入力引数の対応を持つ。enter は Before、leave は After。
戻り値だけで決まる LastError は生成 ApiDef を参照する。入力にも依存する条件は
同じ契約の `last_error_with_input` から生成し、Schema には `DependsOnInputs` を宣言する。

取得操作は scalar、UTF-16、入力バッファ、出力カウント、出力バッファ、LastError と
その入力条件付き判定に限定。
出力バッファは先行フィールドで取得したカウントを再利用し、カウントのメモリを二度読まない。
成功 BOOL、入口時の容量、非同期指定を宣言から接続する。カウントが容量を超えたら
buffer を読まず Unsupported、非同期 leave では出力カウントと buffer を読まない。

不明なキー・操作・型・意味種別、重複フィールド、不正な引数番号や型、前方カウント参照、
取得タイミングの不整合、識別子と捕捉関数シグネチャの変更を生成前に拒否する。
Rust 式は受け付けない。メモリ参照は既存の MemoryReader と上限付きの読み取り処理を使う。
共通の上限は従来と同じ buffer 4096 bytes / UTF-16 1024 units。
他の手書き Capture もこれらの共通定数を使うため、上限変更時は4 API以外への影響もレビューする。

保存した8 Schemaの Golden は、ID・名称・型・flags・content_hash・注記の
一致を確認する。version 3 では CreateFileW/leave の LastError 条件 flags と
それに対応する content_hash のみを意図的に更新し、フィールド順序・型は維持した。23ケースの取得 Golden は成功・失敗・非標準 BOOL・32/64 bit の
INVALID_HANDLE・Unreadable・NULL・非同期・容量違反の Compact Binary を比較する。
生成境界値 0 / 1 / 上限 / 上限+1 / u32::MAX の組合せでは、実際の MemoryReader が
要求容量と取得上限を超えて呼ばれないことを確認する。CI は生成物の更新漏れを拒否する。

## 残る範囲

HANDLE の解放・寿命モデルと非同期完了の追跡はまだ手書きであり、契約から生成しない。
出力取得は現在の4 APIを対象とし、任意の SAL や構造体へ一般化した生成器ではない。

CreateFileW は失敗時に加え、OPEN_ALWAYS / CREATE_ALWAYS の成功時にも
LastError を Captured として保存する。条件となる作成モード `[2, 4]` は契約で
宣言し、Detour が入口の dwCreationDisposition を leave 取得へ渡す。
その他の成功モードでは従来どおり Stale。入力を受け取れない汎用の取得関数を
DependsOnInputs に使った場合は、生値を Unsupported として残し、意味まで取得できたとは扱わない。古い Trace の Stale 判定を自動で
書き換える機能ではなく、新しい Capture で反映される。CreateFileA の L1 Wrapper
にも同じ条件を判定する手書きルールを適用する。それ以外の入力依存条件は
まだ一般化していない。

名前付き同期オブジェクトの L1 LastError も入力付きの手書き判定を持つ。
CreateMutexW / CreateMutexExW / CreateEventW / CreateEventExW /
CreateSemaphoreW は失敗時のエラーを Captured とする。成功時は lpName が NULL
なら Stale、非 NULL で ERROR_ALREADY_EXISTS なら Captured とする。
その他の名前付き成功や引数不足は、L1 だけで新規作成時の状態を断定せず
Unsupported として生値を残す。名前の文字列やオブジェクト寿命を取得する L2
契約ではなく、4 API の宣言的生成パイロットにも含めない。
Microsoft の [CreateEventW の戻り値仕様](https://learn.microsoft.com/windows/win32/api/synchapi/nf-synchapi-createeventw)
に基づき、同じ名前を再度開く Windows テストで ERROR_ALREADY_EXISTS を確認する。

## 共有 Schema の意味種別（2026-11-13）

外部互換実装と共有する Schema では、各フィールドが意味種別を宣言する。
compare は型ではなくこの宣言で正規化する。

| 意味種別 | 意味 | compare の扱い |
| --- | --- | --- |
| `CreatedObject` | 新しいオブジェクトの生成（生成 API の戻り値など） | 相関の起点。`(生成 API, 序数)` の ObjectKey に置き換える |
| `Handle` | 既存オブジェクトへの参照 | 生成と相関させて ObjectKey へ解決する。解決できなければポインタ級 |
| `Pointer` | メモリアドレス | 値は比較しない。0 は Null、番兵値は Invalid として区別する |
| `Scalar` | 個数・サイズ・時刻・フラグ・真理値など | 値をそのまま比較する（U64 でも消さない） |

- API Catalog（`shirusu-api-catalog`）の全 Schema は全フィールドで宣言済みで、
  テスト `every_catalog_field_declares_its_value_kind` が検査する。
- `shirusu-emit` の `ApiSet::add` は宣言の無いフィールド（Unspecified）を拒否する。
- `shirusu-conformance` の `semantic-kinds-declared` は、宣言の無いフィールドを
  Warn として報告する（旧 Trace の互換のため Fail にはしない）。
- 宣言の無い旧来の Schema に対してだけ、compare は「`return` の U64 は生成、
  U64 はハンドル／ポインタ級」と推定する。64bit のカウンタやサイズを返す API で
  誤判定し得るため、この推定を新しい共有 API セットへ持ち込まない。型を変えて
  意味を伝える旧規約（個数は U32 で記録する）も不要になった。
