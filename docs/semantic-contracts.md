# File I/O の意味契約

`crates/shirusu-metadata-gen/file-io-contracts.toml` は初期4 APIの Trace Schema、
引数・バッファ取得、LastError 判定を一つの宣言にまとめる。WinMD の型から副作用を
推測せず、手書きの意味情報を検証してコードへ生成する。現在の契約形式は version 2。

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
Capture 側の LastError 判定も生成 ApiDef を参照し、Schema と別の条件を書かない。

取得操作は scalar、UTF-16、入力バッファ、出力カウント、出力バッファ、LastError に限定。
出力バッファは先行フィールドで取得したカウントを再利用し、カウントのメモリを二度読まない。
成功 BOOL、入口時の容量、非同期指定を宣言から接続する。カウントが容量を超えたら
buffer を読まず Unsupported、非同期 leave では出力カウントと buffer を読まない。

不明なキー・操作・型・意味種別、重複フィールド、不正な引数番号や型、前方カウント参照、
取得タイミングの不整合、識別子と捕捉関数シグネチャの変更を生成前に拒否する。
Rust 式は受け付けない。メモリ参照は既存の MemoryReader と上限付きの読み取り処理を使う。
共通の上限は従来と同じ buffer 4096 bytes / UTF-16 1024 units。
他の手書き Capture もこれらの共通定数を使うため、上限変更時は4 API以外への影響もレビューする。

移行前から保存した8 Schemaの Golden は、ID・名称・型・flags・content_hash・注記の
一致を確認する。23ケースの取得 Golden は成功・失敗・非標準 BOOL・32/64 bit の
INVALID_HANDLE・Unreadable・NULL・非同期・容量違反の Compact Binary を比較する。
生成境界値 0 / 1 / 上限 / 上限+1 / u32::MAX の組合せでは、実際の MemoryReader が
要求容量と取得上限を超えて呼ばれないことを確認する。CI は生成物の更新漏れを拒否する。

## 残る範囲

HANDLE の解放・寿命モデルと非同期完了の追跡はまだ手書きであり、契約から生成しない。
出力取得は現在の4 APIを対象とし、任意の SAL や構造体へ一般化した生成器ではない。

CreateFileW の LastError 条件も既存の失敗時判定を維持している。
OPEN_ALWAYS / CREATE_ALWAYS の成功時に意味を持つ ERROR_ALREADY_EXISTS など、
入力にも依存する条件を現行契約が完全に表現できるわけではない。
