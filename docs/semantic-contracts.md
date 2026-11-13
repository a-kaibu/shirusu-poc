# File I/O の意味契約

`crates/shirusu-metadata-gen/file-io-contracts.toml` は初期 4 API の
Trace Schema と LastError 判定を一つの宣言にまとめる。WinMD の型定義から
副作用を推測せず、手書きの意味情報として管理する。

```sh
cargo run -p shirusu-metadata-gen -- --file-io-contracts
cargo run -p shirusu-metadata-gen -- --file-io-contracts --check
```

WinMD のダウンロードは不要。生成物 `api_file_io_generated.inc` はチェックインし、
Hook と Host が同じ ApiDef を使う。Capture 側の LastError 判定もこの定義を参照する。
Linux CI と generator のテストは、宣言と生成物のずれを拒否する。

宣言は API ID、DLL、関数、観測レベル、注記、フィールド順序、型、値の意味、
LastError の有効条件を持つ。enter は Before、leave は After として生成する。
不明なキー・型・意味種別、重複フィールド、識別子の変更、戻り値と判定の不整合は
生成前に拒否する。Rust 式は受け付けない。

移行前の実装から保存した `tests/golden/file-io-schemas.txt` は、8 Schema の
ID・名称・型・flags・content_hash・注記の一致を確認する。
既存 Capture と CLI Golden のテストも継続する。

## この段階の範囲

これは意味契約への移行の最初の段階。メモリ読み取り処理、バッファ長の関連、
HANDLE の生成・解放、非同期完了の追跡、境界値テストの生成はまだ手書きであり、
この宣言だけで生成できるとはしない。次に取得操作とサイズ式を安全な限定語彙で
表し、既存の unreadable / truncated / unsupported と取得順序を保持して移行する。

現在の CreateFileW の LastError 条件も既存の失敗時判定を維持している。
OPEN_ALWAYS / CREATE_ALWAYS の成功時に意味を持つ ERROR_ALREADY_EXISTS など、
入力にも依存する条件をこの v1 が完全に表現できるわけではない。
