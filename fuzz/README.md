# fuzz

`shirusu-transport` の Host 検証まわりと、`shirusu-trace` の公開 Trace
復号に対する cargo-fuzz ターゲット群。

| ターゲット | 入力 | 検証 |
| --- | --- | --- |
| `validate_control` | Cursor・容量・Generation のバイト列 | 占有量判定のオーバーフローや誤判定がない |
| `decode_descriptor` | 64バイトの Descriptor | 未知の Kind や異常な長さを安全に扱う |
| `decode_payload` | Descriptor と Payload | 参照範囲と折り返しを正しく検証する |
| `decode_compact` | SchemaSet (Protobuf) と値列 | Compact Binary 復号が panic せず、成功時は再符号化と冪等 |
| `recover_trace` | Trace ファイル全体のバイト列 | 回復読みが panic せず、受理時は sequence 単調性などの不変条件を満たす |

## 種（コーパス）の保持方法

正の種は **`seeds/<target>/<name>.hex`**（16進テキスト、64桁折り返し）で保持する。
`corpus/` は生成物であり、git には入れない（`.gitignore` 済み）。

理由：このリポジトリの配布経路（GitHub API 経由のスナップショット push）が
UTF-8 テキストしか扱えず、バイナリ種をそのまま置くと push 全体が拒否されたため（2026-11-09 に実測）。
種の内容自体はバイナリのままが本質なので、テキスト化は保持形式だけの都合であり、
生成時に完全復元できることを往復ハッシュで確認している。

使い方：

```sh
# 種から corpus/ を生成してから fuzz を回す（CI の scripts/ci/fuzz-short.sh は自動で行う）
fuzz/materialize-corpus.sh
cd fuzz && cargo +nightly fuzz run decode_descriptor -- -max_total_time=60

# 新しい種が出たら、corpus/ に置いてから hex へ書き戻してコミットする
fuzz/encode-seeds.sh
```

`decode_compact` と `recover_trace` は Phase 2（Trace 永続化）で対象に
入った（docs/traceability.md の F 項目を参照）。test.md が挙げる 5 本の
fuzz ターゲット（validate_control / decode_descriptor / decode_payload /
decode_compact / recover_trace）はこれで全て揃った。
