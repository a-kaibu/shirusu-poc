# Parquet による Trace の検索

Windows・Linux・macOS の CLI で公開 Trace を変換する。

```sh
shirusu export capture.trace --format parquet --output events.parquet
```

`--output` は必須。変換は同じディレクトリの一時ファイルで完了してから出力先へ
反映する。入力 Trace 自身への出力は拒否する。元の Trace と Blob は保持すること。
Parquet は解析用の派生形式であり、Trace の完全な代替や再インポート用ではない。

DuckDB の例:

```sql
SELECT api, phase, count(*) AS events
FROM read_parquet('events.parquet')
GROUP BY api, phase ORDER BY events DESC;

SELECT thread_id, sequence, api,
       json_extract(event_json, '$.fields') AS typed_fields
FROM read_parquet('events.parquet')
WHERE phase = 'leave' AND api = 'kernel32!ReadFile';

SELECT value
FROM parquet_kv_metadata('events.parquet')
WHERE decode(key) = 'shirusu.trace_summary';
```

出力 schema の版は key/value metadata の `shirusu.parquet_export_version=1`。
すべての数値列は論理型 UINT64（DuckDB では UBIGINT）であり、符号付き整数の
上限を超える ID も保持する。`global_order` の未割り当ては NULL。

| 列 | 内容 |
| --- | --- |
| event_index | ファイル内イベント順、0 始まり |
| session_id, process_id, raw_pid, thread_id | セッション／論理プロセス／OS PID／スレッド |
| sequence, global_order | スレッド内順序、任意の全体観測順序 |
| timestamp_qpc, qpc_frequency | 元の QPC 値と周波数。異なる時計の値をそのまま時刻として比較しない |
| kind, api_id, schema_id, call_id, parent_call_id | 元のイベント識別・呼び出し対応 |
| api, schema_name | 解決済みの名前。未知の Schema は NULL |
| phase, capture | enter / leave / aborted 等、イベントの取得状態 |
| args_error | 引数を復号できなかった理由。成功時は NULL |
| event_json | JSONL export と同じイベント内容。型付き値、取得状態、Blob 参照、COM の名前等を保持 |

`event_json` のポインタ・浮動小数点ビット列・UTF-16 等は JSONL と同じ表現を
使い、値を推測・丸め・置換しない。Blob の本体は埋め込まず、元 Trace への参照を
保持する。追加の列が必要な場合は SQL の JSON 関数で取り出せる。

`shirusu.trace_summary` metadata には `inspect --json` の内容を保存する。
Capture Coverage、Event Integrity、Semantic Completeness、復旧の問題、欠落、
正常確定の有無をここから確認できる。欠落した Trace も変換できるが、変換成功は
元 Trace が完全という意味ではない。解析時の完全性ゲートには `shirusu inspect`
またはこの metadata を使う。

行グループは最大 4096 イベント。Snappy で圧縮する。空の Trace も schema と
metadata を持つ有効な Parquet ファイルにする。入力 Trace の読み取りには既存の
Reader の上限が適用される。イベント全体をストリーミングで読み込む機能ではない。

実装依存は Apache Arrow の Rust `parquet` 59.x（Apache-2.0）、Rust `snap`
（BSD-3-Clause）、`tempfile`（MIT または Apache-2.0）。Arrow 配列の依存と
C の圧縮ライブラリは使わない。60.x は Rust 1.88 が必要なため、プロジェクトの
MSRV 1.87 を維持できる 59.x を使用する。
