# 互換実装の開発支援に向けた優先順

完成済みの範囲と、次に必要な検証を分けて追跡する。API の追加件数を完成条件にはしない。

1. **API 別 Coverage 台帳**：初版実装。Agent の IAT / Inline 設置結果を Trace に保存し、
   静的依存、観測、意味情報と並べる。範囲は [coverage-ledger.md](coverage-ledger.md)。
   DLL・delay import、共有 COM、設置後の変化を含む全経路の証明は未対応。
2. **高頻度 Capture**：部品別計測と Host コピー削減まで実装。Windows の実アプリで
   高負荷時の欠落が残る。単独 Runtime 取得だけでなく、並行回収・変換・通知・待機を
   測る。TLS Writer / Runtime 参照の変更には終了・再 Attach・TLS 消失・SEH の寿命検証が必須。
3. **差分から再現 Probe**：既存 compare / probe / 同期ファイル replay を接続する。
   HANDLE の生成・使用だけでなくファイル初期状態と副作用の依存を保存する。
   記録にない状態を仮定しない。まず対象を同期ファイル 4 API に限定し、Windows と
   比較対象の両方で元の差分が残ることを検証してから削減する。
   初段として、候補のファイルに関する全寿命の履歴を残す依存抽出を実装。
   不明な初期状態は拒否し、無関係なファイルのみ除く。
   続いて、oracle の再現確認を 2 回要求する予算付き単一 I/O 削減 API を実装。
   既存 Runner の型付き結果を対象差分の照合へ接続する adapter も実装。
   先行操作と対象入力が一致する同期 Trace の値差分から fingerprint を生成し、
   バンドルの期待値へ接続済み。外部実行器起動・実行証拠保存・CLI 接続は未実装で、
   元アプリの差分を実行検証済みの最小化とは扱わない。
4. **宣言的な意味契約**：CreateFileW / ReadFile / WriteFile / CloseHandle の成功条件、
   入出力、長さ、所有権を契約にまとめ、既存 Golden と一致させる。SAL は副作用・
   非同期完了の完全な仕様とは扱わない。未実装。
5. **Windows 参照コーパス**：同じ Probe の OS build / architecture / 前提条件 / 結果を
   保存し、単一の Windows 実行を唯一の正解にしない。CI Golden と区別して設計する。未実装。
6. **ETW 補助観測**：Hook とは独立した provenance を持つ証拠とする。API と一対一に
   対応づけず、ETW だけの I/O を直ちに Hook 欠落と判定しない。後続、未実装。

標準の呼び出し元境界と共有 COM L1、任意 Attach の安全性の残課題は、
上記の新機能によって解決済みとは扱わない。
