# API 別 Coverage 台帳

```sh
shirusu coverage capture.trace
shirusu coverage capture.trace --json
```

静的依存、Hook 設置、観測、意味情報を別々の証拠として表示する。記録する Agent と
Host は Bootstrap v12 の同じビルドを使う。結果欄は固定 256 スロットで、API を追加しても
構造体サイズを暗黙に変えない。新しい Agent は旧版の小さい Bootstrap を
全体コピーする前に version を検査して拒否する。

- 静的依存：現在は起動対象 EXE の通常 import table のみ。source と名前／序数を残す。
  Attach、DLL 内の依存、delay-load、動的解決がないことを意味しない。
- Hook：Win32 API ごとに IAT と Inline の結果、理由、範囲を保存する。
  IAT はメインモジュール、Inline は初期化時に解決した export が対象。
  `already-hooked` も今回の設置成功とは扱わず、実際の見送り理由のまま残す。
  設置後のアンロード、全経路の捕捉、共有 COM メソッドの記録を保証しない。
- 観測：保存された Enter / Leave / その他の件数。Profile の集計は別欄。
  0 件は `not-observed` であり「未使用」ではない。記録設定も併記する。
- 意味情報：Agent が申告した対応レベル・制限と、観測されたイベント／引数の
  取得状態・復号失敗数を分ける。能力が L2 でも全引数取得済みとは扱わない。

旧 Trace は解析できるが、保存されていなかった設置証拠は `unknown` のまま。
API 名は Trace の schema / 設置証拠から解決し、現在の API ID 表に置き換えない。
API Set の契約名と実装名は根拠なく統合しない。欠落 Trace は台帳を出した上で終了 1。
正常終了・Finalization の有無・三つの完全性も JSON に残す。

Environment の追加 field 11 は省略可能。空の場合は従来と同じ符号化になり、
旧 reader は未知 field として読み飛ばせる。後続 Environment のモジュール更新でも
証拠を保持する。台帳は現在、初期化成功後の Trace を対象とし、Trace 作成前に
失敗した Attach の診断は従来どおりエラーと Rollback 結果で報告する。
