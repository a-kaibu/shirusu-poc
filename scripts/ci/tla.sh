#!/usr/bin/env bash
# TLA+ / TLC モデル検査 (CI ubuntu + Java)。tla2tools.jar を取得して実行する。
# 主モデルは全不変条件が成立すること、旧順序の変種モデルは
# ClaimedGenerationIsCurrent の違反を検出すること (モデルが Slot 再利用の
# 競合を表現できる証跡) の両方を確認する。
set -euo pipefail
cd "$(dirname "$0")/../../tla"
if [ ! -f tla2tools.jar ]; then
  curl -fsSL -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
fi
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers auto -config ShirusuTransport.cfg ShirusuTransport

buggy_log="$(mktemp)"
if java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers auto -config ShirusuTransportBuggy.cfg ShirusuTransportBuggy >"$buggy_log" 2>&1; then
  echo "ERROR: 旧順序の変種モデルで違反が検出されなかった (モデルが競合を表現できていない)" >&2
  cat "$buggy_log" >&2
  exit 1
fi
if ! grep -q "Invariant ClaimedGenerationIsCurrent is violated" "$buggy_log"; then
  echo "ERROR: 変種モデルで期待した ClaimedGenerationIsCurrent の違反が見つからない" >&2
  cat "$buggy_log" >&2
  exit 1
fi
echo "OK: 変種モデル (旧順序) で ClaimedGenerationIsCurrent の違反を検出した"
