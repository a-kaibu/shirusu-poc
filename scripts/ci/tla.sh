#!/usr/bin/env bash
# TLA+ / TLC モデル検査 (CI ubuntu + Java)。tla2tools.jar を取得して実行する。
# 主モデルは全不変条件が成立すること、旧順序の変種モデルは
# ClaimedGenerationIsCurrent の違反を検出すること (モデルが Slot 再利用の
# 競合を表現できる証跡) の両方を確認する。
set -euo pipefail
cd "$(dirname "$0")/../../tla"
TLA_TOOLS_SHA256="e1f11b75c4b5bc4478ba0ac5cb6ae28e40a01b0016bc33e0aa97da22dfdbcd7f"
# A cached or downloaded jar runs as CI code: verify it every time.
if [ -f tla2tools.jar ] && [ "$(sha256sum tla2tools.jar | cut -d' ' -f1)" != "$TLA_TOOLS_SHA256" ]; then
  echo "tla2tools.jar sha256 mismatch, re-downloading" >&2
  rm -f tla2tools.jar
fi
if [ ! -f tla2tools.jar ]; then
  curl -fsSL -o tla2tools.jar.tmp https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
  if [ "$(sha256sum tla2tools.jar.tmp | cut -d' ' -f1)" != "$TLA_TOOLS_SHA256" ]; then
    echo "tla2tools.jar sha256 mismatch (expected $TLA_TOOLS_SHA256)" >&2
    rm -f tla2tools.jar.tmp
    exit 1
  fi
  mv tla2tools.jar.tmp tla2tools.jar
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

# Registration precedes OS submission; late cancellation cannot erase reuse.
java -cp tla2tools.jar tlc2.TLC -config OverlappedLifecycle.cfg OverlappedLifecycle
if java -cp tla2tools.jar tlc2.TLC -config OverlappedLifecycleBuggy.cfg OverlappedLifecycle >"$buggy_log" 2>&1; then
  echo "ERROR: late registration mutation survived" >&2
  exit 1
fi
if ! grep -Eq 'Invariant (NoLostCompletion|NoEraseReusedOperation) is violated' "$buggy_log"; then
  cat "$buggy_log" >&2
  exit 1
fi
