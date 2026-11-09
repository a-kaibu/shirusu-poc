#!/usr/bin/env bash
# TLA+ / TLC モデル検査 (CI ubuntu + Java)。tla2tools.jar を取得して実行する。
set -euo pipefail
cd "$(dirname "$0")/../../tla"
if [ ! -f tla2tools.jar ]; then
  curl -fsSL -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
fi
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers auto -config ShirusuTransport.cfg ShirusuTransport
