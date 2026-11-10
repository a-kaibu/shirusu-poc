#!/usr/bin/env bash
# Weekly CI: 長時間の負荷テスト（D80）。D52 のソークを既定の 10 倍×10、
# 10 億 ops に拡大して release で回す。規模は SHIRUSU_STRESS_OPS で
# 上書きできる（ローカルでの短縮実行用）。CI ubuntu, stable。
# 測定根拠: この VM の release で 1000 万 ops が 1.55 秒・約 650 万 ops/s
# だったため、10 億 ops は数分程度の見込み。plan.sh の日曜 cron
# （nightly + weekly）がこのジョブを選ぶ。workflow 側の変更は不要。
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"
export SHIRUSU_STRESS_OPS="${SHIRUSU_STRESS_OPS:-1000000000}"
cargo test -p shirusu-transport --release --test stress
