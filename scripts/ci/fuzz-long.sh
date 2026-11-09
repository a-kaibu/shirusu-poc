#!/usr/bin/env bash
# Weekly CI: cargo-fuzz 長時間実行（各 target 最大 600 秒）。CI ubuntu, nightly。
set -uo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"
if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
  cargo +nightly install cargo-fuzz --locked || { echo "FUZZ_UNAVAILABLE: cargo-fuzz を導入できませんでした"; exit 0; }
fi
fuzz/materialize-corpus.sh
cd fuzz
for t in validate_control decode_descriptor decode_payload snapshot_fragments; do
  cargo +nightly fuzz run "$t" -- -max_total_time=600 || exit 1
done
