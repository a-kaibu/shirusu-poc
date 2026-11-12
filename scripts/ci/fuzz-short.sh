#!/usr/bin/env bash
# cargo-fuzz 短時間実行 (CI ubuntu, nightly)。各 target を最大 60 秒。
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"
if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
  cargo +nightly install cargo-fuzz --locked || { echo "FUZZ_UNAVAILABLE: cargo-fuzz を導入できませんでした"; exit 1; }
fi
fuzz/materialize-corpus.sh
cd fuzz
for t in validate_control decode_descriptor decode_payload snapshot_fragments decode_compact recover_trace blob_hex trace_budgets; do
  cargo +nightly fuzz run "$t" -- -max_total_time=60 || exit 1
done
