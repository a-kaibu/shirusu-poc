#!/usr/bin/env bash
# Weekly CI: cargo-fuzz 長時間実行（各 target 最大 600 秒）。CI ubuntu, nightly。
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"
if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
  cargo +nightly install cargo-fuzz --locked || { echo "FUZZ_UNAVAILABLE: cargo-fuzz を導入できませんでした"; exit 1; }
fi
fuzz/materialize-corpus.sh
cd fuzz
for t in validate_control decode_descriptor decode_payload snapshot_fragments decode_compact recover_trace stream_trace blob_hex trace_budgets proto_messages pe_image inline_plan drain_chunk; do
  cargo +nightly fuzz run "$t" -- -max_total_time=600 || exit 1
done
