#!/usr/bin/env bash
# Kani 主要 harness (CI ubuntu)。Kani 未導入環境では導入を試み、失敗したらその旨を表示する。
set -uo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"
export TAR_OPTIONS=--no-same-owner
if ! cargo kani --version >/dev/null 2>&1; then
  cargo install kani-verifier --locked || { echo "KANI_UNAVAILABLE: cargo-kani を導入できませんでした"; exit 0; }
  cargo kani setup || { echo "KANI_SETUP_FAILED"; exit 0; }
fi
cargo kani -p shirusu-transport
