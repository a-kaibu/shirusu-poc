#!/usr/bin/env bash
# Nightly CI: 長時間 PBT / DST + loom（release、拡張ケース数）。ローカルでも同じ手順を再現できる。
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"
PROPTEST_CASES=4096 cargo test --workspace --release
cargo test -p shirusu-loom-tests --release
