#!/usr/bin/env bash
# Linux CI: fmt / clippy / unit / PBT / loom. ローカルでも同じ手順を再現できる。
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"
# L03: 生成表の最新性検査。winmd は NuGet の固定版から取得する。
bash scripts/ci/fetch-winmd.sh
cargo run -q -p shirusu-metadata-gen -- --winmd target/winmd/Windows.Win32.winmd --check
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p shirusu-loom-tests --release
