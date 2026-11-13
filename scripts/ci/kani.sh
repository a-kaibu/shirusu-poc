#!/usr/bin/env bash
# Kani 主要 harness (CI ubuntu)。Kani 未導入環境では固定版を導入する。
# 導入・セットアップの失敗は検証の未実施であり、成功として扱わない。
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"
export TAR_OPTIONS=--no-same-owner
KANI_VERSION="0.68.0"
if ! cargo kani --version 2>/dev/null | grep -q "$KANI_VERSION"; then
  cargo install kani-verifier --version "$KANI_VERSION" --locked || { echo "KANI_UNAVAILABLE: cargo-kani を導入できませんでした" >&2; exit 1; }
  cargo kani setup || { echo "KANI_SETUP_FAILED" >&2; exit 1; }
fi
# set -e を使わないため、各クレートの結果を集めて最後に終了コードへ反映する。
status=0
for crate in shirusu-crc32c shirusu-transport shirusu-trace shirusu-hook; do
  cargo kani -p "$crate" || status=1
done
exit "$status"
