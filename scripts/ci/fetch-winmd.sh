#!/usr/bin/env bash
# Win32 Metadata (Windows.Win32.winmd) を取得する (L03)。
#
# 生成器 win32-metadata-gen の入力。Microsoft の Win32 Metadata
# (NuGet `Microsoft.Windows.SDK.Win32Metadata` の固定版) から取る。
# 版は crates/shirusu-metadata-gen/apis.toml の winmd_version と
# 同じにすること。取得済みで sha256 が一致すれば何もしない。
#
# 使い方: bash scripts/ci/fetch-winmd.sh
# 出力: target/winmd/Windows.Win32.winmd
set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION="71.0.45-preview"
NUPKG_SHA256="c26f8ac7190dcd5599d074b534c5e2c1860cca84e107a63090ac22aceb7ad556"
WINMD_SHA256="b9e476a81e14060040804e4cf09b2973fc53a174befc7b3b670d4db72eef55af"
OUT_DIR="target/winmd"
OUT="$OUT_DIR/Windows.Win32.winmd"

if [ -f "$OUT" ]; then
    if [ "$(sha256sum "$OUT" | cut -d' ' -f1)" = "$WINMD_SHA256" ]; then
        echo "winmd already present: $OUT"
        exit 0
    fi
    echo "winmd hash mismatch, re-downloading: $OUT"
fi

mkdir -p "$OUT_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
NUPKG="$TMP/win32metadata.nupkg"
curl -sSL --max-time 300 -o "$NUPKG" \
    "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.win32metadata/${VERSION}/microsoft.windows.sdk.win32metadata.${VERSION}.nupkg"
if [ "$(sha256sum "$NUPKG" | cut -d' ' -f1)" != "$NUPKG_SHA256" ]; then
    echo "nupkg sha256 mismatch (expected $NUPKG_SHA256)" >&2
    exit 1
fi
unzip -o -q "$NUPKG" Windows.Win32.winmd -d "$TMP"
if [ "$(sha256sum "$TMP/Windows.Win32.winmd" | cut -d' ' -f1)" != "$WINMD_SHA256" ]; then
    echo "winmd sha256 mismatch (expected $WINMD_SHA256)" >&2
    exit 1
fi
cp "$TMP/Windows.Win32.winmd" "$OUT"
echo "fetched $OUT (Microsoft.Windows.SDK.Win32Metadata $VERSION)"
