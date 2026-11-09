#!/usr/bin/env bash
# fuzz/seeds/**/*.hex (テキスト) から fuzz/corpus/ (バイナリ) を生成する。
# 正の種は hex テキストで保持する。理由は fuzz/README.md を参照。
set -euo pipefail
cd "$(dirname "$0")"
python3 - <<'PY'
import os
src_root, dst_root = "seeds", "corpus"
made = 0
for target in sorted(os.listdir(src_root)):
    sdir = os.path.join(src_root, target)
    if not os.path.isdir(sdir):
        continue
    odir = os.path.join(dst_root, target)
    os.makedirs(odir, exist_ok=True)
    for name in sorted(os.listdir(sdir)):
        if not name.endswith(".hex"):
            continue
        hexs = "".join(open(os.path.join(sdir, name)).read().split())
        data = bytes.fromhex(hexs)
        with open(os.path.join(odir, name[:-4]), "wb") as f:
            f.write(data)
        made += 1
print(f"materialized {made} corpus files")
PY
