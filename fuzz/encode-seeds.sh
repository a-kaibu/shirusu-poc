#!/usr/bin/env bash
# fuzz/corpus/ のバイナリ種を fuzz/seeds/**/*.hex に書き戻す（新しい種を追加したとき用）。
set -euo pipefail
cd "$(dirname "$0")"
python3 - <<'PY'
import os
src_root, dst_root = "corpus", "seeds"
made = 0
for target in sorted(os.listdir(src_root)):
    sdir = os.path.join(src_root, target)
    if not os.path.isdir(sdir):
        continue
    odir = os.path.join(dst_root, target)
    os.makedirs(odir, exist_ok=True)
    for name in sorted(os.listdir(sdir)):
        data = open(os.path.join(sdir, name), "rb").read()
        hexs = data.hex()
        wrapped = "\n".join(hexs[i:i + 64] for i in range(0, len(hexs), 64)) + "\n"
        with open(os.path.join(odir, name + ".hex"), "w") as f:
            f.write(wrapped)
        made += 1
print(f"encoded {made} seeds")
PY
