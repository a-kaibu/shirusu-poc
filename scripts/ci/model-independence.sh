#!/usr/bin/env bash
# D56: PBT 参照モデル / 影モデルが実装に追随していないこと (独立性) を
# mutation で実証する。
#
# 手順: 追跡ファイルだけを一時ディレクトリへコピーし、
#   1) 無変更で対象 PBT が成功すること
#   2) 実装へ意図的なバグ (mutation) を入れたコピーで対象 PBT が
#      「テスト失敗」として検出されること
# の両方を確認する。2) で成功してしまうと、参照モデルが実装の計算を
# 写している (独立でない) 疑いが残るため、このスクリプト自体が失敗する。
# mutation の文字列が見つからない場合も、陳腐化として失敗にする。
#
# 実行: scripts/ci/model-independence.sh (nightly の long-verification
# ジョブから呼ばれる。通常の CI では時間節約のため実行しない)
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"
export SHIRUSU_PBT_CASES="${SHIRUSU_PBT_CASES:-128}"

work="${SHIRUSU_MUTATION_WORKDIR:-$PWD/target/model-independence-work}"
rm -rf "$work"
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

copy_tree() {
  local dest="$1"
  mkdir -p "$dest"
  git ls-files | tar -cf - -T - | tar -xf - --no-same-owner -C "$dest"
}

apply_mutation() {
  # $1=file $2=from $3=to
  python3 - "$1" "$2" "$3" <<'PYEOF'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path).read()
if src.count(old) != 1:
    print(f"mutation target not unique/found in {path}: {old!r} (count={src.count(old)})")
    sys.exit(1)
open(path, "w").write(src.replace(old, new))
PYEOF
}

run_pbt() {
  # $1=dir $2=test-file $3=test-name。成功で 0、テスト失敗で 1、その他で 2。
  local dir="$1" file="$2" name="$3"
  local out
  out="$(cd "$dir" && cargo test -p shirusu-transport --test "$file" "$name" 2>&1)" && return 0
  if grep -q "test result: FAILED" <<<"$out"; then
    return 1
  fi
  echo "$out" | tail -20
  return 2
}

echo "== baseline (no mutation): both reference models must pass =="
base="$work/base"
copy_tree "$base"
run_pbt "$base" proptest_ring ring_matches_vecdeque_model
run_pbt "$base" proptest_properties slot_lifecycle_interleavings_match_shadow_model
echo "baseline: PASS"

check_mutation() {
  # $1=label $2=file $3=from $4=to $5=test-file $6=test-name
  local label="$1" file="$2" from="$3" to="$4" tfile="$5" tname="$6"
  local dir="$work/$label"
  copy_tree "$dir"
  apply_mutation "$dir/$file" "$from" "$to"
  local rc=0
  run_pbt "$dir" "$tfile" "$tname" || rc=$?
  if [ "$rc" -eq 1 ]; then
    echo "mutation $label: DETECTED by $tname (model is independent)"
  elif [ "$rc" -eq 0 ]; then
    echo "mutation $label: NOT detected by $tname -- model may mirror the implementation"
    exit 1
  else
    echo "mutation $label: inconclusive run (build/run error)"
    exit 1
  fi
}

# 実装の占有量計算を逆転させると、VecDeque 参照モデルとの照合が壊れるはず。
check_mutation occupancy-swap \
  crates/shirusu-transport/src/layout.rs \
  "write_cursor.checked_sub(read_cursor)" \
  "read_cursor.checked_sub(write_cursor)" \
  proptest_ring ring_matches_vecdeque_model

# 回収で Generation を進めなくすると、Slot 影モデルとの照合が壊れるはず。
check_mutation generation-stall \
  crates/shirusu-transport/src/slot.rs \
  "s.generation.fetch_add(1, Ordering::AcqRel);" \
  "s.generation.fetch_add(0, Ordering::AcqRel);" \
  proptest_properties slot_lifecycle_interleavings_match_shadow_model

echo "model independence: OK (both mutations detected)"
