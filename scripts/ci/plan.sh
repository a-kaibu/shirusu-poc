#!/usr/bin/env bash
# CI プランナ：イベントに応じて scripts/ci/matrix.json から実行行列を作る。
# .github/workflows/ci.yml（汎用ランナー）の plan ジョブから呼ばれる。
# ローカルでも実行できる：
#   EVENT_NAME=push bash scripts/ci/plan.sh
#   EVENT_NAME=schedule EVENT_SCHEDULE="23 4 * * 0" bash scripts/ci/plan.sh
#   EVENT_NAME=workflow_dispatch INPUT_SUITE=all bash scripts/ci/plan.sh
# GITHUB_OUTPUT があればそこへ、無ければ stdout へ matrix=<json> を出す。
set -euo pipefail
cd "$(dirname "$0")/../.."

# --- スイート決定 ---
suite=""
case "${EVENT_NAME:-push}" in
  workflow_dispatch)
    suite="${INPUT_SUITE:-ci}"
    ;;
  schedule)
    # 日曜 cron は nightly + weekly、それ以外の schedule は nightly のみ
    if [ "${EVENT_SCHEDULE:-}" = "23 4 * * 0" ]; then
      suite="nightly weekly"
    else
      suite="nightly"
    fi
    ;;
  *)
    suite="ci"
    ;;
esac
if [ "$suite" = "all" ]; then
  suite="ci nightly weekly"
fi

# --- 行列生成（suites に要求スイートのいずれかを含むジョブを選ぶ） ---
matrix="$(jq -c --arg suites "$suite" '
  ($suites | split(" ")) as $want
  | {include: [ .jobs[]
      | select(any(.suites[]; . as $s | ($want | index($s)) != null))
      | {name, os, toolchain, targets, components, java, run, allow_failure, timeout} ]}
' scripts/ci/matrix.json)"

count="$(printf '%s' "$matrix" | jq '.include | length')"
if [ "$count" -eq 0 ]; then
  echo "plan: no jobs selected for suite(s): $suite" >&2
  exit 1
fi
echo "plan: suite(s)=[$suite] jobs=$count" >&2

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "matrix=$matrix" >> "$GITHUB_OUTPUT"
else
  echo "matrix=$matrix"
fi
