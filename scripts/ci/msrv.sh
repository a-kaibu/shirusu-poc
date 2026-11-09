#!/usr/bin/env bash
# MSRV check (Rust 1.87 — 2026-11-09 に kota が決定)。
#
# 1.87 を選んだ経緯: 当初の MSRV 1.77 は依存グラフと整合しなかった。
# - blake3 1.8.7 → cpufeatures 0.3.1 (edition2024 のマニフェスト。Cargo 1.85+)
# - proptest 1.12 → chacha20 0.10 → cpufeatures 0.3 (同上)
# - ruzstd はソース自体が #[expect] (1.81) 等を使い 0.8.x は 1.77 で
#   コンパイル不能。0.8.3 は rust-version 1.87 を宣言する。
# - generator 0.8.12 (loom の依存) は rust-version 1.95 を宣言する。
# よって 1.87 + 「generator ≤ 0.8.11 を Cargo.lock で固定」が最小構成。
# `cargo update` の際は generator が 0.8.12 以降へ上がらないよう注意する
# こと (上がるとこのジョブが rust-version 不一致で落ちて気づける)。
#
# Cargo.lock は v4 だが Cargo 1.87 はそのまま読めるため、旧 1.77 時代の
# ロックファイル差し替えは不要。--locked でピン済みグラフをそのまま使う。
set -euo pipefail
rustc --version
cargo check --workspace --locked
