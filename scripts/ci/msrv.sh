#!/usr/bin/env bash
# MSRV check (Rust 1.77).
# Cargo.lock v4 (written by current Cargo) cannot be read by Cargo 1.77
# (v4 needs Cargo >= 1.78), so check with a throwaway lockfile and
# restore the repo lockfile afterwards, even on failure.
set -euo pipefail
cp Cargo.lock /tmp/Cargo.lock.v4
trap 'cp /tmp/Cargo.lock.v4 Cargo.lock' EXIT
rm Cargo.lock
cargo check --workspace
