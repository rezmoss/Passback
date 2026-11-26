#!/usr/bin/env bash
# Reproducible release build of the passback binary.
#   TARGET=<rust target triple> [USE_ZIG=true] ./scripts/build-release.sh
# Output: dist/passback-<target>[.exe]
#
# Reproducibility: pinned toolchain (rust-toolchain.toml), --locked dependencies,
# SOURCE_DATE_EPOCH from the commit, build paths remapped, no build ids or
# timestamps embedded, one codegen unit, static musl on Linux.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${TARGET:?set TARGET}"

# Install build tools first, before the release RUSTFLAGS/CFLAGS below are set:
# those flags (e.g. +crt-static) are for our binary and break building the tools.
if [[ "${USE_ZIG:-false}" == "true" ]]; then
  # cargo-zigbuild finds zig through `python3 -m ziglang` when no zig binary is on PATH.
  command -v zig >/dev/null || python3 -m pip install --quiet --user --break-system-packages ziglang==0.15.1
  command -v cargo-zigbuild >/dev/null || cargo install cargo-zigbuild --locked
fi

export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export PASSBACK_GIT_COMMIT="$(git rev-parse --short=12 HEAD)"
export CARGO_INCREMENTAL=0
src="$(pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
flags="--remap-path-prefix=${src}=/src --remap-path-prefix=${cargo_home}=/cargo"
export CFLAGS="-ffile-prefix-map=${src}=/src -ffile-prefix-map=${cargo_home}=/cargo"

case "$TARGET" in
  *-linux-*) flags="$flags -C target-feature=+crt-static -C link-arg=-Wl,--build-id=none" ;;
  *-windows-msvc) flags="$flags -C target-feature=+crt-static -C link-arg=/Brepro" ;;
esac
export RUSTFLAGS="$flags"

if [[ "${USE_ZIG:-false}" == "true" ]]; then
  cargo zigbuild --release --locked -p passback --target "$TARGET"
else
  cargo build --release --locked -p passback --target "$TARGET"
fi

mkdir -p dist
ext=""; [[ "$TARGET" == *windows* ]] && ext=".exe"
cp "target/$TARGET/release/passback$ext" "dist/passback-$TARGET$ext"
(cd dist && { sha256sum "passback-$TARGET$ext" 2>/dev/null || shasum -a 256 "passback-$TARGET$ext"; })
