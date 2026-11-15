#!/usr/bin/env bash
# Stage the NeonHearth Linux release layout.
#
# Builds the release service binary and desktop UI bundle, then stages them
# into packaging/dist/linux/ so packaging/linux/nfpm.yaml has a real input.
#
# Usage (from a Linux host or WSL2 with the repo's toolchain):
#   packaging/stage.sh [--skip-rust] [--skip-ui]
#
# STATUS / HONESTY: authored on the Windows build machine and validated with
# `bash -n` (syntax only). It has NOT been executed end-to-end on a Linux
# host from this session.
set -euo pipefail

SKIP_RUST=0
SKIP_UI=0
for arg in "$@"; do
    case "$arg" in
        --skip-rust) SKIP_RUST=1 ;;
        --skip-ui) SKIP_UI=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

PACKAGING_ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$PACKAGING_ROOT")"
DIST_ROOT="$PACKAGING_ROOT/dist/linux"
DESKTOP="$REPO_ROOT/apps/desktop"

if [ "$SKIP_RUST" -eq 0 ]; then
    echo "== cargo build --release -p lattice-service =="
    (cd "$REPO_ROOT" && cargo build --release -p lattice-service)
fi

if [ "$SKIP_UI" -eq 0 ]; then
    echo "== npm build apps/desktop =="
    if [ ! -d "$DESKTOP/node_modules" ]; then
        npm --prefix "$DESKTOP" ci
    fi
    npm --prefix "$DESKTOP" run build
fi

BIN="$REPO_ROOT/target/release/lattice-service"
UI_DIST="$DESKTOP/dist"
[ -x "$BIN" ] || { echo "missing $BIN - run without --skip-rust" >&2; exit 1; }
[ -f "$UI_DIST/index.html" ] || { echo "missing $UI_DIST/index.html - run without --skip-ui" >&2; exit 1; }

echo "== staging into $DIST_ROOT =="
rm -rf "$DIST_ROOT"
mkdir -p "$DIST_ROOT/bin"
cp "$BIN" "$DIST_ROOT/bin/lattice-service"
cp -R "$UI_DIST" "$DIST_ROOT/ui"

# Deterministic manifest so package inputs are auditable.
(
    cd "$DIST_ROOT"
    find . -type f ! -name STAGING-MANIFEST.txt -print0 |
        sort -z |
        xargs -0 sha256sum > STAGING-MANIFEST.txt
)

echo "Staged $(find "$DIST_ROOT" -type f | wc -l) files into $DIST_ROOT"
echo "Manifest: $DIST_ROOT/STAGING-MANIFEST.txt"
