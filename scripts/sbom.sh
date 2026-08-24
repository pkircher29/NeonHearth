#!/usr/bin/env sh
# Generate CycloneDX SBOMs for the Rust workspace and the desktop app.
# Thin wrapper: see docs/build/supply-chain.md for context and prerequisites
# (cargo install cargo-cyclonedx --locked; Node 22 with npm; libpcap-dev on Linux).
# SBOM files (*.cdx.json) are build artifacts — do not commit them.
set -eu

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

cargo cyclonedx --format json

cd apps/desktop
npm sbom --sbom-format cyclonedx --package-lock-only > desktop.cdx.json
cd "$repo_root"

find . -name '*.cdx.json' -not -path '*/node_modules/*' -not -path '*/target/*' \
    -exec echo "SBOM: {}" \;
