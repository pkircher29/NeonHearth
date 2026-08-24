#!/bin/sh
# NeonHearth deb/rpm preremove: stop and disable the service cleanly.
set -eu
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl stop neonhearth.service || true
    systemctl disable neonhearth.service || true
fi
exit 0
