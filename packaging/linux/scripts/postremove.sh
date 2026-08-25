#!/bin/sh
# NeonHearth deb/rpm postremove.
# Deliberately does NOT delete /var/lib/neonhearth, /etc/neonhearth, or the
# neonhearth user: state survives for reinstall (see README-UNINSTALL.txt in
# the state directory). Only reloads systemd so the removed unit disappears.
set -eu
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
exit 0
