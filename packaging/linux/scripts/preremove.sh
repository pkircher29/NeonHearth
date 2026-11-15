#!/bin/sh
# NeonHearth deb/rpm preremove: stop and disable the service ONLY on a real
# removal. The same script also runs for the OLD version during an upgrade:
#   deb prerm:  "remove" | "upgrade" | "deconfigure" | "failed-upgrade"
#   rpm %preun: "0" (final erase) | "1" (upgrade)
# On rpm the old %preun runs AFTER the new %post, and on deb the old prerm runs
# before the new postinst, so stopping/disabling on upgrade left the collector
# stopped and disabled after every upgrade. postinstall.sh restarts the unit.
set -eu
STATE_DIR=/var/lib/neonhearth
case "${1:-}" in
    remove|0) ;;
    *) exit 0 ;;
esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl stop neonhearth.service || true
    systemctl disable neonhearth.service || true
fi
# Real removal only: the service (stopped above) wrote this file when the owner
# rotated the token. Leaving it behind would make it win over the token of a
# later reinstall. The rest of the state directory is kept (see postremove.sh).
rm -f "$STATE_DIR/owner-token"
exit 0
