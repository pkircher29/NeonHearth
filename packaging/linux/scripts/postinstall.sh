#!/bin/sh
# NeonHearth deb/rpm postinstall.
# Creates the service user, generates the pairing token on first install,
# and enables the unit on first install only. The token file is root:root 0600:
# systemd (root) reads it through EnvironmentFile, so the service account needs
# no read access, and it never appears in `systemctl show` environment listings
# or process command lines.
#
# Token precedence (matches the service, crates/lattice-service/src/main.rs):
# /var/lib/neonhearth/owner-token, written by the service itself (service
# account, mode 0600) whenever the owner rotates the token, wins over the
# LATTICE_SERVICE_TOKEN value in the env file below. The env file is therefore
# only the install-time seed. Upgrades leave both alone, so a rotated token
# survives; `sudo neonhearth-token` prints whichever is current. Nothing here
# makes the token readable by an unprivileged user.
#
# Packager arguments: dpkg passes "configure <old-version>" (old-version empty
# on first install); rpm passes "1" on install and "2" on upgrade. Upgrades must
# not re-enable a unit the administrator disabled, and preremove.sh no longer
# disables the unit during an upgrade, so a plain restart here is enough.
#
# This script never writes into /var/lib/neonhearth: that directory is owned by
# the (less trusted) service account, and a root write there would follow a
# symlink the service planted. The data-retention note ships as a package file
# under /usr/share/doc/neonhearth instead.
set -eu

ENV_DIR=/etc/neonhearth
ENV_FILE="$ENV_DIR/service.env"
STATE_DIR=/var/lib/neonhearth
fresh_install=0
case "${1:-}" in
    configure) [ -z "${2:-}" ] && fresh_install=1 ;;
    1) fresh_install=1 ;;
    2) fresh_install=0 ;;
    *) [ ! -f "$ENV_FILE" ] && fresh_install=1 ;;
esac

# 1. Service account (idempotent). Failures are fatal.
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/neonhearth.conf
elif ! getent passwd neonhearth >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/neonhearth --create-home \
        --shell /usr/sbin/nologin neonhearth
fi
if ! getent passwd neonhearth >/dev/null 2>&1; then
    echo "neonhearth: service account 'neonhearth' was not created; aborting postinstall" >&2
    exit 1
fi

# 2. Pairing token (first install only; preserved on upgrade). Ownership and
#    mode are enforced on every run so a looser pre-existing directory or file
#    (including the 0640 root:neonhearth files older packages created) is fixed.
umask 077
mkdir -p "$ENV_DIR"
chown root:root "$ENV_DIR"
chmod 0700 "$ENV_DIR"
if [ -L "$ENV_FILE" ]; then
    echo "neonhearth: $ENV_FILE is a symlink; refusing to continue" >&2
    exit 1
fi
if [ ! -f "$ENV_FILE" ]; then
    # 64 alphanumeric chars; the service requires >= 32 (constant-time compare).
    token="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 64)"
    printf 'LATTICE_SERVICE_TOKEN=%s\n' "$token" > "$ENV_FILE"
    # A rotated-token file left by an earlier install would win over this new
    # seed and lock out the token just generated. rm unlinks the name only (it
    # never follows a symlink the service account may have planted).
    rm -f "$STATE_DIR/owner-token"
fi
chown root:root "$ENV_FILE"
chmod 0600 "$ENV_FILE"

# 3. Unit activation. Enable only on a fresh install so an administrator's
#    `systemctl disable` survives package upgrades; always reload and restart
#    an enabled (or fresh) unit so an upgraded binary is picked up.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    if [ "$fresh_install" -eq 1 ]; then
        systemctl enable neonhearth.service
    fi
    if [ "$fresh_install" -eq 1 ] || systemctl is-enabled --quiet neonhearth.service; then
        systemctl restart neonhearth.service || \
            echo "neonhearth.service failed to start; see 'journalctl -u neonhearth'" >&2
    fi
fi

exit 0
