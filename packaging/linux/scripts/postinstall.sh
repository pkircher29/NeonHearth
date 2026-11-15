#!/bin/sh
# NeonHearth deb/rpm postinstall.
# Creates the service user, generates the pairing token on first install,
# and enables the unit on first install only. Token file is root-owned 0640
# (group neonhearth) so systemd (root) reads it via EnvironmentFile and it
# never appears in `systemctl show` environment listings or process command
# lines.
#
# Audit remediation 2026-09-03: `systemctl enable` no longer runs on every
# upgrade (it re-enabled a unit the administrator had deliberately disabled),
# and sysusers/chown failures are no longer swallowed with `|| true`, so a
# missing service account fails the install here with a clear message instead
# of surfacing later as an opaque service start failure.
set -eu

# Packager arguments: dpkg passes "configure <old-version>" (old-version empty
# on first install); rpm passes "1" on install and "2" on upgrade. nfpm passes
# them through unchanged. Fall back to "token file absent" when neither shape
# is recognised.
ENV_DIR=/etc/neonhearth
ENV_FILE="$ENV_DIR/service.env"
fresh_install=0
case "${1:-}" in
    configure) [ -z "${2:-}" ] && fresh_install=1 ;;
    1) fresh_install=1 ;;
    2) fresh_install=0 ;;
    *) [ ! -f "$ENV_FILE" ] && fresh_install=1 ;;
esac

# 1. Service account (idempotent). Failures are fatal: everything below
#    depends on the account existing.
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

# 2. Pairing token (first install only; preserved on upgrade).
if [ ! -f "$ENV_FILE" ]; then
    umask 077
    mkdir -p "$ENV_DIR"
    # 64 alphanumeric chars; the service requires >= 32 (constant-time compare).
    token="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 64)"
    printf 'LATTICE_SERVICE_TOKEN=%s\n' "$token" > "$ENV_FILE"
    chown root:neonhearth "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
fi

# 3. Unit activation. Enable only on a fresh install so an administrator's
#    `systemctl disable` survives package upgrades; always reload and restart
#    so an upgraded binary is picked up.
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

# 4. Data-retention note (uninstall leaves /var/lib/neonhearth in place).
if [ -d /var/lib/neonhearth ]; then
    cat > /var/lib/neonhearth/README-UNINSTALL.txt <<'EOF'
This directory holds NeonHearth's collected state (lattice.db, backups).
Package removal stops and disables the service and removes program files,
but leaves this directory so device history and approvals survive a
reinstall. Delete it manually (and /etc/neonhearth) to remove all data.
EOF
fi

exit 0
