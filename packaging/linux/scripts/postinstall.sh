#!/bin/sh
# NeonHearth deb/rpm postinstall.
# Creates the service user, generates the pairing token on first install,
# and enables the unit. Token file is root-owned 0640 (group neonhearth) so
# systemd (root) reads it via EnvironmentFile and it never appears in
# `systemctl show` environment listings or process command lines.
set -eu

# 1. Service account (idempotent).
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/neonhearth.conf || true
elif ! getent passwd neonhearth >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/neonhearth --create-home \
        --shell /usr/sbin/nologin neonhearth
fi

# 2. Pairing token (first install only; preserved on upgrade).
ENV_DIR=/etc/neonhearth
ENV_FILE="$ENV_DIR/service.env"
if [ ! -f "$ENV_FILE" ]; then
    umask 077
    mkdir -p "$ENV_DIR"
    # 64 alphanumeric chars; the service requires >= 32 (constant-time compare).
    token="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 64)"
    printf 'LATTICE_SERVICE_TOKEN=%s\n' "$token" > "$ENV_FILE"
    chown root:neonhearth "$ENV_FILE" 2>/dev/null || true
    chmod 0640 "$ENV_FILE"
fi

# 3. Unit activation.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable neonhearth.service || true
    systemctl restart neonhearth.service || \
        echo "neonhearth.service failed to start; see 'journalctl -u neonhearth'" >&2
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
