NeonHearth keeps its collected state (lattice.db, backups) in /var/lib/neonhearth
and its pairing token in /etc/neonhearth/service.env.
Removing the package stops and disables the service and removes program files,
but leaves both locations so device history and approvals survive a reinstall.
Delete them manually (and the neonhearth user) to remove all data.
