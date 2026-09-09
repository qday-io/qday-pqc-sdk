#!/bin/sh
set -eu

# Bind-mounted ./data is owned by the host user. Start as root, fix
# ownership, then drop to the unprivileged service account `app`.
mkdir -p /data
if [ "$(id -u)" = "0" ]; then
	chown -R app:app /data
	chmod 0750 /data
	exec gosu app /usr/local/bin/qday-pqc-server "$@"
fi

exec /usr/local/bin/qday-pqc-server "$@"
