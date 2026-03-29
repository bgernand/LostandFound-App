#!/bin/sh
set -e

/docker-entrypoint.sh apache2-foreground &
BOOT_PID=$!

TARGET_ROOT="/var/www/html"

wait_for_roundcube() {
  i=0
  while [ ! -d "${TARGET_ROOT}/plugins" ] || [ ! -d "${TARGET_ROOT}/config" ]; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
      echo "[roundcube] target directories not ready in ${TARGET_ROOT}" >&2
      kill "$BOOT_PID" >/dev/null 2>&1 || true
      wait "$BOOT_PID" || true
      exit 1
    fi
    sleep 1
  done
}

wait_for_roundcube

mkdir -p "${TARGET_ROOT}/plugins/lostandfound_bridge"
cp /opt/lostfound-roundcube/plugins/lostandfound_bridge/lostandfound_bridge.php "${TARGET_ROOT}/plugins/lostandfound_bridge/lostandfound_bridge.php"
cp /opt/lostfound-roundcube/plugins/lostandfound_bridge/lostandfound_bridge.js "${TARGET_ROOT}/plugins/lostandfound_bridge/lostandfound_bridge.js"
chown -R www-data:www-data "${TARGET_ROOT}/plugins/lostandfound_bridge"

if ! grep -q "lostandfound_bridge" "${TARGET_ROOT}/config/config.inc.php" 2>/dev/null; then
  cat /opt/lostfound-roundcube/config/config.inc.php >> "${TARGET_ROOT}/config/config.inc.php"
fi

wait "$BOOT_PID"
