#!/bin/sh
set -e

DOMAIN="${DOMAIN:-localhost}"

DUMMY_DIR="/etc/nginx/ssl-dummy/${DOMAIN}"
DUMMY_FULLCHAIN="${DUMMY_DIR}/fullchain.pem"
DUMMY_PRIVKEY="${DUMMY_DIR}/privkey.pem"

LE_DIR="/etc/letsencrypt/live/${DOMAIN}"
LE_FULLCHAIN="${LE_DIR}/fullchain.pem"
LE_PRIVKEY="${LE_DIR}/privkey.pem"

mkdir -p "${DUMMY_DIR}"

ensure_cert_target() {
  # Prefer Let's Encrypt when available.
  if [ -f "${LE_FULLCHAIN}" ] && [ -f "${LE_PRIVKEY}" ]; then
    ln -sf "${LE_FULLCHAIN}" "${DUMMY_FULLCHAIN}"
    ln -sf "${LE_PRIVKEY}" "${DUMMY_PRIVKEY}"
    echo "[nginx] Using Let's Encrypt certificate for ${DOMAIN}."
    return
  fi

  # Fallback to temporary dummy cert (never touch /etc/letsencrypt).
  if [ ! -f "${DUMMY_FULLCHAIN}" ] || [ ! -f "${DUMMY_PRIVKEY}" ]; then
    echo "[nginx] Creating temporary self-signed cert in ${DUMMY_DIR}..."
    openssl req -x509 -nodes -newkey rsa:2048 \
      -days 7 \
      -keyout "${DUMMY_PRIVKEY}" \
      -out "${DUMMY_FULLCHAIN}" \
      -subj "/CN=${DOMAIN}" >/dev/null 2>&1
  fi
}

ensure_cert_target

# Reload loop so renewed certs get picked up
(
  while true; do
    sleep 6h
    ensure_cert_target
    echo "[nginx] periodic reload"
    nginx -s reload || true
  done
) &

# IMPORTANT: run official nginx entrypoint so templates are rendered
exec /docker-entrypoint.sh nginx -g "daemon off;"
