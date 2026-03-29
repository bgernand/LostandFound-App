#!/usr/bin/env bash
set -euo pipefail

INIT_LETSENCRYPT=0
LETSENCRYPT_EMAIL=""

usage() {
  cat <<'EOF'
Usage:
  ./deploy.sh [--init-letsencrypt --email you@example.com]

Options:
  --init-letsencrypt   Request an initial Let's Encrypt certificate if none exists yet.
  --email <address>    Email used for Let's Encrypt (required with --init-letsencrypt).
  -h, --help           Show this help.
EOF
}

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

is_invalid_example_value() {
  local v="${1:-}"
  [[ -z "$v" ]] && return 0
  [[ "$v" == replace-with-* ]] && return 0
  [[ "$v" == "your-domain.example" ]] && return 0
  [[ "$v" == "https://your-domain.example" ]] && return 0
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --init-letsencrypt)
      INIT_LETSENCRYPT=1
      shift
      ;;
    --email)
      [[ $# -lt 2 ]] && fail "--email requires a value"
      LETSENCRYPT_EMAIL="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "==> LostandFound deployment starting..."

mkdir -p data uploads certbot/www certbot/conf nginx/templates roundcube/data roundcube/sessions

# Ensure mounted runtime directories are writable by the non-root app user (uid/gid 10001).
APP_UID="${APP_UID:-10001}"
APP_GID="${APP_GID:-10001}"
chown -R "${APP_UID}:${APP_GID}" data uploads

# Roundcube runs as www-data inside the container and needs write access to its sqlite/session storage.
ROUNDCUBE_UID="${ROUNDCUBE_UID:-33}"
ROUNDCUBE_GID="${ROUNDCUBE_GID:-33}"
chown -R "${ROUNDCUBE_UID}:${ROUNDCUBE_GID}" roundcube/data
chown -R "${ROUNDCUBE_UID}:${ROUNDCUBE_GID}" roundcube/sessions

if [[ ! -f ".env" ]]; then
  if [[ -f ".env.example" ]]; then
    cp .env.example .env
    fail ".env was missing. Created from .env.example. Please edit .env and run again."
  fi
  fail ".env is missing and no .env.example was found."
fi

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git ls-files --error-unmatch .env >/dev/null 2>&1; then
    fail ".env is tracked by git. Remove it from repository tracking (git rm --cached .env) before deployment."
  fi
fi

load_env_file() {
  while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
    local line="$raw_line"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue
    [[ "$line" != *=* ]] && continue

    local key="${line%%=*}"
    local value="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"
    value="${value#"${value%%[![:space:]]*}"}"

    if [[ ${#value} -ge 2 ]]; then
      if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
        value="${value:1:${#value}-2}"
      elif [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
        value="${value:1:${#value}-2}"
      fi
    fi

    printf -v "$key" '%s' "$value"
    export "$key"
  done < ./.env
}

load_env_file

is_invalid_example_value "${SECRET_KEY:-}" && fail "SECRET_KEY in .env is missing or still a placeholder."
is_invalid_example_value "${INITIAL_ADMIN_PASSWORD:-}" && fail "INITIAL_ADMIN_PASSWORD in .env is missing or still a placeholder."
is_invalid_example_value "${BASE_URL:-}" && fail "BASE_URL in .env is missing or still a placeholder."
is_invalid_example_value "${DOMAIN:-}" && fail "DOMAIN in .env is missing or still a placeholder."

command -v docker >/dev/null 2>&1 || fail "Docker is not available in PATH."

COMPOSE_CMD=()
if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
else
  fail "Neither 'docker compose' nor 'docker-compose' is available."
fi

compose() {
  "${COMPOSE_CMD[@]}" "$@"
}

LE_FULLCHAIN_HOST_PATH="${PROJECT_ROOT}/certbot/conf/live/${DOMAIN}/fullchain.pem"
LE_PRIVKEY_HOST_PATH="${PROJECT_ROOT}/certbot/conf/live/${DOMAIN}/privkey.pem"
SERVICES=(app worker nginx certbot)
if [[ "${ROUNDCUBE_ENABLED:-false}" == "true" ]]; then
  SERVICES=(app worker roundcube nginx certbot)
fi

has_existing_le_cert() {
  [[ -f "$LE_FULLCHAIN_HOST_PATH" && -f "$LE_PRIVKEY_HOST_PATH" ]]
}

echo "==> Building and starting full stack..."
compose up -d --build "${SERVICES[@]}"

if [[ "$INIT_LETSENCRYPT" -eq 1 ]]; then
  [[ -z "$LETSENCRYPT_EMAIL" ]] && fail "Use --email you@example.com with --init-letsencrypt."

  if has_existing_le_cert; then
    echo "==> Existing Let's Encrypt certificate found for ${DOMAIN}. Skipping certificate request."
  else
    echo "==> Requesting initial Let's Encrypt certificate for ${DOMAIN} ..."
    compose run --rm --entrypoint certbot certbot certonly \
      --webroot -w /var/www/certbot \
      -d "$DOMAIN" \
      --email "$LETSENCRYPT_EMAIL" \
      --agree-tos --no-eff-email \
      --cert-name "$DOMAIN"
  fi

  echo "==> Reloading nginx to pick up certificate state..."
  compose exec nginx sh -lc "nginx -s reload"
fi

echo
echo "Deployment finished."
echo "App stack: running (${SERVICES[*]})."
if [[ "$INIT_LETSENCRYPT" -eq 0 ]]; then
  if has_existing_le_cert; then
    echo "Let's Encrypt certificate already present for ${DOMAIN}."
  else
    echo "HTTPS with real Let's Encrypt cert not requested in this run."
    echo "Run once: ./deploy.sh --init-letsencrypt --email you@example.com"
  fi
fi
