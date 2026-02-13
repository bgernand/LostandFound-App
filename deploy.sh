#!/usr/bin/env bash
set -euo pipefail

INIT_LETSENCRYPT=0
LETSENCRYPT_EMAIL=""

usage() {
  cat <<'EOF'
Usage:
  ./deploy.sh [--init-letsencrypt --email you@example.com]

Options:
  --init-letsencrypt   Request initial Let's Encrypt certificate.
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

mkdir -p data uploads certbot/www certbot/conf nginx/templates

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

set -a
# shellcheck disable=SC1091
source ./.env
set +a

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

echo "==> Building and starting app/nginx/certbot..."
compose up -d --build app nginx certbot

if [[ "$INIT_LETSENCRYPT" -eq 1 ]]; then
  [[ -z "$LETSENCRYPT_EMAIL" ]] && fail "Use --email you@example.com with --init-letsencrypt."

  echo "==> Requesting initial Let's Encrypt certificate for ${DOMAIN} ..."
  compose run --rm --entrypoint certbot certbot certonly \
    --webroot -w /var/www/certbot \
    -d "$DOMAIN" \
    --email "$LETSENCRYPT_EMAIL" \
    --agree-tos --no-eff-email \
    --cert-name "$DOMAIN"

  echo "==> Linking LE certificate for nginx and reloading..."
  compose exec nginx sh -lc \
    "mkdir -p /etc/nginx/ssl-dummy/$DOMAIN && \
     ln -sf /etc/letsencrypt/live/$DOMAIN/fullchain.pem /etc/nginx/ssl-dummy/$DOMAIN/fullchain.pem && \
     ln -sf /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/nginx/ssl-dummy/$DOMAIN/privkey.pem && \
     nginx -s reload"
fi

echo
echo "Deployment finished."
echo "App stack: running (app, nginx, certbot)."
if [[ "$INIT_LETSENCRYPT" -eq 0 ]]; then
  echo "HTTPS with real Let's Encrypt cert not requested in this run."
  echo "Run: ./deploy.sh --init-letsencrypt --email you@example.com"
fi
