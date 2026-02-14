# Deployment Guide (Debian/Linux)

This guide deploys the app with Docker Compose, Nginx, and Certbot.

Code layout note:
- Runtime app code is in `lfapp/main.py`.
- Root `app.py` is a compatibility entry-point that calls `create_app()`, so existing `gunicorn app:app` setup keeps working.
- `create_app(config=None)` supports optional config overrides (mainly useful for tests).
- Extracted helper modules include:
  - `lfapp/db_utils.py`
  - `lfapp/totp_utils.py`
  - `lfapp/match_utils.py`
  - `lfapp/link_match_utils.py`
  - `lfapp/security_utils.py`
  - `lfapp/filter_utils.py`
  - `lfapp/category_utils.py`
  - `lfapp/auth_core.py`
  - `lfapp/routes_auth.py`
  - `lfapp/routes_admin.py`
  - `lfapp/routes_overview.py`
  - `lfapp/routes_items.py`
  - `lfapp/item_form_utils.py`

## 1. Prerequisites
- Debian/Linux server
- Docker + Docker Compose plugin (`docker compose`) or `docker-compose`
- Domain with DNS record to server IP
- Open ports `80` and `443`

## 2. Prepare Project
```bash
cd /opt/LostandFound-App
cp .env.example .env
nano .env
```

Set at minimum:
- `SECRET_KEY` with a long random value
- `INITIAL_ADMIN_PASSWORD` with a strong password
- `BASE_URL` with full URL (`https://your-domain.example`)
- `DOMAIN` with hostname only (`your-domain.example`)

Recommended security settings:
- `MIN_PASSWORD_LENGTH=10` (or higher)
- `TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128,172.16.0.0/12` (adapt to your proxy network)
- `SESSION_COOKIE_SECURE=1`
- `SESSION_COOKIE_SAMESITE=Lax`
- `MAX_CONTENT_LENGTH=20971520` (20 MB)

## 3. One-Click Deploy
```bash
chmod +x deploy.sh
./deploy.sh
```

What this does:
- creates required folders (`data`, `uploads`, `certbot/www`, `certbot/conf`)
- validates `.env`
- builds and starts `app`, `nginx`, and `certbot`

## 4. Initial Let's Encrypt Certificate (Optional in same script)
```bash
./deploy.sh --init-letsencrypt --email you@example.com
```

This requests the initial certificate and reloads Nginx with symlinked cert files.

## 5. Verify Deployment
```bash
docker compose ps
docker compose logs -f app
docker compose logs -f nginx
docker compose logs -f certbot
```

Functional checks after deploy:
- Login works and /dashboard opens
- Viewer user is read-only (no create/edit/link/delete controls)
- Bulk status update works for staff/admin
- Possible Matches page loads and score colors are visible
- Saved searches can be saved/opened/deleted
- Reminder workflow appears for stale In contact items
- Receipt PDF download works on item detail
- Public token link /p/<token> is accessible only when public sharing is enabled

If `docker compose` is unavailable on your server, use:
```bash
docker-compose ps
```

## 6. Updates / Redeploy
```bash
./deploy.sh
```

If you updated from an older root-based setup and see `sqlite3.OperationalError: attempt to write a readonly database`, fix ownership once:
```bash
chown -R 10001:10001 data uploads
docker compose up -d --build app
```

## 7. Persistent Data
- `./data` -> SQLite DB (`/app/data`)
- `./uploads` -> uploaded photos (`/app/uploads`)
- `./certbot/conf` -> Let's Encrypt cert data
- `./certbot/www` -> ACME challenge webroot

## 8. Backups (Recommended)
Backup these folders regularly:
- `data/`
- `uploads/`
- `certbot/conf/`

## 9. CI / Tests
- CI config is in `.github/workflows/ci.yml` and runs a factory smoke check plus `pytest`.
- Local test run:
```bash
python -m pip install -r requirements.txt
python -m pip install pytest
pytest -q
```






## 10. Manual Sanity Check (Post-Refactor)
Run this quick checklist after updates that touch routing or app initialization:
- Open `/login` and verify redirect to `/dashboard` after login.
- Create one `Lost Request` and one `Found Item`, then open both detail pages.
- Create and delete a link between them, verify status sync and timeline entries.
- Download `Receipt` PDF and verify filename uses receipt number.
- Open Possible Matches, apply filters, save/open/delete one saved search.
- Export CSV from filtered home view and verify file content.



