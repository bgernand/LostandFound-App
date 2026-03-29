# Deployment Guide (Debian/Linux)

This guide deploys the app with Docker Compose, Nginx, and Certbot.

Code layout note:
- Runtime app code is in `lfapp/main.py`.
- Root `app.py` is a compatibility entry-point that calls `create_app()`, so existing `gunicorn app:app` setup keeps working.
- `create_app(config=None)` supports optional config overrides (mainly useful for tests).
- Extracted helper modules include:
  - `lfapp/cli.py`
  - `lfapp/db_utils.py`
  - `lfapp/worker_tasks.py`
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
- `SESSION_COOKIE_SECURE=true`
- `SESSION_COOKIE_SAMESITE=Lax`
- `SESSION_MAX_AGE_SECONDS=28800` (8h absolute login session max age)
- `MAX_CONTENT_LENGTH=20971520` (20 MB)
- `PUBLIC_LOST_WINDOW_SECONDS=900`
- `PUBLIC_LOST_MAX_ATTEMPTS=8`
- `PUBLIC_LOST_DAILY_MAX_ATTEMPTS=30`
- `PUBLIC_LOST_MAX_FILES=5`
- `PUBLIC_LOST_CAPTCHA_ENABLED=false` (set `true` to enable captcha on public lost form)
- `ITEM_RETENTION_MONTHS=12` (automatic deletion of items after N months without updates; set `0` to disable)
- `AUDIT_RETENTION_DAYS=180` (daily cleanup by age; set `0` to disable)
- `AUDIT_MAX_ROWS=200000` (daily cap by row count; set `0` to disable)
- `AUDIT_REDACT_ENABLED=true`
- `SETTINGS_ENCRYPTION_KEY=\"<long-random-secret>\"` (required for encrypted SMTP password storage)
- `ROUNDCUBE_ENABLED=true` (to show the Webmail menu entry and enable SSO to Roundcube)
- `ROUNDCUBE_SHARED_SECRET=\"<long-random-secret>\"`
- `ROUNDCUBE_DES_KEY=\"<long-random-secret>\"` (optional but recommended)
- `ROUNDCUBE_EXTERNAL_URL=/webmail/`

After first login as admin, configure SMTP, mail ticket workflow, item mail templates, description-quality settings, and Roundcube bridge access in:
- `Settings -> System Settings`

## 3. One-Click Deploy
```bash
chmod +x deploy.sh
./deploy.sh
```

What this does:
- creates required folders (`data`, `uploads`, `certbot/www`, `certbot/conf`, `roundcube/data`)
- validates `.env`
- builds and starts `app`, `worker`, `nginx`, and `certbot`
- also starts `roundcube` when `ROUNDCUBE_ENABLED=true` is set in `.env`
- fixes ownership for app data and Roundcube data volumes

## 4. Initial Let's Encrypt Certificate (Optional in same script)
```bash
./deploy.sh --init-letsencrypt --email you@example.com
```

This requests the initial certificate only if none exists yet for the configured domain. On later runs the script skips certificate issuance and only redeploys/updates the stack, then reloads Nginx.

## 5. Verify Deployment
```bash
docker compose ps
docker compose logs -f app
docker compose logs -f worker
docker compose logs -f nginx
docker compose logs -f certbot
```

Functional checks after deploy:
- Login works and /dashboard opens
- Public lost submission page `/report/lost` is reachable without login
- Public lost submission abuse controls work (rate limit + honeypot, optional captcha)
- Viewer user is read-only (no create/edit/link/delete controls)
- Bulk status update works for staff/admin
- Lost review queue `/reviews/lost` opens for roles with `items.review`
- Possible Matches page loads and score colors are visible
- Saved searches can be saved/opened/deleted
- Reminder workflow appears for stale Waiting for answer items
- Receipt PDF download works on item detail
- Public token link /p/<token> is accessible only when public sharing is enabled
- If mail ticket workflow is enabled:
  - sending a Lost Request mail adds a `[LFT-<public_id>]` reference
  - item status changes to `Waiting for answer`
  - incoming replies are imported into the item thread and move status to `Answer received`
  - inbound mails without a valid reference are moved to `ToDo`
  - IMAP can be tested directly in the admin UI and a mailbox poll can be triggered manually
  - Webmail is handled in Roundcube and supports the Lost & Found bridge actions `Create Lost`, `Create Found`, and `Assign to Existing Item`

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
- CI config is in `.github/workflows/ci.yml` and runs a factory smoke check, `pytest`, and `ruff`.
- Local test run:
```bash
python -m pip install -r requirements-dev.txt
pytest -q
ruff check lfapp tests app.py
```






## INITIAL_ADMIN Password Reset (Console)
If the protected `INITIAL_ADMIN` password is lost:

```bash
docker compose exec app python -m lfapp.cli reset-initial-admin-password
```

Optional non-interactive mode:
```bash
docker compose exec app python -m lfapp.cli reset-initial-admin-password --password 'YourNewStrongPassword'
```

## Worker / Scheduled Jobs
Run one maintenance cycle manually:
```bash
docker compose exec worker python -m lfapp.cli run-maintenance
```

Run one mail poll manually:
```bash
docker compose exec worker python -m lfapp.cli run-mail-poll
```

Run one full worker cycle manually:
```bash
docker compose exec worker python -m lfapp.cli run-worker --once
```

Behavior:
- Targets the `INITIAL_ADMIN` account (`is_root_admin=1`).
- Forces role `admin`.
- Reactivates the account if it was inactive.

## 10. Manual Sanity Check (Post-Refactor)
Run this quick checklist after updates that touch routing or app initialization:
- Open `/login` and verify redirect to `/dashboard` after login.
- Create one `Lost Request` and one `Found Item`, then open both detail pages.
- Create and delete a link between them, verify status sync and timeline entries.
- Download `Receipt` PDF and verify filename uses receipt number.
- Open Possible Matches, apply filters, save/open/delete one saved search.
- Export CSV from filtered home view and verify file content.




