# LostandFound-App

Lost-and-found web app based on Flask, SQLite, Gunicorn, Nginx, and Certbot.

## Features
- Internal login-based workflow for lost/found items
- Public read-only item links via token
- Photo uploads
- Admin user and category management
- Audit log and CSV export
- n:n linking between `Found Item` and `Lost Request`
- Link search by ID and text fields (title, description, category, location, names)
- Possible Matches overview with scoring and direct link action
- Saved searches (save, open, delete) on items overview and matches overview
- CSV export with active filter set
- Multi-select filters (status/category/type), linked/unlinked filter, date range + quick presets
- Field-level validation errors with preserved form values
- Clickable contact fields (`mailto:` / `tel:`) in detail and receipt views
- Item timeline in detail view (audit-based event history)
- Dashboard with KPIs, status distribution, top categories, and open follow-up reminders
- Bulk status update for selected items in the main overview
- Role model: `admin`, `staff`, `viewer` (viewer is read-only)
- Improved search with token expansion, synonym support, and phonetic (`soundex`) matching
- Optional per-user 2FA with TOTP (authenticator app)
- Admin controls for TOTP mandatory mode and per-user 2FA reset

## Status Behavior
- Available statuses: `Lost`, `Maybe Found -> Check`, `Found`, `In contact`, `Ready to send`, `Handed over / Sent`, `Lost forever`
- New items are always created with default status `Lost` (independent of type)
- When a link is created between items, all items in the linked graph are set to `Found`
- Changing the status of one linked item synchronizes that status to all linked items
- Daily automatic maintenance sets `Lost` items to `Lost forever` when `event_date` is older than 90 days

## Roles and Permissions
- `admin`: full access, including user/category admin and destructive actions
- `staff`: operational write access (create/edit/link/update items, reminders, bulk actions)
- `viewer`: read-only access to overviews/details/dashboard (no write actions)

## Two-Factor Authentication (TOTP)
- Each user can enable/disable 2FA in `Settings -> Two-factor authentication`.
- Login flow with enabled 2FA:
  1. Username + password
  2. TOTP code challenge (`/login/2fa`)
- Admin can enable **mandatory TOTP for all users** in `Settings -> Users`.
- If mandatory TOTP is enabled, users without configured 2FA are redirected to setup before using the app.
- Admin can reset 2FA for other users (clears TOTP secret and disables 2FA for that account).

## Possible Matching
- The system compares `Lost Request` and `Found Item` records and calculates a score per pair.
- Scoring uses multiple signals: title keywords/similarity, category, location overlap, event date distance, and optional full-text hit.
- Matches below the configured minimum score are filtered out.
- The overview supports filters for type, source/candidate status, category, date range, score threshold, and source limit.
- Already linked pairs can be included/excluded.
- A link can be created directly from the match result row.
- Score badge colors indicate confidence level (high score = stronger match).

## Follow-up Workflow
- A follow-up reminder is generated automatically when an item stays in `In contact` for more than 7 days without updates.
- Open reminders are shown on the dashboard and as a warning on the items overview.
- Staff/admin can mark reminders as done.

## Quality and CI
- Basic automated tests are included in `tests/`.
- GitHub Actions CI runs pytest on push and pull request (`.github/workflows/ci.yml`).

## Tech Stack
- Flask 3
- SQLite
- Gunicorn
- Nginx (reverse proxy, TLS termination)
- Certbot (Let's Encrypt renewal)
- Docker Compose

## Project Structure
```text
.
├─ app.py                    # compatibility entry-point (imports from lfapp/main.py)
├─ lfapp/
│  ├─ __init__.py
│  ├─ main.py                # main Flask application (routes/orchestration)
│  ├─ totp_utils.py          # TOTP helper logic
│  └─ match_utils.py         # matching/search helper logic
├─ deploy.sh
├─ docker-compose.yml
├─ dockerfile
├─ templates/
├─ nginx/
│  ├─ dockerfile
│  ├─ entrypoint.sh
│  └─ templates/default.conf.template
├─ certbot/
│  ├─ www/
│  └─ conf/
├─ data/
└─ uploads/
```

## Codebase Refactor Status
- The application was split from a single large root `app.py` into a package-based structure start:
  - runtime code now lives in `lfapp/main.py`
  - root `app.py` stays as a compatibility shim for Gunicorn/tests (`app:app`)
- Additional helper modules extracted:
  - `lfapp/totp_utils.py`
  - `lfapp/match_utils.py`
- This keeps deployment stable while allowing further modularization into dedicated files.

## Quick Start (Debian/Linux)
Tested on Debian 13.

1. Copy and edit environment file:
```bash
cp .env.example .env
nano .env
```
2. Set secure values in `.env`:
- `SECRET_KEY`
- `INITIAL_ADMIN_PASSWORD`
- `BASE_URL`
- `DOMAIN`
3. Run deployment:
```bash
chmod +x deploy.sh
./deploy.sh
```
4. Optional: request initial Let's Encrypt certificate:
```bash
./deploy.sh --init-letsencrypt --email you@example.com
```

## Environment Variables
- `SECRET_KEY` (required)
- `INITIAL_ADMIN_USERNAME` (default: `admin`)
- `INITIAL_ADMIN_PASSWORD` (required on first startup)
- `BASE_URL` (required, e.g. `https://lostfound.example`)
- `DOMAIN` (required, e.g. `lostfound.example`)
- `LOGIN_WINDOW_SECONDS` (optional, default `900`)
- `LOGIN_MAX_ATTEMPTS` (optional, default `5`)
- `MIN_PASSWORD_LENGTH` (optional, default `10`)
- `TOTP_ISSUER` (optional, default `Lost & Found`)
- `TRUSTED_PROXY_CIDRS` (optional, default `127.0.0.1/32,::1/128,172.16.0.0/12`)
- `SESSION_COOKIE_SECURE` (optional, default `1`)
- `SESSION_COOKIE_SAMESITE` (optional, default `Lax`)
- `MAX_CONTENT_LENGTH` (optional, default `20971520`)
- `DATA_DIR` (optional, default `/app/data`; Docker Compose sets it internally)
- `UPLOAD_DIR` (optional, default `/app/uploads`; Docker Compose sets it internally)
- `FLASK_DEBUG` (optional, default `0`; local development only)

## Security Notes
- CSRF protection is enabled for POST routes.
- Open redirect on login is blocked.
- Brute-force protection for login attempts is enabled.
- Optional TOTP-based 2FA is supported, including global mandatory mode.
- No default fallback `SECRET_KEY` is used.
- Session cookies are hardened (`Secure`, `HttpOnly`, `SameSite`).
- Client IP for login-rate-limit is only taken from proxy headers if request comes from trusted proxy CIDRs.
- Security headers are set at Nginx level (HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy).
- `.env` must never be committed; rotate secrets immediately if exposure is suspected.
- Daily automatic maintenance updates stale `Lost` items (`event_date` older than 90 days) to `Lost forever`.

## Documentation
- Deployment details: `DeploymentGuide.md`

## Disclaimer
This project is provided without any warranty. No liability is assumed for any direct or indirect damages, data loss, outages, or any other consequences resulting from the use, operation, or distribution of this software. Use of this software is entirely at your own risk.

