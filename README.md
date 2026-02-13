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

## Status Behavior
- Available statuses: `Lost`, `Maybe Found -> Check`, `Found`, `In contact`, `Ready to send`, `Sent`, `Done`, `Lost forever`
- New items are always created with default status `Lost` (independent of type)
- When a link is created between items, all items in the linked graph are set to `Found`
- Changing the status of one linked item synchronizes that status to all linked items
- Daily automatic maintenance sets `Lost` items to `Lost forever` when `event_date` is older than 90 days

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
├─ app.py
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

## Quick Start (Debian/Linux)
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
- `TRUSTED_PROXY_CIDRS` (optional, default `127.0.0.1/32,::1/128,172.16.0.0/12`)
- `SESSION_COOKIE_SECURE` (optional, default `1`)
- `SESSION_COOKIE_SAMESITE` (optional, default `Lax`)
- `MAX_CONTENT_LENGTH` (optional, default `20971520`)

## Security Notes
- CSRF protection is enabled for POST routes.
- Open redirect on login is blocked.
- Brute-force protection for login attempts is enabled.
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

