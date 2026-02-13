# LostandFound-App

Lost-and-found web app based on Flask, SQLite, Gunicorn, Nginx, and Certbot.

## Features
- Internal login-based workflow for lost/found items
- Public read-only item links via token
- Photo uploads
- Admin user and category management
- Audit log and CSV export

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

## Security Notes
- CSRF protection is enabled for POST routes.
- Open redirect on login is blocked.
- Brute-force protection for login attempts is enabled.
- No default fallback `SECRET_KEY` is used.

## Documentation
- Deployment details: `DeploymentGuide.md`
