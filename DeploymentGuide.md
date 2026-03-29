# Deployment Guide

Deployment target: Debian / Linux with Docker Compose, Nginx, and Certbot.

This guide reflects the current application layout and feature set, including the worker container, public lost submission, AutoMail, and optional Roundcube SSO.

## Architecture

Containers:

- `app` - Flask / Gunicorn application
- `worker` - scheduled maintenance, IMAP polling, AutoMail
- `nginx` - reverse proxy and TLS termination
- `certbot` - certificate renewal
- `roundcube` - optional webmail UI

Persistent data:

- `./data`
- `./uploads`
- `./certbot/conf`
- `./certbot/www`
- `./roundcube/data`
- `./roundcube/sessions`

## 1. Prerequisites

- Debian or comparable Linux host
- Docker Engine
- Docker Compose plugin (`docker compose`)
- domain with DNS pointing to the server
- ports `80` and `443` reachable

## 2. Prepare the project

```bash
cd /opt/LostandFound-App
cp .env.example .env
nano .env
```

Set at minimum:

- `SECRET_KEY`
- `INITIAL_ADMIN_PASSWORD`
- `BASE_URL=https://your-domain.example`
- `DOMAIN=your-domain.example`

Recommended security-related values:

- `MIN_PASSWORD_LENGTH=10`
- `SESSION_COOKIE_SECURE=true`
- `SESSION_COOKIE_SAMESITE=Lax`
- `SESSION_MAX_AGE_SECONDS=28800`
- `PUBLIC_LOST_CAPTCHA_ENABLED=true`
- `PUBLIC_TOKEN_VALIDITY_DAYS=365`
- `AUDIT_REDACT_ENABLED=true`
- `SETTINGS_ENCRYPTION_KEY="<long-random-secret>"`

Optional Roundcube values:

- `ROUNDCUBE_ENABLED=true`
- `ROUNDCUBE_SHARED_SECRET="<long-random-secret>"`
- `ROUNDCUBE_DES_KEY="<long-random-secret>"`
- `ROUNDCUBE_EXTERNAL_URL=/webmail/`
- `ROUNDCUBE_REQUEST_PATH=/webmail/`
- `ROUNDCUBE_SSO_MAX_AGE_SECONDS=900`

## 3. Deploy

```bash
chmod +x deploy.sh
./deploy.sh
```

What this does:

- validates `.env`
- creates required runtime directories
- builds and starts the stack
- starts `roundcube` when `ROUNDCUBE_ENABLED=true`
- applies ownership fixes for mounted data

## 4. Issue the initial TLS certificate

```bash
./deploy.sh --init-letsencrypt --email you@example.com
```

Use this once after DNS is live. Later runs of `deploy.sh` only redeploy and reuse the existing certificate.

## 5. Verify container status

```bash
docker compose ps
docker compose logs -f app
docker compose logs -f worker
docker compose logs -f nginx
docker compose logs -f certbot
```

If Roundcube is enabled:

```bash
docker compose logs -f roundcube
```

## 6. First application setup

After the stack is up:

1. sign in with the initial admin account
2. open `Settings -> System Settings`
3. configure:
   - SMTP settings
   - IMAP / mail ticket workflow
   - public lost confirmation mail
   - item mail templates
   - AutoMail rules
   - legal notice / privacy policy

If Roundcube is enabled:

4. verify `Webmail` access with a role that has:
   - `Access Webmail`
   - `Send mail`
   - `View personal data`

## 7. Functional smoke test

Run this checklist after initial deploy or an update:

- login works and `/dashboard` opens
- create one lost item and one found item
- upload at least one photo
- link two matching items and verify synchronized status
- open the possible matches overview
- export CSV from the item overview
- open `/report/lost` without login and verify the public form loads
- verify roles and permissions UI in `Settings -> Users`
- verify public item links only work when sharing is enabled

Mail workflow checks:

- send one manual item mail
- verify item status becomes `Waiting for answer`
- if IMAP polling is enabled, verify replies import into the item thread
- verify imported replies switch status to `To be answered`
- verify unmatched mails land in the configured unassigned folder

Roundcube checks when enabled:

- `/webmail-login` opens Roundcube through SSO
- `Webmail` menu entry is only visible to users with webmail access
- unassigned mail actions work:
  - `Create Lost`
  - `Create Found`
  - `Assign to Existing Item`
- processed messages can be moved to the configured processed folder

AutoMail checks:

- verify `Settings -> System Settings -> AutoMail` opens
- create or edit a rule
- confirm worker logs show AutoMail execution

## 8. Updates and redeploy

Standard update:

```bash
git pull origin main
./deploy.sh
```

If images or dependencies changed and you want a clean rebuild:

```bash
docker compose build --no-cache
./deploy.sh
```

If ownership problems appear on SQLite or uploads:

```bash
chown -R 10001:10001 data uploads
docker compose up -d --build app worker
```

## 9. Operations Runbook

Run one maintenance cycle:

```bash
docker compose exec worker python -m lfapp.cli run-maintenance
```

Run one IMAP poll:

```bash
docker compose exec worker python -m lfapp.cli run-mail-poll
```

Run one full worker cycle:

```bash
docker compose exec worker python -m lfapp.cli run-worker --once
```

Reset `INITIAL_ADMIN` password:

```bash
docker compose exec app python -m lfapp.cli reset-initial-admin-password
```

Non-interactive reset:

```bash
docker compose exec app python -m lfapp.cli reset-initial-admin-password --password "YourNewStrongPassword"
```

Quick triage order:

1. `docker compose ps`
2. inspect `app`, `worker`, and `nginx` logs
3. if mail or webmail is involved, inspect `roundcube` logs too
4. verify the relevant settings in `System Settings`
5. rerun one worker cycle manually

## 10. Backups

There is currently no built-in backup scheduler in the stack.

At minimum, back up:

- `data/`
- `uploads/`
- `certbot/conf/`
- `roundcube/data/`
- `roundcube/sessions/` if you need session persistence during restore scenarios

Pragmatic recommendation:

- snapshot the whole project directory excluding transient build cache
- or archive the persistent directories daily with host-level cron / systemd timer

## 11. Visual Documentation Assets

The repository now reserves `docs/media/` for UI screenshots and short GIFs.

Suggested assets:

- `mail-thread.png`
- `auto-mail-settings.png`
- `webmail-unassigned.gif`

Expected capture scopes are documented in `docs/media/README.md`.

## 12. Security notes

- keep `.env` out of version control
- rotate `SECRET_KEY`, `SETTINGS_ENCRYPTION_KEY`, and Roundcube shared secrets if exposed
- review role permissions after upgrades
- keep `PUBLIC_LOST_CAPTCHA_ENABLED=true` on public deployments unless there is a reason not to
- use HTTPS only in production
- verify `BASE_URL` is correct, because public links and webmail redirects depend on it

## 13. Troubleshooting

### Roundcube login page appears instead of SSO

Check:

- `ROUNDCUBE_ENABLED=true`
- `ROUNDCUBE_SHARED_SECRET` matches between app and Roundcube
- user has:
  - `Access Webmail`
  - `Send mail`
  - `View personal data`

Useful logs:

```bash
docker compose logs --tail=150 nginx
docker compose logs --tail=150 roundcube
```

### Public links return expired / unavailable

Check:

- `PUBLIC_TOKEN_VALIDITY_DAYS`
- whether the item has public sharing enabled
- whether the token was regenerated recently

### Mail polling does not import replies

Check:

- IMAP settings in `System Settings`
- worker logs
- mailbox folder configuration
- whether the ticket reference `[LFT-<public_id>]` is present in the thread

### SQLite is read-only

Fix volume ownership:

```bash
chown -R 10001:10001 data uploads
docker compose up -d --build app worker
```
