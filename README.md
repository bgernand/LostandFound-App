# LostandFound-App

Lost-and-found web app built with Flask, SQLite, Docker Compose, and optional Roundcube webmail integration.

## Overview

This project covers the full operational workflow for lost and found offices:

- internal staff login with role-based permissions
- lost and found item management
- public lost-item submission
- public token links for status sharing
- matching and linking between lost and found records
- reminders, audit logging, and CSV export
- SMTP / IMAP based mail workflow
- optional Roundcube SSO for mailbox handling

## Terminology

The documentation and UI use these terms consistently:

- `Lost Request` - a reported lost item owned by a person searching for it
- `Found Item` - an item that was handed in or recorded as found
- `Review Queue` - the queue for public lost submissions that still need staff review
- `Mail` - the item-centric ticket and template workflow inside Lost & Found
- `Webmail` - the Roundcube mailbox UI reached through SSO
- `AutoMail` - delayed, rule-based automatic mails triggered by item status and age in status

## Main Features

### Item workflow

- create and manage `Lost` and `Found` items
- configurable categories
- photo uploads with content validation
- status tracking with synchronized status changes across linked items
- bulk status updates
- receipt PDF generation
- timeline / history view based on audit events

### Matching and review

- possible-match scoring between lost and found items
- direct linking from the matches overview
- saved searches and reusable filters
- dedicated public-lost review queue

### Mail workflow

- manual outbound mail from item detail pages
- admin-managed mail templates with variable rendering
- ticket-style mail threads per item
- IMAP polling for replies
- unassigned mailbox workflow
- Roundcube bridge with `Create Lost`, `Create Found`, and `Assign to Existing Item`
- optional move of processed mails to the configured processed folder

### AutoMail

- configurable automatic mails in `Settings -> System Settings -> AutoMail`
- per-rule enable / disable
- trigger by item status
- send after configurable number of days in the current status
- optional status change after sending
- built-in preset: `Still Not Found`

### Security and administration

- role-based access control with per-permission role matrix
- optional per-user TOTP 2FA
- optional mandatory 2FA for all users
- audit log with redaction
- CSRF protection
- brute-force protection for login and public lost submission
- encrypted storage for SMTP secrets when `SETTINGS_ENCRYPTION_KEY` is configured

## Status Model

Current item statuses:

- `Lost`
- `Maybe Found -> Check`
- `Found`
- `Waiting for answer`
- `To be answered`
- `Ready to send`
- `Handed over / Sent`
- `Lost forever`

Behavior:

- new items default to `Lost`
- linking items sets the linked graph to `Found`
- changing the status of one linked item synchronizes the full linked graph
- outgoing ticket mail sets status to `Waiting for answer`
- incoming ticket replies set status to `To be answered`
- daily maintenance moves stale `Lost` items to `Lost forever`
- daily maintenance deletes inactive items after `ITEM_RETENTION_MONTHS`

## Roles and Permissions

System roles:

- `admin`
- `staff`
- `found-staff`
- `lost-staff`
- `viewer`

Permissions are configurable in `Settings -> Users -> Roles & Permissions`.

Key permission areas:

- admin: access, users, settings, audit, categories
- item access: view lost / found, view personal data
- item work: create, edit, review, bulk status, linking, photo delete, delete
- public controls: public visibility and public link regeneration
- mail: send mail
- webmail: explicit Roundcube / webmail access
- reminders: reminder management

Important:

- Webmail access is controlled explicitly through the `Access Webmail` permission
- Webmail still additionally requires mail + PII access in practice
- roles can be changed in the UI; defaults are only the initial baseline

## Mail and Webmail Workflow

Mail ticket workflow is configured in `Settings -> System Settings -> Mail`.

Behavior:

- outbound item mails use ticket references in the subject: `[LFT-<public_id>]`
- IMAP polling imports matching replies into the item thread
- unmatched replies go to the configured unassigned folder
- Roundcube provides the operational mailbox UI under `/webmail/`
- Lost & Found users can enter Roundcube through SSO via `/webmail-login`

Roundcube bridge actions:

- `Create Lost`
- `Create Found`
- `Assign to Existing Item`

When processing unassigned mail, users can optionally move the message to the configured processed folder after saving or assigning.

## Public Lost Submission

Public route:

- `/report/lost`

Behavior:

- always creates a `Lost` item
- always sets `review_pending = 1`
- can trigger an optional confirmation mail
- supports abuse controls:
  - rate limit
  - honeypot
  - optional captcha

Public item links:

- use token-based URLs
- can be regenerated
- now expire after `PUBLIC_TOKEN_VALIDITY_DAYS` days

## AutoMail

AutoMail rules are managed in the admin UI and support:

- rule name
- enable / disable
- trigger statuses
- send delay in days
- subject template
- body template
- optional status after send

Built-in preset:

- `Still Not Found`

AutoMail processing runs in the worker and sends each rule once per item.

## Tech Stack

- Flask 3
- SQLite
- Gunicorn
- Docker Compose
- Nginx
- Certbot
- optional Roundcube

## Local CI Test Run

To run the same basic test flow as GitHub Actions locally, use Docker from the repository root.

PowerShell:

```powershell
.\scripts\test-ci-local.ps1
```

Bash:

```bash
./scripts/test-ci-local.sh
```

VS Code:

- open `Terminal -> Run Task`
- run `CI: Docker Test`

The local Docker run mirrors the CI job:

- `debian:13`
- Python `3.13`
- fresh virtualenv inside the container
- factory smoke check
- `pytest -q`
- `ruff check lfapp tests app.py`

Implementation detail:

- host scripts only start Docker
- the actual CI-like test sequence runs inside `scripts/test-ci-in-container.sh`
- this avoids PowerShell quoting problems on Windows

## Project Structure

```text
.
├─ app.py
├─ lfapp/
│  ├─ main.py
│  ├─ cli.py
│  ├─ db_utils.py
│  ├─ worker_tasks.py
│  ├─ auth_core.py
│  ├─ security_utils.py
│  ├─ routes_auth.py
│  ├─ routes_admin.py
│  ├─ routes_items.py
│  ├─ routes_overview.py
│  ├─ item_form_utils.py
│  ├─ match_utils.py
│  ├─ link_match_utils.py
│  ├─ category_utils.py
│  └─ totp_utils.py
├─ templates/
├─ nginx/
├─ roundcube/
├─ certbot/
├─ docker-compose.yml
├─ deploy.sh
└─ DeploymentGuide.md
```

## Quick Start

Tested on Debian / Linux.

### 1. Configure environment

```bash
cp .env.example .env
nano .env
```

Set at minimum:

- `SECRET_KEY`
- `INITIAL_ADMIN_PASSWORD`
- `BASE_URL`
- `DOMAIN`

### 2. Deploy

```bash
chmod +x deploy.sh
./deploy.sh
```

Optional initial certificate request:

```bash
./deploy.sh --init-letsencrypt --email you@example.com
```

### 3. First login

After deployment:

- sign in with `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD`
- open `Settings -> System Settings`
- configure SMTP / IMAP / mail templates / AutoMail as needed
- optionally enable Roundcube in `.env`

For the full deployment flow, see `DeploymentGuide.md`.

## Environment Variables

Defaults below reflect `.env.example`.

### Required

- `SECRET_KEY`
- `INITIAL_ADMIN_PASSWORD`
- `BASE_URL`
- `DOMAIN`

### Core auth and session

- `INITIAL_ADMIN_USERNAME` default: `admin`
- `LOGIN_WINDOW_SECONDS` default: `900`
- `LOGIN_MAX_ATTEMPTS` default: `5`
- `MIN_PASSWORD_LENGTH` default: `10`
- `TOTP_ISSUER` default: `Lost & Found`
- `TRUSTED_PROXY_CIDRS` default: `127.0.0.1/32,::1/128,172.16.0.0/12`
- `SESSION_COOKIE_SECURE` default: `true`
- `SESSION_COOKIE_SAMESITE` default: `Lax`
- `SESSION_MAX_AGE_SECONDS` default: `28800`

### Uploads and public lost form

- `MAX_CONTENT_LENGTH` default: `20971520`
- `PUBLIC_LOST_WINDOW_SECONDS` default: `900`
- `PUBLIC_LOST_MAX_ATTEMPTS` default: `8`
- `PUBLIC_LOST_DAILY_MAX_ATTEMPTS` default: `30`
- `PUBLIC_LOST_MAX_FILES` default: `5`
- `PUBLIC_LOST_CAPTCHA_ENABLED` default: `true`
- `PUBLIC_TOKEN_VALIDITY_DAYS` default: `365`

### Data lifecycle

- `ITEM_RETENTION_MONTHS` default: `12`
- `AUDIT_RETENTION_DAYS` default: `180`
- `AUDIT_MAX_ROWS` default: `0`
- `AUDIT_REDACT_ENABLED` default: `true`

### Storage

- `DATA_DIR` default: `/app/data`
- `UPLOAD_DIR` default: `/app/uploads`

### App runtime

- `FLASK_DEBUG` default: `false`
- `SETTINGS_ENCRYPTION_KEY` recommended, required for encrypted SMTP password storage

### Roundcube

- `ROUNDCUBE_ENABLED` default: `false`
- `ROUNDCUBE_SHARED_SECRET`
- `ROUNDCUBE_DES_KEY`
- `ROUNDCUBE_EXTERNAL_URL` default: `/webmail/`
- `ROUNDCUBE_REQUEST_PATH` default: `/webmail/`
- `ROUNDCUBE_SSO_MAX_AGE_SECONDS` default: `900`

## Background Worker

The worker handles scheduled jobs outside HTTP requests:

- stale-item maintenance
- retention cleanup
- audit cleanup
- IMAP polling
- AutoMail sending

Useful commands:

```bash
python -m lfapp.cli run-maintenance
python -m lfapp.cli run-mail-poll
python -m lfapp.cli run-worker --once
python -m lfapp.cli run-worker --interval 60
```

## Operations Runbook

Common operational tasks:

### Check service health

```bash
docker compose ps
docker compose logs --tail=100 app
docker compose logs --tail=100 worker
docker compose logs --tail=100 nginx
```

If Roundcube is enabled:

```bash
docker compose logs --tail=100 roundcube
```

### Run maintenance manually

```bash
docker compose exec worker python -m lfapp.cli run-maintenance
```

### Run one IMAP poll manually

```bash
docker compose exec worker python -m lfapp.cli run-mail-poll
```

### Run one full worker cycle manually

```bash
docker compose exec worker python -m lfapp.cli run-worker --once
```

### Redeploy after changes

```bash
git pull origin main
./deploy.sh
```

### Reset the protected initial admin password

```bash
docker compose exec app python -m lfapp.cli reset-initial-admin-password
```

## Local Development

```bash
python -m pip install -r requirements-dev.txt
pytest -q
ruff check lfapp tests app.py
```

## Security Notes

- passwords are hashed with `scrypt`
- application secret encryption uses PBKDF2-based key derivation
- CSRF protection is enabled on POST routes
- app-side CSP is nonce-based
- session cookies are hardened
- login and public submission paths are rate-limited
- public links expire
- uploaded images are validated by content, not only by extension
- `.env` must never be committed

Roundcube note:

- the Roundcube surface has its own compatibility-oriented CSP requirements
- treat Roundcube as a separate webmail surface with its own operational risk profile

## Password Reset for `INITIAL_ADMIN`

Interactive:

```bash
docker compose exec app python -m lfapp.cli reset-initial-admin-password
```

Non-interactive:

```bash
docker compose exec app python -m lfapp.cli reset-initial-admin-password --password "YourNewStrongPassword"
```

## Documentation

- deployment: `DeploymentGuide.md`
- terminology and wording: `docs/STYLEGUIDE.md`

## Third-Party Software

- this project optionally integrates Roundcube Webmail
- Roundcube is licensed separately under `GPL-3.0-or-later`
- upstream: `https://github.com/roundcube/roundcubemail`
- when distributing with Roundcube enabled, keep upstream license and copyright notices

## Disclaimer

This project is provided without warranty. Use it at your own risk.
