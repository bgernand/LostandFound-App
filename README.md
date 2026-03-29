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
- Role model with granular permissions: `admin`, `staff`, `found-staff`, `lost-staff`, `viewer`
- Improved search with token expansion, synonym support, and phonetic (`soundex`) matching
- Optional per-user 2FA with TOTP (authenticator app)
- Admin controls for TOTP mandatory mode and per-user 2FA reset
- Manual SMTP e-mail sending from Lost Request detail view to requester address
- Mail composer popup with admin-managed templates, variable rendering, and optional receipt PDF attachment
- Ticket-style mail thread per item with outbound/inbound history, reference tagging, optional IMAP polling, and Roundcube filing
- Description quality validation with live form feedback and admin-managed blacklist extension
- Public Lost submission page (`/report/lost`) without login
- Dedicated Lost Review Queue with mass-processing flow (`Reviewed & Next`)
- Optional confirmation e-mail to requester after public lost submission (configurable template with preview in `Settings -> System Settings`)

## Status Behavior
- Available statuses: `Lost`, `Maybe Found -> Check`, `Found`, `Waiting for answer`, `Answer received`, `Ready to send`, `Handed over / Sent`, `Lost forever`
- New items are always created with default status `Lost` (independent of type)
- When a link is created between items, all items in the linked graph are set to `Found`
- Changing the status of one linked item synchronizes that status to all linked items
- Daily automatic maintenance sets `Lost` items to `Lost forever` when `event_date` is older than 90 days
- Daily automatic maintenance deletes items after a configurable number of months without updates (`ITEM_RETENTION_MONTHS`, default `12`)

## Roles and Permissions
- `admin`: full access, including user/category admin, mail template management, and destructive actions
- `staff`: operational write access across Lost and Found items, reminders, bulk actions, links, and public review
- `found-staff`: create and edit Found items only
- `lost-staff`: create and edit Lost items, view personal data, and send mail
- `viewer`: read-only access based on explicit `items.view_lost` / `items.view_found` permissions
- Mail template management is restricted to admins. Mail usage itself is available to all roles with `items.send_email`.

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
- A follow-up reminder is generated automatically when an item stays in `Waiting for answer` for more than 7 days without updates.
- Open reminders are shown on the dashboard and as a warning on the items overview.
- Staff/admin can mark reminders as done.

## Mail Ticket Workflow
- The workflow is configured in `Settings -> System Settings -> Mail Ticket Workflow`.
- The built-in mailbox UI was removed. Webmail access now runs through Roundcube under `/webmail/`.
- Outgoing Lost Request mails are tagged with a reference in the subject using the schema `[LFT-<public_id>]`.
- When ticket workflow is enabled:
  - sending a mail sets the item status to `Waiting for answer`
  - incoming replies are fetched from IMAP, matched by reference, and added to the item thread
  - received replies set the item status to `Answer received`
  - outgoing messages are appended to the IMAP sent folder (default `LostFound/Send`)
  - processed incoming messages are moved to the IMAP processed folder (default `LostFound/Proceeded`)
  - incoming messages without a valid ticket reference are moved to the IMAP unassigned folder (default `ToDo`)
  - unassigned messages are handled in Roundcube with Lost & Found bridge actions: `Create Lost`, `Create Found`, `Assign to Existing Item`
- The item detail page shows the complete mail thread (incoming and outgoing).

## Public Lost Submission + Review
- Public users can submit a new `Lost Request` via `/report/lost`.
- Public submission always creates:
  - `kind = lost`
  - `status = Lost`
  - `review_pending = 1`
- Public form excludes `Price of postage` and `Paid`.
- Staff with permission `items.review` process queue items in:
  - `Lost Reviews` (menu) / `/reviews/lost`
- Review workflow is optimized for throughput:
  - always edit mode
  - `Reviewed & Next` marks current entry reviewed and opens the next pending one.

## Quality and CI
- Tests are split by domain in `tests/` with shared fixtures in `tests/conftest.py`.
- GitHub Actions CI runs a create_app factory smoke check, `pytest`, and `ruff` on push and pull request (`.github/workflows/ci.yml`).
- Local development dependencies live in `requirements-dev.txt`.

## Tech Stack
- Flask 3
- SQLite
- Gunicorn
- Background worker container (`python -m lfapp.cli run-worker`)
- Nginx (reverse proxy, TLS termination)
- Certbot (Let's Encrypt renewal)
- Docker Compose

## Project Structure
```text
.
├─ app.py                    # compatibility entry-point (app factory: create_app -> app)
├─ lfapp/
│  ├─ __init__.py
│  ├─ main.py                # app factory + dependency wiring
│  ├─ cli.py                 # maintenance / worker CLI
│  ├─ db_utils.py            # db/schema/maintenance helpers
│  ├─ worker_tasks.py        # scheduled maintenance + mailbox poll orchestration
│  ├─ totp_utils.py          # TOTP helper logic
│  ├─ match_utils.py         # matching/search helper logic
│  ├─ link_match_utils.py    # item link + matching db helpers
│  ├─ security_utils.py      # login/security helper logic
│  ├─ filter_utils.py        # filter/saved-search helper logic
│  ├─ category_utils.py      # category repository helpers
│  ├─ auth_core.py           # current_user/login_required/require_role/audit helpers
│  ├─ routes_auth.py         # auth/account route registration
│  ├─ routes_admin.py        # admin route registration (users/audit/categories)
│  ├─ routes_overview.py     # dashboard/index/matches/saved-search routes
│  ├─ routes_items.py        # item/detail/public/export route registration
│  └─ item_form_utils.py     # item form parsing/validation helpers
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
  - root `app.py` stays as a compatibility shim calling `create_app()` for Gunicorn/tests (`app:app`)
  - `lfapp.main.create_app(config=None)` supports optional config overrides (useful for tests)
- Additional helper modules extracted:
  - `lfapp/db_utils.py`
  - `lfapp/cli.py`
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
This starts `app`, `worker`, `nginx`, and `certbot`.
4. Optional: request initial Let's Encrypt certificate:
```bash
./deploy.sh --init-letsencrypt --email you@example.com
```

## Environment Variables
- `SECRET_KEY` (required)
- `INITIAL_ADMIN_USERNAME` (default: `admin`)
- `INITIAL_ADMIN_PASSWORD` (required on first startup)
- `BASE_URL` (required, e.g. `https://lostfound.example`)
- `DOMAIN` (required for deployment/nginx/certbot, e.g. `lostfound.example`)
- `LOGIN_WINDOW_SECONDS` (optional, default `900`)
- `LOGIN_MAX_ATTEMPTS` (optional, default `5`)
- `MIN_PASSWORD_LENGTH` (optional, default `10`)
- `TOTP_ISSUER` (optional, default `Lost & Found`)
- `TRUSTED_PROXY_CIDRS` (optional, default `127.0.0.1/32,::1/128,172.16.0.0/12`)
- `SESSION_COOKIE_SECURE` (optional, default `true`)
- `SESSION_COOKIE_SAMESITE` (optional, default `Lax`)
- `SESSION_MAX_AGE_SECONDS` (optional, default `28800` = 8h absolute login session max age)
- `MAX_CONTENT_LENGTH` (optional, default `20971520`)
- `PUBLIC_LOST_WINDOW_SECONDS` (optional, default `900`)
- `PUBLIC_LOST_MAX_ATTEMPTS` (optional, default `8`)
- `PUBLIC_LOST_DAILY_MAX_ATTEMPTS` (optional, default `30`)
- `PUBLIC_LOST_MAX_FILES` (optional, default `5`)
- `PUBLIC_LOST_CAPTCHA_ENABLED` (optional, default `false`)
- `ITEM_RETENTION_MONTHS` (optional, default `12`; automatic item deletion after N months without updates, `0` disables it)
- `DATA_DIR` (optional, default `/app/data`; Docker Compose sets it internally)
- `UPLOAD_DIR` (optional, default `/app/uploads`; Docker Compose sets it internally)
- `FLASK_DEBUG` (optional, default `false`; local development only)
- `AUDIT_RETENTION_DAYS` (optional, default `180`; `0` disables age-based audit cleanup)
- `AUDIT_MAX_ROWS` (optional, default `200000`; `0` disables count-based audit cleanup)
- `AUDIT_REDACT_ENABLED` (optional, default `true`; redacts sensitive snapshots in audit log)
- `SETTINGS_ENCRYPTION_KEY` (optional but recommended; required to store SMTP password encrypted in DB)
- `ROUNDCUBE_ENABLED` (optional, default `false`; enables the Roundcube webmail bridge and menu entry)
- `ROUNDCUBE_SHARED_SECRET` (optional but recommended; shared secret between app and Roundcube plugin)
- `ROUNDCUBE_DES_KEY` (optional; dedicated Roundcube secret, otherwise derived from `ROUNDCUBE_SHARED_SECRET`)
- `ROUNDCUBE_EXTERNAL_URL` (optional, default `/webmail/`)

## Background Worker
- Scheduled maintenance and mail polling run in the separate `worker` container, not inside web requests.
- Available CLI commands:
```bash
python -m lfapp.cli run-maintenance
python -m lfapp.cli run-mail-poll
python -m lfapp.cli run-worker --once
python -m lfapp.cli run-worker --interval 60
```

## Database Migrations
- SQLite migrations are versioned via `PRAGMA user_version`.
- Startup upgrades legacy databases in place, including foreign-key cascade fixes and item-search rebuilds.

## Local Development
```bash
python -m pip install -r requirements-dev.txt
pytest -q
ruff check lfapp tests app.py
```

## Security Notes
- CSRF protection is enabled for POST routes.
- Open redirect on login is blocked.
- Brute-force protection for login attempts is enabled.
- Public `/report/lost` has IP-based submission rate limits, honeypot, and optional captcha.
- Optional TOTP-based 2FA is supported, including global mandatory mode.
- No default fallback `SECRET_KEY` is used.
- Session cookies are hardened (`Secure`, `HttpOnly`, `SameSite`).
- Session uses browser-session cookies plus an app-side absolute max age (`SESSION_MAX_AGE_SECONDS`, default 8h).
- Optional SMTP integration allows sending manual update e-mails from Lost Request detail pages; configure in `Settings -> System Settings`.
- Mail ticket workflow and IMAP polling are configured in `Settings -> System Settings`, not in `.env`.
- Roundcube can be enabled via `.env` and uses the mailbox settings stored in `Settings -> System Settings -> Mail`.
- Item mail templates are managed in `Settings -> System Settings` and support variables such as `{{ item_id }}`, `{{ title }}`, `{{ status }}`, `{{ full_name }}`, `{{ receipt_no }}`, and `{{ public_url }}`.
- Item mail templates also support `{{ ticket_ref }}` when mail ticket workflow is enabled.
- The mail composer popup on Lost Request detail pages can optionally attach the current Receipt PDF to the outgoing mail.
- IMAP credentials can be stored encrypted in settings when `SETTINGS_ENCRYPTION_KEY` is configured.
- Description quality defaults and blacklist extension are managed in `Settings -> System Settings`.
- Audit log stores action context plus structured before/after snapshots for critical changes (items/users/roles/settings/categories).
- Audit snapshot redaction is enabled by default for sensitive keys (contact/address/token/secret fields).
- Daily audit rotation runs automatically (age + max-row cap configurable by `.env`).
- Client IP extraction for login limits and audit is trusted-proxy aware (`TRUSTED_PROXY_CIDRS`).
- SMTP password in system settings is stored encrypted (requires `SETTINGS_ENCRYPTION_KEY`).
- Security headers are set at Nginx level (HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy).
- `.env` must never be committed; rotate secrets immediately if exposure is suspected.
- Daily automatic maintenance updates stale `Lost` items (`event_date` older than 90 days) to `Lost forever`.
- Daily automatic maintenance also deletes items with no changes for `ITEM_RETENTION_MONTHS` months and removes related photos, links, reminders, and mail records.

## Reset INITIAL_ADMIN Password (Console)
If you no longer know the password of the protected `INITIAL_ADMIN` account, reset it from console:

```bash
docker compose exec app python -m lfapp.cli reset-initial-admin-password
```

Optional non-interactive mode:

```bash
docker compose exec app python -m lfapp.cli reset-initial-admin-password --password 'YourNewStrongPassword'
```

Notes:
- The command targets `INITIAL_ADMIN` (`is_root_admin=1`).
- It enforces role `admin` and re-activates the account.

## Documentation
- Deployment details: `DeploymentGuide.md`

## Disclaimer
This project is provided without any warranty. No liability is assumed for any direct or indirect damages, data loss, outages, or any other consequences resulting from the use, operation, or distribution of this software. Use of this software is entirely at your own risk.








