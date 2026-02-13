# Deployment Guide (Debian/Linux)

This guide deploys the app with Docker Compose, Nginx, and Certbot.

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
