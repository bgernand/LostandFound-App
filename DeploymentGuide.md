# 🚀 Deployment Guide --- Docker + Nginx + Let's Encrypt (Certbot)

This setup runs:

-   **Flask app** (Gunicorn) inside a container
-   **Nginx** as reverse proxy (ports 80/443)
-   **Certbot** for Let's Encrypt certificates + automatic renewal

------------------------------------------------------------------------

## 📋 Prerequisites

You need:

-   A server with **Docker** and **Docker Compose** installed
-   A domain name (e.g. `your-domain.example`)
-   DNS `A/AAAA` record pointing to your server's public IP
-   Firewall / security group allowing inbound:

  Port   Protocol
  ------ ----------
  80     TCP
  443    TCP

------------------------------------------------------------------------

## 📁 Create Required Directories

From your project root:

``` bash
mkdir -p nginx/templates
mkdir -p certbot/www certbot/conf

mkdir -p data uploads
sudo chown -R $USER:$USER data uploads
sudo chmod -R 755 data uploads
```

------------------------------------------------------------------------

## 🌐 Configure DOMAIN and BASE_URL

Edit `docker-compose.yml`:

### In the **nginx** service

    DOMAIN=your-domain.example

### In the **app** service

    BASE_URL=https://your-domain.example

> ⚠️ Important:\
> The QR code uses `BASE_URL` to generate public links.

------------------------------------------------------------------------

## ▶️ Start App & Nginx (Before Certificate)

Build and start:

``` bash
docker compose up -d --build app nginx
```

At this point:

-   Nginx listens on **port 80**
-   Serves ACME challenge path
-   ❌ HTTPS will NOT work yet (no certificate)

------------------------------------------------------------------------

## 🔐 Obtain Initial Let's Encrypt Certificate (One-Time)

Replace domain and email:

``` bash
docker compose run --rm --entrypoint certbot certbot certonly \
  --webroot -w /var/www/certbot \
  -d your-domain.example \
  --email you@your-domain.example \
  --agree-tos --no-eff-email \
  --cert-name your-domain.example
```

Reload nginx:

``` bash
docker compose exec nginx sh -lc '
  mkdir -p /etc/nginx/ssl-dummy/your-domain.example &&
  ln -sf /etc/letsencrypt/live/your-domain.example/fullchain.pem /etc/nginx/ssl-dummy/your-domain.example/fullchain.pem &&
  ln -sf /etc/letsencrypt/live/your-domain.example/privkey.pem   /etc/nginx/ssl-dummy/your-domain.example/privkey.pem &&
  nginx -s reload
'
```

### Common failure causes

-   DNS not propagated yet
-   Port 80 blocked by firewall
-   Another service already using port 80

------------------------------------------------------------------------

## 🔄 Restart Nginx

``` bash
docker compose restart nginx
```

Your site should now be available at:

    https://your-domain.example

------------------------------------------------------------------------

## ♻️ Automatic Certificate Renewal

The `certbot` service runs renewals every 12 hours.

Start it:

``` bash
docker compose up -d certbot
```

------------------------------------------------------------------------

## 🔄 Updating / Redeploying

After code changes:

``` bash
docker compose up -d --build app
docker compose restart nginx
```

------------------------------------------------------------------------

## 💾 Data Persistence

The following data is stored permanently:

  Type           Local               Container
  -------------- ------------------- ---------------------
  SQLite DB      `./lostfound.db`    `/app/lostfound.db`
  Uploads        `./uploads/`        `/app/uploads`
  Certificates   `./certbot/conf/`   `/etc/letsencrypt`
  ACME webroot   `./certbot/www/`    `/var/www/certbot`

### Recommended Backups

-   `lostfound.db`
-   `uploads/`
-   `certbot/conf/` *(optional but useful)*

------------------------------------------------------------------------

## 🧪 Quick Sanity Checks

### Running containers

``` bash
docker compose ps
```

### View logs

``` bash
docker compose logs -f nginx
docker compose logs -f app
docker compose logs -f certbot
```

------------------------------------------------------------------------

## ✅ Done

Your Flask application is now deployed with:

-   HTTPS encryption
-   Automatic certificate renewal
-   Persistent data storage
-   Production-ready reverse proxy
