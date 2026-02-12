Deployment guide (English): Docker + Nginx + Let’s Encrypt (Certbot)

This setup runs:

Flask app (Gunicorn) in one container

Nginx as reverse proxy (ports 80/443)

Certbot for Let’s Encrypt certificates + automatic renewal

1) Prerequisites

A server with Docker and Docker Compose installed

A domain name, e.g. your-domain.example

DNS A/AAAA record pointing to your server’s public IP

Firewall/security group allows inbound:

80/tcp

443/tcp

2) Create required directories

From your project root:

mkdir -p uploads
mkdir -p nginx/templates
mkdir -p certbot/www certbot/conf

3) Set your DOMAIN and BASE_URL

Edit docker-compose.yml:

In the nginx service:

DOMAIN=your-domain.example

In the app service:

BASE_URL=https://your-domain.example

This is important because the QR code uses BASE_URL to generate public links.

4) Start the app and Nginx (before requesting the cert)

Build and start:

docker compose up -d --build app nginx


At this point:

Nginx listens on port 80 and serves the ACME challenge path.

HTTPS won’t work yet (no certificate).

5) Obtain the initial Let’s Encrypt certificate (one-time)

Run Certbot (replace domain + email):

docker compose run --rm certbot certonly \
  --webroot -w /var/www/certbot \
  -d your-domain.example \
  --email you@your-domain.example \
  --agree-tos --no-eff-email


If this fails, the most common causes are:

DNS not pointing correctly yet

Port 80 blocked by firewall

Another service already using port 80

6) Restart Nginx to load the certificate
docker compose restart nginx


Now your site should be available at:

https://your-domain.example

7) Start automatic certificate renewal

The certbot service in docker-compose.yml runs renewals every 12 hours. Start it:

docker compose up -d certbot

8) Updating / redeploying later

After code changes:

docker compose up -d --build app
docker compose restart nginx

9) Data persistence

This setup persists:

SQLite database: ./lostfound.db ↔ /app/lostfound.db

Uploaded photos: ./uploads/ ↔ /app/uploads

Certificates: ./certbot/conf/ and ACME webroot: ./certbot/www/

Back up at minimum:

lostfound.db

uploads/

certbot/conf/ (optional but useful)

10) Quick sanity checks

Check running containers:

docker compose ps


View logs:

docker compose logs -f nginx
docker compose logs -f app
docker compose logs -f certbot