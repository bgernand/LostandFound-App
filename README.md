"# LostandFound-App" 

lostandfound/
├─ app.py
├─ requirements.txt
├─ Dockerfile
├─ docker-compose.yml
├─ templates/
│  ├─ base.html
│  ├─ login.html
│  ├─ index.html
│  ├─ form.html
│  ├─ detail.html
│  ├─ receipt.html
│  ├─ public_detail.html
│  ├─ users.html
│  ├─ audit.html
│  └─ categories.html
├─ nginx/
│  ├─ Dockerfile
│  ├─ entrypoint.sh
│  └─ templates/
│     └─ default.conf.template
├─ certbot/
│  ├─ www/        (ACME webroot)
│  └─ conf/       (Let’s Encrypt data)
├─ data/          (SQLite DB)
└─ uploads/       (item photos)
