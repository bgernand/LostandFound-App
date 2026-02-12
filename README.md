"# LostandFound-App" 


Project Tree

lostfound/
  app.py
  requirements.txt
  dockerfile
  docker-compose.yml

  lostfound.db            # wird angelegt/weiterverwendet (Volume)
  uploads/                # Upload-Ordner (Volume)

  nginx/
    templates/
      default.conf.template

  certbot/
    conf/                 # Let’s Encrypt Zertifikate (Volume)
    www/                  # ACME webroot (Volume)

  templates/
    base.html
    login.html
    index.html
    form.html
    detail.html
    receipt.html
    public_detail.html
    users.html
    audit.html
