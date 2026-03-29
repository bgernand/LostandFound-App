FROM roundcube/roundcubemail:latest

USER root

RUN mkdir -p /opt/lostfound-roundcube/config /opt/lostfound-roundcube/plugins/lostandfound_bridge /var/roundcube/db

COPY config/config.inc.php /opt/lostfound-roundcube/config/config.inc.php
COPY plugins/lostandfound_bridge /opt/lostfound-roundcube/plugins/lostandfound_bridge
COPY docker-entrypoint.sh /usr/local/bin/lostfound-roundcube-entrypoint.sh

RUN chmod +x /usr/local/bin/lostfound-roundcube-entrypoint.sh \
    && chown -R www-data:www-data /opt/lostfound-roundcube /var/roundcube/db

ENTRYPOINT ["/usr/local/bin/lostfound-roundcube-entrypoint.sh"]
