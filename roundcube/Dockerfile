FROM roundcube/roundcubemail:latest

USER root

RUN mkdir -p /opt/lostfound-roundcube/config /usr/src/roundcubemail/plugins/lostandfound_bridge /var/roundcube/db /var/roundcube/sessions

COPY config/config.inc.php /opt/lostfound-roundcube/config/config.inc.php
COPY plugins/lostandfound_bridge /usr/src/roundcubemail/plugins/lostandfound_bridge
COPY docker-entrypoint.sh /usr/local/bin/lostfound-roundcube-entrypoint.sh
COPY php/lostfound-roundcube.ini /usr/local/etc/php/conf.d/zz-lostfound-roundcube.ini

RUN chmod +x /usr/local/bin/lostfound-roundcube-entrypoint.sh \
    && chown -R www-data:www-data /opt/lostfound-roundcube /usr/src/roundcubemail/plugins/lostandfound_bridge /var/roundcube/db /var/roundcube/sessions

ENTRYPOINT ["/usr/local/bin/lostfound-roundcube-entrypoint.sh"]
