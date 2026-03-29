FROM roundcube/roundcubemail:latest

USER root

RUN mkdir -p /var/roundcube/db /var/roundcube/plugins/lostandfound_bridge

COPY config/config.inc.php /var/roundcube/config/config.inc.php
COPY plugins/lostandfound_bridge /var/roundcube/plugins/lostandfound_bridge

RUN chown -R www-data:www-data /var/roundcube/db /var/roundcube/plugins/lostandfound_bridge /var/roundcube/config/config.inc.php

USER www-data
