<?php

$config = [];
$config['db_dsnw'] = 'sqlite:////var/roundcube/db/roundcube.sqlite?mode=0646';
$config['default_host'] = 'ssl://invalid.local';
$config['smtp_server'] = '';
$config['support_url'] = '';
$config['product_name'] = 'Lost & Found Webmail';
$config['des_key'] = getenv('ROUNDCUBE_DES_KEY') ?: hash('sha256', getenv('ROUNDCUBE_SHARED_SECRET') ?: 'lostfound-roundcube');
$config['plugins'] = ['archive', 'zipdownload', 'lostandfound_bridge'];
$config['skin'] = 'elastic';
$config['language'] = 'en_US';
$config['language_selector'] = false;
$config['enable_installer'] = false;
$config['session_lifetime'] = 28800;
$config['log_driver'] = 'stdout';
$config['lostandfound_bridge_app_url'] = rtrim(getenv('LAF_APP_INTERNAL_URL') ?: 'http://app:8000', '/');
$config['lostandfound_bridge_shared_secret'] = getenv('ROUNDCUBE_SHARED_SECRET') ?: '';
