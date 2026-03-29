<?php

class lostandfound_bridge extends rcube_plugin
{
    public function init(): void
    {
        $rcmail = rcmail::get_instance();
        $this->register_action('plugin.lostandfound_bridge.login', [$this, 'login_action']);
        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('render_page', [$this, 'render_page']);
        $this->add_hook('logout_after', [$this, 'logout_after']);
        if ($rcmail->task === 'mail') {
            $this->include_script('lostandfound_bridge.js');
        }
    }

    public function startup(array $args): array
    {
        $rcmail = rcmail::get_instance();
        $task = (string) ($args['task'] ?? '');
        $action = (string) ($args['action'] ?? '');

        if ($task === 'login' && $action === 'plugin.lostandfound_bridge.login') {
            $this->login_action();
        }
        if (!$rcmail->user) {
            $this->redirect_to_webmail_entry();
        }

        return $args;
    }

    public function login_action(): void
    {
        $token = rcube_utils::get_input_value('_laf_token', rcube_utils::INPUT_GPC);
        if (!$token) {
            $this->render_error('Missing Lost & Found SSO token.');
        }

        $payload = $this->fetch_sso_config($token);
        if (empty($payload['ok']) || empty($payload['imap'])) {
            $this->render_error('Lost & Found did not return valid Roundcube login data.');
        }

        $imap = $payload['imap'];
        $host = trim(($imap['use_ssl'] ? 'ssl://' : '') . ($imap['host'] ?? ''));
        $user = trim($imap['username'] ?? '');
        $pass = (string) ($imap['password'] ?? '');
        if (!$host || !$user || !$pass) {
            $this->render_error('Mailbox settings are incomplete in Lost & Found.');
        }

        $rcmail = rcmail::get_instance();
        $result = $rcmail->login($user, $pass, $host);
        if (!$result) {
            $this->render_error('Roundcube could not authenticate against IMAP using the configured mailbox data.');
        }

        $_SESSION['lostandfound_bridge'] = [
            'unassigned_folder' => trim((string) ($imap['unassigned_folder'] ?? 'ToDo')) ?: 'ToDo',
            'app_user' => $payload['app_user'] ?? [],
        ];

        header('Location: ./?_task=mail&_mbox=' . rawurlencode($_SESSION['lostandfound_bridge']['unassigned_folder']));
        exit;
    }

    public function render_page(array $args): array
    {
        $rcmail = rcmail::get_instance();
        if ($rcmail->task !== 'mail') {
            return $args;
        }

        $bridge = $_SESSION['lostandfound_bridge'] ?? [];
        $runtime = $this->fetch_runtime_config();
        if (!empty($runtime['imap']['unassigned_folder'])) {
            $bridge['unassigned_folder'] = trim((string) $runtime['imap']['unassigned_folder']) ?: ($bridge['unassigned_folder'] ?? 'ToDo');
            $_SESSION['lostandfound_bridge'] = $bridge;
        }
        $rcmail->output->set_env('laf_bridge', [
            'enabled' => !empty($bridge),
            'unassigned_folder' => trim((string) ($bridge['unassigned_folder'] ?? 'ToDo')) ?: 'ToDo',
            'app_user' => $bridge['app_user'] ?? [],
            'assign_url' => '/roundcube/bridge/assign',
            'create_lost_url' => '/roundcube/bridge/start-create/lost',
            'create_found_url' => '/roundcube/bridge/start-create/found',
        ]);

        return $args;
    }

    public function logout_after(array $args): array
    {
        $target = $this->dashboard_url();
        header('Location: ' . $target);
        exit;
    }

    private function fetch_sso_config(string $token): array
    {
        [$response, $status] = $this->http_get(
            '/api/roundcube/sso-config?token=' . rawurlencode($token)
        );

        if (!$response || $status >= 400) {
            $this->render_error('Lost & Found denied the Roundcube SSO request.');
        }

        $decoded = json_decode($response, true);
        if (!is_array($decoded)) {
            $this->render_error('Lost & Found returned invalid JSON for Roundcube SSO.');
        }

        return $decoded;
    }

    private function fetch_runtime_config(): array
    {
        [$response, $status] = $this->http_get('/api/roundcube/runtime-config');
        if (!$response || $status >= 400) {
            return [];
        }

        $decoded = json_decode($response, true);
        return is_array($decoded) ? $decoded : [];
    }

    private function http_get(string $path): array
    {
        $rcmail = rcmail::get_instance();
        $url = rtrim((string) $rcmail->config->get('lostandfound_bridge_app_url'), '/') . $path;
        $secret = (string) $rcmail->config->get('lostandfound_bridge_shared_secret');
        $headers = [
            'X-Roundcube-Secret: ' . $secret,
        ];

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_TIMEOUT => 15,
            ]);
            $response = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            return [$response, $status];
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => implode("\r\n", $headers) . "\r\n",
                'timeout' => 15,
                'ignore_errors' => true,
            ],
        ]);
        $response = @file_get_contents($url, false, $context);
        $status = 0;
        if (!empty($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
            $status = (int) $m[1];
        }

        return [$response, $status];
    }

    private function app_base_url(): string
    {
        $rcmail = rcmail::get_instance();
        return rtrim((string) $rcmail->config->get('lostandfound_bridge_base_url'), '/');
    }

    private function dashboard_url(): string
    {
        $base = $this->app_base_url();
        return ($base ?: '') . '/dashboard';
    }

    private function webmail_entry_url(): string
    {
        $base = $this->app_base_url();
        return ($base ?: '') . '/webmail-login';
    }

    private function redirect_to_webmail_entry(): void
    {
        $target = $this->webmail_entry_url();
        if (!$target) {
            $this->render_login_notice();
        }
        header('Location: ' . $target);
        exit;
    }

    private function render_login_notice(): void
    {
        http_response_code(200);
        $entryUrl = $this->webmail_entry_url();
        $dashboardUrl = $this->dashboard_url();
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8">';
        echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<title>Open Webmail from Lost &amp; Found</title>';
        echo '<style>';
        echo 'body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f3f5f7;color:#1f2933;}';
        echo '.wrap{max-width:640px;margin:10vh auto;padding:24px;}';
        echo '.card{background:#fff;border:1px solid #d8dee4;border-radius:12px;padding:28px;box-shadow:0 8px 30px rgba(15,23,42,.08);}';
        echo 'h1{margin:0 0 12px;font-size:28px;line-height:1.2;}';
        echo 'p{margin:0 0 14px;line-height:1.6;}';
        echo '.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px;}';
        echo '.btn{display:inline-block;padding:10px 16px;border-radius:8px;text-decoration:none;font-weight:600;}';
        echo '.btn-primary{background:#0f766e;color:#fff;}';
        echo '.btn-secondary{background:#fff;color:#1f2933;border:1px solid #cbd2d9;}';
        echo '</style></head><body><main class="wrap"><section class="card">';
        echo '<h1>Open Webmail from Lost &amp; Found</h1>';
        echo '<p>Direct Roundcube login is disabled in this setup.</p>';
        echo '<p>Open Webmail from Lost &amp; Found so the mailbox session is created with the configured mailbox credentials.</p>';
        echo '<div class="actions">';
        echo '<a class="btn btn-primary" href="' . htmlspecialchars($entryUrl, ENT_QUOTES, 'UTF-8') . '">Open Webmail</a>';
        echo '<a class="btn btn-secondary" href="' . htmlspecialchars($dashboardUrl, ENT_QUOTES, 'UTF-8') . '">Back to Dashboard</a>';
        echo '</div></section></main></body></html>';
        exit;
    }

    private function render_error(string $message): void
    {
        http_response_code(500);
        echo '<!doctype html><html><head><meta charset="utf-8"><title>Roundcube bridge error</title></head><body>';
        echo '<h1>Roundcube bridge error</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>';
        echo '</body></html>';
        exit;
    }
}
