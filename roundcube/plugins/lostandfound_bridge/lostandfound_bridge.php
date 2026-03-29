<?php

class lostandfound_bridge extends rcube_plugin
{
    public function init(): void
    {
        $rcmail = rcmail::get_instance();
        $this->register_action('plugin.lostandfound_bridge.login', [$this, 'login_action']);
        $this->add_hook('render_page', [$this, 'render_page']);
        if ($rcmail->task === 'mail') {
            $this->include_script('lostandfound_bridge.js');
        }
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

    private function fetch_sso_config(string $token): array
    {
        $rcmail = rcmail::get_instance();
        $url = rtrim((string) $rcmail->config->get('lostandfound_bridge_app_url'), '/') . '/api/roundcube/sso-config';
        $secret = (string) $rcmail->config->get('lostandfound_bridge_shared_secret');
        $body = json_encode(['token' => $token]);
        $headers = [
            'Content-Type: application/json',
            'X-Roundcube-Secret: ' . $secret,
        ];

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_TIMEOUT => 15,
            ]);
            $response = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
        } else {
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => implode("\r\n", $headers),
                    'content' => $body,
                    'timeout' => 15,
                    'ignore_errors' => true,
                ],
            ]);
            $response = @file_get_contents($url, false, $context);
            $status = 200;
        }

        if (!$response || $status >= 400) {
            $this->render_error('Lost & Found denied the Roundcube SSO request.');
        }

        $decoded = json_decode($response, true);
        if (!is_array($decoded)) {
            $this->render_error('Lost & Found returned invalid JSON for Roundcube SSO.');
        }

        return $decoded;
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
