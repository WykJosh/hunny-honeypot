<?php

require_once __DIR__ . '/../config.php';

$raw = file_get_contents('php://input');
parse_str($raw, $data);

log_honeypot('honeyPotAdmin_beacon', 'honeyPotAdmin', [
    'mouse_moves' => (int)($data['moves'] ?? 0),
    'keystrokes'  => (int)($data['keys'] ?? 0),
    'time_on_page_ms' => (int)($data['time'] ?? 0),
]);

http_response_code(204); // No content
