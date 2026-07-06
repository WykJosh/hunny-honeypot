<?php
// catches requests to fake paths from robots.txt
// gets routed here by Nginx. Logs the attempt and returns 403

require_once __DIR__ . '/config.php';

$uri = $_SERVER['REQUEST_URI'] ?? '/unknown';

log_honeypot('trap_path_access', 'trap', [
    'trapped_path' => $uri,
]);

http_response_code(403);
header('Server: Nginx/1.27 (Debian)');
header('X-Powered-By: PHP/8.2');
?>
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>

<head>
    <title>403 Forbidden</title>
</head>

<body>
    <h1>Forbidden</h1>
    <p>You don't have permission to access <?= htmlspecialchars($uri) ?>
        on this server.</p>
    <hr>
    <address>Nginx/1.27 (Debian) Server at <?= htmlspecialchars($_SERVER['HTTP_HOST'] ?? 'localhost') ?> Port 80</address>
</body>

</html>