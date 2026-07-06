<?php


// The DB password is loaded from /etc/honeypot/db.env at runtime

// ---- Load the DB password ---------
$envFile = '/etc/honeypot/db.env';
if (is_readable($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if ($line === '' || $line[0] === '#') continue;
        [$k, $v] = array_pad(explode('=', $line, 2), 2, '');
        putenv("$k=$v");
        $_ENV[$k] = $v;
    }
}

// defining constants
define('DB_HOST', '127.0.0.1');
define('DB_NAME', getenv('DB_NAME') ?: 'honeypot');
define('DB_USER', getenv('DB_USER') ?: 'hunny_app');
define('DB_PASS', getenv('DB_PASS') ?: '');

define('UPLOAD_DIR', __DIR__ . '/uploads/'); // avatars saved here
define('UPLOAD_URL', '/uploads/');
define('MAX_AVATAR_SIZE', 2 * 1024 * 1024);         // 2 MB upload limit - used in profile.php
define('ALLOWED_IMAGE_TYPES', ['image/jpeg', 'image/png',  'image/webp']);

// Password policy
define('PASSWORD_MIN_LENGTH', 12);
define('PASSWORD_REQUIRE_UPPER',   true);
define('PASSWORD_REQUIRE_LOWER',   true);
define('PASSWORD_REQUIRE_NUMBER',  true);
define('PASSWORD_REQUIRE_SPECIAL', true);

// ---- Session cookie hardening -----------

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Lax',
]);
ini_set('session.use_strict_mode', '1');

// ---- Database -----------------
function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        try {
            $pdo = new PDO(
                'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                ]
            );
        } catch (PDOException $e) {
            error_log('DB connection failed: ' . $e->getMessage());
            die('Database unavailable. Please try again later.');
        }
    }
    return $pdo;
}

// ---- Application event logging -----------------
function log_event(string $type, ?int $userId, string $usernameAttempted = '', string $details = ''): void
{
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $ip = trim(explode(',', $ip)[0]);
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    try {
        $stmt = db()->prepare(
            'INSERT INTO activity_log (event_type, user_id, username_attempted, ip_address, user_agent, details)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([$type, $userId, $usernameAttempted, $ip, $ua, $details]);
    } catch (PDOException $e) {
        error_log('log_event failed: ' . $e->getMessage());
    }
    // Mirror to a JSON line file so Filebeat ships it to Elasticsearch
    $jsonLog = [
        '@timestamp' => date('c'),
        'app'        => 'hunny-todo',
        'event'      => $type,
        'user_id'    => $userId,
        'username'   => $usernameAttempted,
        'source_ip'  => $ip,
        'user_agent' => $ua,
        'details'    => $details,
    ];
    @file_put_contents(
        '/var/log/hunny/app.log',
        json_encode($jsonLog, JSON_UNESCAPED_SLASHES) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

// ---- Honeypot trap logging --------------------
function log_honeypot(string $trapName, string $layer, array $extra = []): void
{
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $forwarded = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
        if (filter_var($forwarded, FILTER_VALIDATE_IP)) {
            $ip = $forwarded;
        }
    }
    $ip = trim(explode(',', $ip)[0]);

    $data = array_merge([
        'post_data'    => $_POST,
        'cookies'      => $_COOKIE,
        'query_string' => $_SERVER['QUERY_STRING'] ?? '',
        'all_headers'  => function_exists('getallheaders') ? getallheaders() : [],
        'detected_tool' => detect_tool($_SERVER['HTTP_USER_AGENT'] ?? ''),
    ], $extra);

    try {
        $stmt = db()->prepare(
            'INSERT INTO honeypot_log (trap_name, layer, source_ip, method, request_uri, user_agent, referer, details)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            $trapName,
            $layer,
            $ip,
            $_SERVER['REQUEST_METHOD'] ?? '',
            $_SERVER['REQUEST_URI'] ?? '',
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_REFERER'] ?? '',
            json_encode($data, JSON_UNESCAPED_SLASHES),
        ]);
    } catch (PDOException $e) {
        error_log('log_honeypot failed: ' . $e->getMessage());
    }

    // Mirror to a JSON line file that Filebeat picks up
    $jsonLog = [
        '@timestamp' => date('c'),
        'app'        => 'hunny-honeypot',
        'trap_name'  => $trapName,
        'layer'      => $layer,
        'source_ip'  => $ip,
        'method'     => $_SERVER['REQUEST_METHOD'] ?? '',
        'uri'        => $_SERVER['REQUEST_URI'] ?? '',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'referer'    => $_SERVER['HTTP_REFERER'] ?? '',
        'details'    => $data,
    ];
    @file_put_contents(
        '/var/log/hunny/honeypot.log',
        json_encode($jsonLog, JSON_UNESCAPED_SLASHES) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

// ---- Detect common attack-tool signatures ----------
function detect_tool(string $ua): string
{
    $signatures = [
        'sqlmap'          => 'sqlmap',
        'nikto'           => 'nikto',
        'gobuster'        => 'gobuster',
        'dirbuster'       => 'dirbuster',
        'feroxbuster'     => 'feroxbuster',
        'ffuf'            => 'ffuf',
        'wfuzz'           => 'wfuzz',
        'burp'            => 'burpsuite',
        'nmap'            => 'nmap',
        'masscan'         => 'masscan',
        'hydra'           => 'hydra',
        'medusa'          => 'medusa',
        'wpscan'          => 'wpscan',
        'curl/'           => 'curl',
        'python-requests' => 'python-requests',
        'wget/'           => 'wget',
        'zaproxy'         => 'owasp-zap',
        'zgrab'           => 'zgrab',
    ];
    $uaLower = strtolower($ua);
    foreach ($signatures as $sig => $tool) {
        if (str_contains($uaLower, $sig)) return $tool;
    }
    return '';
}

// ---- Session / Auth -----------------
function current_user(): ?array
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    return $_SESSION['user'] ?? null;
}

function require_login(): array
{
    $user = current_user();
    if (!$user) {
        header('Location: /login.php');
        exit;
    }
    if (!$user['is_enabled']) {
        session_destroy();
        header('Location: /login.php?error=disabled');
        exit;
    }
    return $user;
}

function require_admin(): array
{
    $user = require_login();
    if (!$user['is_admin']) {
        log_event(
            'ADMIN_ACCESS_DENIED',
            $user['id'],
            $user['username'],
            json_encode(['attempted_url' => $_SERVER['REQUEST_URI'] ?? ''])
        );
        header('Location: /index.php');
        exit;
    }
    return $user;
}

// ---- Output escaping ------------
function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ---- CSRF tokens -------------------
function csrf_token(): string
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(string $token): bool
{
    return hash_equals(csrf_token(), $token);
}

// ---- Password validation --------------------
function validate_password(string $password): string
{
    if (strlen($password) < PASSWORD_MIN_LENGTH)
        return 'Password must be at least ' . PASSWORD_MIN_LENGTH . ' characters.';
    if (PASSWORD_REQUIRE_UPPER && !preg_match('/[A-Z]/', $password))
        return 'Password must contain at least one uppercase letter (A-Z).';
    if (PASSWORD_REQUIRE_LOWER && !preg_match('/[a-z]/', $password))
        return 'Password must contain at least one lowercase letter (a-z).';
    if (PASSWORD_REQUIRE_NUMBER && !preg_match('/[0-9]/', $password))
        return 'Password must contain at least one number (0-9).';
    if (PASSWORD_REQUIRE_SPECIAL && !preg_match('/[\W_]/', $password))
        return 'Password must contain at least one special character (!@#$%...).';
    return '';
}

// ---- JWT authentication helper ----
require_once __DIR__ . '/includes/jwt.php';
