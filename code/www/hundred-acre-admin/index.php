<?php
// LAYER 2 /hundred-acre-admin/

require_once __DIR__ . '/../config.php';

if (session_status() === PHP_SESSION_NONE) session_start();

// Log every visit
log_honeypot('honeyPotAdmin_login_page', 'honeyPotAdmin');

$error = '';

// Handle logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    unset($_SESSION['hp_admin_auth'], $_SESSION['hp_admin_user'], $_SESSION['hp_request_count']);
    log_honeypot('honeyPotAdmin_logout', 'honeyPotAdmin');
    header('Location: /hundred-acre-admin/');
    exit;
}

if (!empty($_SESSION['hp_admin_auth'])) {
    header('Location: /hundred-acre-admin/dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF
    if (!isset($_POST['_token']) || !hash_equals($_SESSION['hp_csrf'] ?? '', $_POST['_token'] ?? '')) {
        $error = 'Session expired. Please try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        log_honeypot('honeyPotAdmin_login_attempt', 'honeyPotAdmin', [
            'username_tried' => $username,
            'password_tried' => $password,
        ]);

        log_event(
            'HONEYPOT_L2_LOGIN',
            null,
            $username,
            json_encode(['password_tried' => $password, 'layer' => 'honeyPotAdmin'])
        );

        // inject their attempts into the fake user table
        $_SESSION['hp_seen_usernames'] = $_SESSION['hp_seen_usernames'] ?? [];
        if ($username !== '' && !in_array($username, $_SESSION['hp_seen_usernames'], true)) {
            $_SESSION['hp_seen_usernames'][] = $username;
        }

        // "leaked" credentials from .env file
        $validPairs = [
            'christopher_robin' => 'ThinkThinkThink!',
            'cr_admin'          => 'ThinkThinkThink!',
            'admin'             => 'HunnyP0t@2026!',
        ];

        $_SESSION['hp_login_attempts'] = ($_SESSION['hp_login_attempts'] ?? 0) + 1;

        if (isset($validPairs[$username]) && $validPairs[$username] === $password) {
            $_SESSION['hp_admin_auth'] = true;
            $_SESSION['hp_admin_user'] = $username;
            $_SESSION['hp_request_count'] = 0;
            $_SESSION['hp_first_seen'] = microtime(true);
            log_honeypot('honeyPotAdmin_login_success', 'honeyPotAdmin', [
                'username' => $username,
                'attempts' => $_SESSION['hp_login_attempts'],
            ]);
            header('Location: /hundred-acre-admin/dashboard.php');
            exit;
        } else {
            if ($_SESSION['hp_login_attempts'] >= 5) {
                $error = 'Too many failed attempts. Account locked for 5 minutes.';
                // not actually locked
            } else {
                $error = 'Invalid username or password.';
            }
        }
    }
}

$_SESSION['hp_csrf'] = bin2hex(random_bytes(32));
$csrfToken = $_SESSION['hp_csrf'];
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Hunny Admin - Login</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🍯</text></svg>">
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/hundred-acre-admin/layer2-style.css">
</head>

<body class="index">
    <div class="login-card">
        <h1>Hunny Admin</h1>
        <p class="sub">Hundred Acre Wood Management</p>

        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="/hundred-acre-admin/">
            <input type="hidden" name="_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <div class="field">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" autocomplete="username"
                    value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
            </div>
            <div class="field">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" autocomplete="current-password">
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
        <div class="footer">
        </div>
    </div>
</body>

</html>