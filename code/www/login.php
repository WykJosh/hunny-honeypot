<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/layout.php';
if (session_status() === PHP_SESSION_NONE) session_start();

if (!empty($_SESSION['user'])) {
    header('Location: /index.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // bots fill this, humans never see it
    if (!empty($_POST['website'] ?? '')) {
        log_honeypot('hidden_field_login', 'trap', [
            'field_value'    => $_POST['website'],
            'username_tried' => trim($_POST['username'] ?? ''),
        ]);
        // Return fake success to hide the trap
        header('Location: /login.php');
        exit;
    }

    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request. Please try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($username === '' || $password === '') {
            $error = 'Please fill in all fields.';
            log_event('LOGIN_FAIL', null, $username, 'Empty fields');
        } else {
            $stmt = db()->prepare('SELECT * FROM users WHERE username = ? LIMIT 1');
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if ($user && password_verify($password, $user['password_hash'])) {
                if (!$user['is_enabled']) {
                    $error = 'Your account has been disabled. Contact an admin.';
                    log_event('LOGIN_FAIL', $user['id'], $username, 'Account disabled');
                } else {
                    // Regenerate session ID on login
                    session_regenerate_id(true);
                    $_SESSION['user'] = [
                        'id'       => $user['id'],
                        'username' => $user['username'],
                        'email'    => $user['email'],
                        'is_admin' => (bool)$user['is_admin'],
                        'is_enabled' => (bool)$user['is_enabled'],
                        'avatar'   => $user['avatar'],
                    ];
                    log_event('LOGIN_SUCCESS', $user['id'], $username, '');
                    header('Location: /index.php');
                    exit;
                }
            } else {
                $error = 'Invalid username or password.';
                log_event('LOGIN_FAIL', null, $username, 'Bad credentials');
            }
        }
    }
}

// Error from disabled check on require_login redirect
if (isset($_GET['error']) && $_GET['error'] === 'disabled') {
    $error = 'Your account has been disabled.';
}

start_page('Login', false, false);
?>
<div class="auth-wrap">
    <div class="auth-card">
        <span class="auth-bee">🐻</span>
        <div class="auth-title">Welcome Back!</div>
        <p class="text-center text-muted" style="margin-bottom:1.5rem">Log in to your Hunny Do</p>

        <?php if ($error): ?>
            <div class="alert alert-error"><?= h($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="/login.php" novalidate>
            <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>" />
            <!-- Honeypot field — moved offscreen, bots fill it, humans can't see it -->
            <div style="position:absolute;left:-9999px" aria-hidden="true">
                <label for="website">Website</label>
                <input type="text" id="website" name="website" tabindex="-1" autocomplete="off" />
            </div>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username"
                    value="<?= h($_POST['username'] ?? '') ?>"
                    autocomplete="username" required maxlength="50" />
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password"
                    autocomplete="current-password" required maxlength="100" />
            </div>
            <button type="submit" class="btn btn-primary btn-full" style="margin-top:0.5rem">
                🍯 Enter the Hundred Acre Wood
            </button>
        </form>

        <div class="auth-switch">
            No account yet? <a href="/register.php">Register here</a>
        </div>
    </div>
</div>
<?php end_page(); ?>