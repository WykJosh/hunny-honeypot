<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/layout.php';
if (session_status() === PHP_SESSION_NONE) session_start();

if (!empty($_SESSION['user'])) {
    header('Location: /index.php');
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['company_url'] ?? '')) {
        log_honeypot('hidden_field_register', 'trap', [
            'field_value'    => $_POST['company_url'],
            'username_tried' => trim($_POST['username'] ?? ''),
        ]);
        header('Location: /register.php');
        exit;
    }

    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request. Please try again.';
    } else {
        $username  = trim($_POST['username'] ?? '');
        $email     = trim($_POST['email'] ?? '');
        $password  = $_POST['password'] ?? '';
        $password2 = $_POST['password2'] ?? '';

        if ($username === '' || $email === '' || $password === '') {
            $error = 'All fields are required.';
        } elseif (strlen($username) < 3 || strlen($username) > 50) {
            $error = 'Username must be 3–50 characters.';
        } elseif (!preg_match('/^[a-zA-Z0-9_.-]+$/', $username)) {
            $error = 'Username may only contain letters, numbers, _ . -';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Enter a valid email address.';
        } elseif ($password !== $password2) {
            $error = 'Passwords do not match.';
        } elseif (($pwErr = validate_password($password)) !== '') {
            $error = $pwErr;
        } else {
            $stmt = db()->prepare('SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1');
            $stmt->execute([$username, $email]);
            if ($stmt->fetch()) {
                $error = 'Username or email already in use.';
                log_event('REGISTER_FAIL', null, $username, 'Duplicate username/email');
            } else {
                //bcrypt cost 12 to resist brute force
                $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
                $stmt = db()->prepare('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)');
                $stmt->execute([$username, $hash, $email]);
                $newId = (int)db()->lastInsertId();
                log_event('REGISTER', $newId, $username, json_encode(['email' => $email]));
                $success = 'Account created! You can now log in.';
            }
        }
    }
}

start_page('Register', false, false);
?>
<div class="auth-wrap">
    <div class="auth-card">
        <span class="auth-bee">🐝</span>
        <div class="auth-title">Join the Wood!</div>
        <p class="text-center text-muted" style="margin-bottom:1.5rem">Create your Hunny Do account</p>

        <?php if ($error): ?>
            <div class="alert alert-error"><?= h($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success">
                <?= h($success) ?> <a href="/login.php">Log in →</a>
            </div>
        <?php endif; ?>

        <form method="POST" action="/register.php" novalidate>
            <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>" />
            <div style="position:absolute;left:-9999px" aria-hidden="true">
                <label for="company_url">Company URL</label>
                <input type="text" id="company_url" name="company_url" tabindex="-1" autocomplete="off" />
            </div>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username"
                    value="<?= h($_POST['username'] ?? '') ?>"
                    autocomplete="username" required maxlength="50" />
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email"
                    value="<?= h($_POST['email'] ?? '') ?>"
                    autocomplete="email" required maxlength="100" />
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password"
                    autocomplete="new-password" required maxlength="100" />
                <small class="text-muted" style="margin-top:0.3rem;display:block">
                    Min <?= PASSWORD_MIN_LENGTH ?> characters, must include uppercase, lowercase, number &amp; special character
                </small>
            </div>
            <div class="form-group">
                <label for="password2">Confirm Password</label>
                <input type="password" id="password2" name="password2"
                    autocomplete="new-password" required maxlength="100" />
            </div>
            <button type="submit" class="btn btn-primary btn-full" style="margin-top:0.5rem">
                🍯 Create Account
            </button>
        </form>

        <div class="auth-switch">
            Already have an account? <a href="/login.php">Log in</a>
        </div>
    </div>
</div>
<?php end_page(); ?>