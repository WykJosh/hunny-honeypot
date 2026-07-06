<?php
// LAYER 1 fakeAdmin
// scroll to it with - /admin/

require_once __DIR__ . '/../config.php';

// Log EVERY request to this path
log_honeypot('fakeAdmin_visit', 'fakeAdmin');

$error = '';
$loggedIn = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    // Log the credentials they tried
    log_honeypot('fakeAdmin_login', 'fakeAdmin', [
        'username_tried' => $username,
        'password_tried' => $password,
    ]);

    // Also log to activity_log so it shows in the real admin dashboard
    log_event(
        'HONEYPOT_FAKEADMIN_LOGIN',
        null,
        $username,
        json_encode(['password_tried' => $password, 'layer' => 'fakeAdmin'])
    );

    // Track attempts in session to accept creds after a few tries
    if (session_status() === PHP_SESSION_NONE) session_start();
    $_SESSION['fake_admin_attempts'] = ($_SESSION['fake_admin_attempts'] ?? 0) + 1;

    // Accept well-known defaults immediately, anything else after 3 attempts
    $easyPairs = [
        'admin' => ['admin', 'password', '123456', 'admin123', 'letmein'],
        'root'  => ['root', 'toor', 'password'],
        'administrator' => ['administrator', 'password', 'admin'],
    ];

    $accepted = false;
    if (isset($easyPairs[$username]) && in_array($password, $easyPairs[$username], true)) {
        $accepted = true;
    } elseif ($_SESSION['fake_admin_attempts'] >= 3) {
        $accepted = true; // Let them in after 3 tries with anything
    }

    if ($accepted) {
        $_SESSION['fake_admin_auth'] = true;
        $_SESSION['fake_admin_user'] = $username;
        log_honeypot('fakeAdmin_login_accepted', 'fakeAdmin', [
            'username' => $username,
            'attempts' => $_SESSION['fake_admin_attempts'],
        ]);
        $loggedIn = true;
    } else {
        $error = 'Invalid credentials.';
    }
}

// Check if already "logged in" to fake admin
if (session_status() === PHP_SESSION_NONE) session_start();
if (!empty($_SESSION['fake_admin_auth'])) {
    $loggedIn = true;
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Admin Login</title>
    <link rel="stylesheet" href="/admin/admin-style.css">

</head>

<body>
    <?php if (!$loggedIn): ?>
        <div class="wrap">
            <div class="panel">
                <h2>Admin Login</h2>
                <?php if ($error): ?>
                    <div class="error"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>
                <form method="POST" action="/admin/">
                    <div class="field">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
                    </div>
                    <div class="field">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password">
                    </div>
                    <button type="submit" class="btn">Login</button>
                </form>
            </div>
            <p style="text-align:center;margin-top:1rem;font-size:0.8rem;color:#999">
                Hunny To-Do Admin v1.2
            </p>
        </div>
    <?php else: ?>
        <?php
        log_honeypot('fakeAdmin_dashboard', 'fakeAdmin');
        ?>
        <div class="wrap" style="max-width:700px">
            <div class="panel dash">
                <h2>Admin Dashboard</h2>
                <div class="info">
                    Logged in as: <strong><?= htmlspecialchars($_SESSION['fake_admin_user'] ?? 'admin') ?></strong>
                    | <a href="/admin/?logout=1" style="color:#31708f">Logout</a>
                </div>
                <p>System Status: <span style="color:green">Online</span></p>

                <!-- TODO: change creds in /.env before going live -->
                <h3 style="margin:1rem 0 0.5rem;font-size:1rem">Registered Users</h3>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>1</td>
                            <td>admin</td>
                            <td>admin@honeypot.local</td>
                            <td style="color:green">Active</td>
                        </tr>
                        <tr>
                            <td>2</td>
                            <td>pooh</td>
                            <td>pooh@hundredacre.local</td>
                            <td style="color:green">Active</td>
                        </tr>
                        <tr>
                            <td>3</td>
                            <td>piglet</td>
                            <td>piglet@hundredacre.local</td>
                            <td style="color:red">Disabled</td>
                        </tr>
                        <tr>
                            <td>4</td>
                            <td>tigger</td>
                            <td>tigger@hundredacre.local</td>
                            <td style="color:green">Active</td>
                        </tr>
                    </tbody>
                </table>
                <p style="margin-top:1rem;font-size:0.8rem;color:#999">Showing 4 of 4 users.</p>
            </div>
        </div>
    <?php endif; ?>

    <?php
    if (isset($_GET['logout'])) {
        if (session_status() === PHP_SESSION_NONE) session_start();
        unset($_SESSION['fake_admin_auth'], $_SESSION['fake_admin_user'], $_SESSION['fake_admin_attempts']);
        log_honeypot('fakeAdmin_logout', 'fakeAdmin');
        header('Location: /admin/');
        exit;
    }
    ?>
</body>

</html>