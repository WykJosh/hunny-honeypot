<?php

require_once __DIR__ . '/../config.php';

if (session_status() === PHP_SESSION_NONE) session_start();

// Must be "authenticated" to honeypot admin
if (empty($_SESSION['hp_admin_auth'])) {
    header('Location: /hundred-acre-admin/');
    exit;
}

// Track request count and timing for this session
$_SESSION['hp_request_count'] = ($_SESSION['hp_request_count'] ?? 0) + 1;
$sessionDuration = round(microtime(true) - ($_SESSION['hp_first_seen'] ?? microtime(true)), 2);

// Log every page view
log_honeypot('honeyPotAdmin_dashboard', 'honeyPotAdmin', [
    'request_number'  => $_SESSION['hp_request_count'],
    'session_duration' => $sessionDuration,
    'section'         => $_GET['section'] ?? 'overview',
]);

$section = $_GET['section'] ?? 'overview';
$success = '';

// fake saves that appear to work
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['_token']) || !hash_equals($_SESSION['hp_csrf'] ?? '', $_POST['_token'] ?? '')) {
        // Still log the attempt even if CSRF fails
        log_honeypot('honeyPotAdmin_csrf_fail', 'honeyPotAdmin', [
            'action' => $_POST['action'] ?? 'unknown',
        ]);
    } else {
        $action = $_POST['action'] ?? '';

        log_honeypot('honeyPotAdmin_action', 'honeyPotAdmin', [
            'action'          => $action,
            'request_number'  => $_SESSION['hp_request_count'],
            'session_duration' => $sessionDuration,
        ]);

        switch ($action) {
            case 'toggle_user':
                $uid = (int)($_POST['user_id'] ?? 0);
                // Fake toggle
                $_SESSION['hp_disabled_users'] = $_SESSION['hp_disabled_users'] ?? [];
                if (in_array($uid, $_SESSION['hp_disabled_users'])) {
                    $_SESSION['hp_disabled_users'] = array_diff($_SESSION['hp_disabled_users'], [$uid]);
                    $success = 'User enabled successfully.';
                } else {
                    $_SESSION['hp_disabled_users'][] = $uid;
                    $success = 'User disabled successfully.';
                }
                break;

            case 'save_settings':
                //  2 second delay simulating "saving"
                usleep(2000000);
                $success = 'Settings saved successfully.';
                log_honeypot('honeyPotAdmin_settings_save', 'honeyPotAdmin', [
                    'settings_data' => $_POST,
                ]);
                break;

            case 'run_query':
                $query = $_POST['query'] ?? '';
                log_honeypot('honeyPotAdmin_sql_query', 'honeyPotAdmin', [
                    'query' => $query,
                ]);
                // Stored for display below
                $_SESSION['hp_last_query'] = $query;
                $_SESSION['hp_query_result'] = 'OK';
                break;

            case 'export_backup':
                log_honeypot('honeyPotAdmin_export', 'honeyPotAdmin');
                $success = 'Backup queued. Download will be ready in ~30 seconds...';
                break;
        }
    }
    // Regenerate CSRF
    $_SESSION['hp_csrf'] = bin2hex(random_bytes(32));
}

$csrfToken = $_SESSION['hp_csrf'] ?? bin2hex(random_bytes(32));
$_SESSION['hp_csrf'] = $csrfToken;


$seedUsers = [
    ['id' => 1,  'username' => 'admin',     'email' => 'admin@honeypot.local',          'role' => 'Admin',  'status' => 'Active',   'joined' => date('Y-m-d', strtotime('-47 days')), 'logins' => 34],
    ['id' => 2,  'username' => 'pooh',      'email' => 'pooh@hundredacre.local',        'role' => 'User',   'status' => 'Active',   'joined' => date('Y-m-d', strtotime('-42 days')), 'logins' => 28],
    ['id' => 3,  'username' => 'piglet',    'email' => 'piglet@hundredacre.local',      'role' => 'User',   'status' => 'Disabled', 'joined' => date('Y-m-d', strtotime('-40 days')), 'logins' => 3],
    ['id' => 4,  'username' => 'tigger',    'email' => 'tigger@hundredacre.local',      'role' => 'User',   'status' => 'Active',   'joined' => date('Y-m-d', strtotime('-38 days')), 'logins' => 19],
    ['id' => 5,  'username' => 'eeyore',    'email' => 'eeyore@hundredacre.local',      'role' => 'User',   'status' => 'Active',   'joined' => date('Y-m-d', strtotime('-35 days')), 'logins' => 7],
    ['id' => 6,  'username' => 'rabbit',    'email' => 'rabbit@hundredacre.local',      'role' => 'Mod',    'status' => 'Active',   'joined' => date('Y-m-d', strtotime('-30 days')), 'logins' => 22],
    ['id' => 7,  'username' => 'owl',       'email' => 'owl@hundredacre.local',         'role' => 'User',   'status' => 'Active',   'joined' => date('Y-m-d', strtotime('-28 days')), 'logins' => 11],
    ['id' => 8,  'username' => 'kanga',     'email' => 'kanga@hundredacre.local',       'role' => 'User',   'status' => 'Active',   'joined' => date('Y-m-d', strtotime('-25 days')), 'logins' => 5],
    ['id' => 9,  'username' => 'roo',       'email' => 'roo@hundredacre.local',         'role' => 'User',   'status' => 'Active',   'joined' => date('Y-m-d', strtotime('-18 days')), 'logins' => 14],
    ['id' => 10, 'username' => 'christopher', 'email' => 'cr@hundredacre.local',         'role' => 'Admin',  'status' => 'Active',   'joined' => date('Y-m-d', strtotime('-50 days')), 'logins' => 67],
    ['id' => 11, 'username' => 'lumpy',     'email' => 'lumpy@hundredacre.local',       'role' => 'User',   'status' => 'Active',   'joined' => date('Y-m-d', strtotime('-12 days')), 'logins' => 2],
];

// turns  username into a fake "user record"
function fake_user_record(int $id, string $username, string $joined, int $logins = 1): array
{
    // only allow safe chars to avoid breaking the table layout
    $clean = preg_replace('/[^a-zA-Z0-9_.-]/', '', $username);
    if ($clean === '' || strlen($clean) > 30) $clean = 'user' . $id;
    return [
        'id'       => $id,
        'username' => $clean,
        'email'    => $clean . '@hundredacre.local',
        'role'     => 'User',
        'status'   => 'Active',
        'joined'   => $joined,
        'logins'   => $logins,
    ];
}

// Global user list — all attackers see the same list, no IP filtering
$seedUsernames = array_column($seedUsers, 'username');
$dynamicUsers  = [];
$nextId        = 12;

// Pin the logged-in username at top first so it always appears
$currentUser = $_SESSION['hp_admin_user'] ?? '';
if ($currentUser !== '' && !in_array($currentUser, $seedUsernames, true)) {
    $dynamicUsers[] = fake_user_record(
        $nextId++,
        $currentUser,
        date('Y-m-d'),
        1
    );
}

// Pull ALL usernames globally from activity_log — no IP filter
try {
    $excludeNow  = array_merge($seedUsernames, $currentUser !== '' ? [$currentUser] : []);
    $placeholders = implode(',', array_fill(0, count($excludeNow), '?'));
    $stmt = db()->prepare("
        SELECT   username_attempted,
                 MIN(created_at) AS first_seen,
                 COUNT(*)        AS attempts
        FROM     activity_log
        WHERE    username_attempted IS NOT NULL
          AND    username_attempted != ''
          AND    username_attempted NOT IN ($placeholders)
        GROUP BY username_attempted
        ORDER BY MAX(created_at) DESC
        LIMIT    60
    ");
    $stmt->execute($excludeNow);
    foreach ($stmt->fetchAll() as $row) {
        $dynamicUsers[] = fake_user_record(
            $nextId++,
            $row['username_attempted'],
            date('Y-m-d', strtotime($row['first_seen'])),
            min((int)$row['attempts'], 20)
        );
    }
} catch (PDOException $e) {
    error_log('honeyPotAdmin global users error: ' . $e->getMessage());
}

$fakeUsers = array_merge($seedUsers, $dynamicUsers);

// Apply session-based fake toggles
foreach ($fakeUsers as &$fu) {
    if (in_array($fu['id'], $_SESSION['hp_disabled_users'] ?? [])) {
        $fu['status'] = ($fu['status'] === 'Active') ? 'Disabled' : 'Active';
    }
}
unset($fu);
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Hunny Admin - Dashboard</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🍯</text></svg>">
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/hundred-acre-admin/layer2-style.css">
</head>

<body class="dashboard">
    <nav class="sidebar">
        <div class="brand">
            <h2>Hunny Admin</h2>
            <span>v3.2.1 - PHP 8.5</span>
        </div>

        <a href="?section=overview" class="<?= $section === 'overview' ? 'active' : '' ?>">Dashboard</a>
        <a href="?section=users" class="<?= $section === 'users' ? 'active' : '' ?>">Users</a>
        <a href="?section=settings" class="<?= $section === 'settings' ? 'active' : '' ?>">Settings</a>
        <a href="?section=database" class="<?= $section === 'database' ? 'active' : '' ?>">Database</a>
        <a href="?section=logs" class="<?= $section === 'logs' ? 'active' : '' ?>">Logs</a>
        <a href="?section=backups" class="<?= $section === 'backups' ? 'active' : '' ?>">Backups</a>
        <a href="/hundred-acre-admin/?action=logout" style="margin-top:2rem;color:#ef4444">Sign Out</a>
        <img src="/images/christopher-robin-winnie-the-pooh.png" class="sidebar-chris" alt="">

    </nav>



    <div class="main">
        <div class="topbar">
            <h1><?php
                $titles = ['overview' => 'Dashboard', 'users' => 'User Management', 'settings' => 'Settings', 'database' => 'Database Tools', 'logs' => 'System Logs', 'backups' => 'Backups'];
                echo $titles[$section] ?? 'Dashboard';
                ?></h1>
            <div class="user">
                Signed in as <strong><?= htmlspecialchars($_SESSION['hp_admin_user'] ?? 'admin') ?></strong>
                &middot; <a href="/hundred-acre-admin/?action=logout">Sign out</a>
            </div>
        </div>

        <?php if ($success): ?>
            <div class="success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <?php if ($section === 'overview'): ?>
            <div class="cards">
                <div class="stat-card">
                    <div class="label">Total users</div>
                    <div class="value"><?= count($fakeUsers) ?></div>
                    <div class="sub">+3 this week</div>
                </div>
                <div class="stat-card">
                    <div class="label">Active sessions</div>
                    <div class="value">7</div>
                    <div class="sub">2 admins online</div>
                </div>
                <div class="stat-card">
                    <div class="label">Todos created</div>
                    <div class="value">46</div>
                    <div class="sub">11 completed today</div>
                </div>
                <div class="stat-card">
                    <div class="label">Failed logins (24h)</div>
                    <div class="value">23</div>
                    <div class="sub">from 4 unique IPs</div>
                </div>
            </div>

            <div class="panel">
                <h3>Recent activity</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Event</th>
                            <th>User</th>
                            <th>IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><?= date('H:i:s', strtotime('-2 min')) ?></td>
                            <td><span class="badge badge-active">LOGIN</span></td>
                            <td>pooh</td>
                            <td><code>192.168.30.104</code></td>
                        </tr>
                        <tr>
                            <td><?= date('H:i:s', strtotime('-8 min')) ?></td>
                            <td><span class="badge badge-disabled">FAIL</span></td>
                            <td>root</td>
                            <td><code>192.168.30.104</code></td>
                        </tr>
                        <tr>
                            <td><?= date('H:i:s', strtotime('-12 min')) ?></td>
                            <td><span class="badge badge-active">LOGIN</span></td>
                            <td>tigger</td>
                            <td><code>192.168.30.104</code></td>
                        </tr>
                        <tr>
                            <td><?= date('H:i:s', strtotime('-18 min')) ?></td>
                            <td><span class="badge badge-disabled">FAIL</span></td>
                            <td>admin</td>
                            <td><code>192.168.30.104</code></td>
                        </tr>
                        <tr>
                            <td><?= date('H:i:s', strtotime('-25 min')) ?></td>
                            <td><span class="badge badge-active">REGISTER</span></td>
                            <td>lumpy</td>
                            <td><code>192.168.30.20</code></td>
                        </tr>
                        <tr>
                            <td><?= date('H:i:s', strtotime('-31 min')) ?></td>
                            <td><span class="badge badge-disabled">FAIL</span></td>
                            <td>administrator</td>
                            <td><code>192.168.30.16</code></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="panel">
                <h3>System information</h3>
                <table>
                    <tbody>
                        <tr>
                            <td style="color:#888;width:200px">Server</td>
                            <td>Debian 12 / Nginx 1.28</td>
                        </tr>
                        <tr>
                            <td style="color:#888">PHP version</td>
                            <td>8.5-fpm</td>
                        </tr>
                        <tr>
                            <td style="color:#888">Database</td>
                            <td>MariaDB 10.11.6</td>
                        </tr>
                        <tr>
                            <td style="color:#888">Uptime</td>
                            <td><?= rand(12, 45) ?> days, <?= rand(1, 23) ?>h <?= rand(0, 59) ?>m</td>
                        </tr>
                        <tr>
                            <td style="color:#888">Disk usage</td>
                            <td>1.2 GB / 4 GB </td>
                        </tr>
                        <tr>
                            <td style="color:#888">Memory</td>
                            <td>1.8 GB / 4 GB </td>
                        </tr>
                        <tr>
                            <td style="color:#888">App root</td>
                            <td><code>/srv/legacy-admin</code></td>
                        </tr>
                        <tr>
                            <td style="color:#888">Config</td>
                            <td><code>/srv/legacy-admin/conf/database.yml</code></td>
                        </tr>
                    </tbody>
                </table>
            </div>

        <?php elseif ($section === 'users'): ?>
            <div class="panel">
                <h3>All users (<?= count($fakeUsers) ?>)</h3>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Joined</th>
                            <th>Logins</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($fakeUsers as $fu): ?>
                            <tr>
                                <td><?= $fu['id'] ?></td>
                                <td><strong><?= htmlspecialchars($fu['username']) ?></strong></td>
                                <td style="color:#888"><?= htmlspecialchars($fu['email']) ?></td>
                                <td>
                                    <?php if ($fu['role'] === 'Admin'): ?><span class="badge badge-admin">Admin</span>
                                    <?php elseif ($fu['role'] === 'Mod'): ?><span class="badge badge-mod">Mod</span>
                                    <?php else: ?><span style="color:#888">User</span><?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge <?= $fu['status'] === 'Active' ? 'badge-active' : 'badge-disabled' ?>">
                                        <?= $fu['status'] ?>
                                    </span>
                                </td>
                                <td style="color:#888"><?= $fu['joined'] ?></td>
                                <td><?= $fu['logins'] ?></td>
                                <td>
                                    <form method="POST" style="display:inline">
                                        <input type="hidden" name="_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                        <input type="hidden" name="action" value="toggle_user">
                                        <input type="hidden" name="user_id" value="<?= $fu['id'] ?>">
                                        <button type="submit" class="btn <?= $fu['status'] === 'Active' ? 'btn-red' : 'btn-green' ?>">
                                            <?= $fu['status'] === 'Active' ? 'Disable' : 'Enable' ?>
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

        <?php elseif ($section === 'settings'): ?>
            <div class="panel">
                <h3>Application settings</h3>
                <form method="POST">
                    <input type="hidden" name="_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <input type="hidden" name="action" value="save_settings">
                    <div class="form-group">
                        <label>Site name</label>
                        <input type="text" name="site_name" value="Hunny Do">
                    </div>
                    <div class="form-group">
                        <label>Admin email</label>
                        <input type="email" name="admin_email" value="admin@honeypot.local">
                    </div>
                    <div class="form-group">
                        <label>Registration</label>
                        <select name="registration">
                            <option value="open">Open</option>
                            <option value="invite">Invite only</option>
                            <option value="closed">Closed</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Max upload size (MB)</label>
                        <input type="number" name="max_upload" value="2">
                    </div>
                    <div class="form-group">
                        <label>Session timeout (minutes)</label>
                        <input type="number" name="session_timeout" value="30">
                    </div>
                    <div class="form-group">
                        <label>Database host</label>
                        <input type="text" name="db_host" value="db">
                    </div>
                    <div class="form-group">
                        <label>Database name</label>
                        <input type="text" name="db_name" value="honeypot">
                    </div>
                    <button type="submit" class="btn btn-primary">Save settings</button>
                </form>
            </div>

        <?php elseif ($section === 'database'): ?>
            <div class="panel">
                <h3>SQL query tool</h3>
                <p style="font-size:0.8rem;margin-bottom:1rem">Execute SQL queries against the application database. Use with caution.</p>
                <form method="POST">
                    <input type="hidden" name="_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <input type="hidden" name="action" value="run_query">
                    <div class="form-group">
                        <label>SQL Query</label>
                        <textarea name="query" placeholder="SELECT * FROM users LIMIT 10;"><?= htmlspecialchars($_SESSION['hp_last_query'] ?? '') ?></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Execute</button>
                </form>

                <?php if (!empty($_SESSION['hp_query_result'])): ?>
                    <div class="query-result">
                        <div style="margin-bottom:0.5rem">Query executed successfully. <?= rand(1, 15) ?> row(s) returned in <?= rand(1, 45) ?>ms.</div>
                        +----+----------+----------------------------+-------+--------+
                        | id | username | email | role | status |
                        +----+----------+----------------------------+-------+--------+
                        | 1 | admin | admin@honeypot.local | Admin | Active |
                        | 2 | pooh | pooh@hundredacre.local | User | Active |
                        | 3 | piglet | piglet@hundredacre.local | User | Dis. |
                        | 4 | tigger | tigger@hundredacre.local | User | Active |
                        +----+----------+----------------------------+-------+--------+
                    </div>
                    <?php unset($_SESSION['hp_query_result']); ?>
                <?php endif; ?>
            </div>

            <div class="panel">
                <h3>Database tables</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Table</th>
                            <th>Rows</th>
                            <th>Size</th>
                            <th>Engine</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><code>users</code></td>
                            <td><?= count($fakeUsers) ?></td>
                            <td>48 KB</td>
                            <td>InnoDB</td>
                        </tr>
                        <tr>
                            <td><code>todos</code></td>
                            <td>847</td>
                            <td>96 KB</td>
                            <td>InnoDB</td>
                        </tr>
                        <tr>
                            <td><code>sessions</code></td>
                            <td>23</td>
                            <td>16 KB</td>
                            <td>InnoDB</td>
                        </tr>
                        <tr>
                            <td><code>activity_log</code></td>
                            <td>2,341</td>
                            <td>384 KB</td>
                            <td>InnoDB</td>
                        </tr>
                        <tr>
                            <td><code>password_resets</code></td>
                            <td>5</td>
                            <td>8 KB</td>
                            <td>InnoDB</td>
                        </tr>
                    </tbody>
                </table>
            </div>

        <?php elseif ($section === 'logs'): ?>
            <div class="panel">
                <h3>Application logs (last 24h)</h3>
                <div class="query-result" style="max-height:400px">
                    [<?= date('Y-m-d H:i:s', strtotime('-3 min')) ?>] [INFO] User 'pooh' logged in from 192.168.30.104
                    [<?= date('Y-m-d H:i:s', strtotime('-8 min')) ?>] [WARN] Failed login for 'root' from 192.168.30.104 (bad password)
                    [<?= date('Y-m-d H:i:s', strtotime('-12 min')) ?>] [INFO] User 'tigger' logged in from 192.168.30.104
                    [<?= date('Y-m-d H:i:s', strtotime('-15 min')) ?>] [WARN] Failed login for 'admin' from 192.168.30.104 (bad password)
                    [<?= date('Y-m-d H:i:s', strtotime('-18 min')) ?>] [WARN] Failed login for 'administrator' from 192.168.30.16 (user not found)
                    [<?= date('Y-m-d H:i:s', strtotime('-22 min')) ?>] [INFO] New user registered: lumpy (192.168.30.20)
                    [<?= date('Y-m-d H:i:s', strtotime('-30 min')) ?>] [WARN] Rate limit triggered for 192.168.30.13 (auth endpoint)
                    [<?= date('Y-m-d H:i:s', strtotime('-45 min')) ?>] [INFO] User 'rabbit' updated profile
                    [<?= date('Y-m-d H:i:s', strtotime('-1 hour')) ?>] [INFO] Backup job completed (4.2 MB)
                    [<?= date('Y-m-d H:i:s', strtotime('-2 hour')) ?>] [WARN] Failed login for 'sa' from 192.168.30.03 (user not found)
                    [<?= date('Y-m-d H:i:s', strtotime('-3 hour')) ?>] [INFO] User 'admin' logged in from 127.0.0.1
                    [<?= date('Y-m-d H:i:s', strtotime('-6 hour')) ?>] [ERROR] MySQL connection pool exhaustion (recovered in 2.3s)
                    [<?= date('Y-m-d H:i:s', strtotime('-8 hour')) ?>] [WARN] Suspicious user-agent detected: sqlmap/1.7 from 192.168.30.16
                </div>
            </div>

        <?php elseif ($section === 'backups'): ?>
            <div class="panel">
                <h3>Database backups</h3>
                <form method="POST" style="margin-bottom:1.5rem">
                    <input type="hidden" name="_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <input type="hidden" name="action" value="export_backup">
                    <button type="submit" class="btn btn-primary">Create new backup</button>
                </form>
                <table>
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <th>Size</th>
                            <th>Created</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><code>backup_<?= date('Ymd', strtotime('-1 day')) ?>.sql.gz</code></td>
                            <td>4.1 MB</td>
                            <td><?= date('Y-m-d H:i', strtotime('-1 day')) ?></td>
                            <td><a href="#" style="color:#e94560;font-size:0.85rem" onclick="alert('Preparing download...');return false;">Download</a></td>
                        </tr>
                        <tr>
                            <td><code>backup_<?= date('Ymd', strtotime('-3 days')) ?>.sql.gz</code></td>
                            <td>3.8 MB</td>
                            <td><?= date('Y-m-d H:i', strtotime('-3 days')) ?></td>
                            <td><a href="#" style="color:#e94560;font-size:0.85rem" onclick="alert('Preparing download...');return false;">Download</a></td>
                        </tr>
                        <tr>
                            <td><code>backup_<?= date('Ymd', strtotime('-7 days')) ?>.sql.gz</code></td>
                            <td>3.5 MB</td>
                            <td><?= date('Y-m-d H:i', strtotime('-7 days')) ?></td>
                            <td><a href="#" style="color:#e94560;font-size:0.85rem" onclick="alert('Preparing download...');return false;">Download</a></td>
                        </tr>
                    </tbody>
                </table>
            </div>

        <?php endif; ?>
    </div>

    <script>
        (function() {
            var moves = 0,
                keys = 0,
                start = Date.now();
            document.addEventListener('mousemove', function() {
                moves++
            });
            document.addEventListener('keydown', function() {
                keys++
            });
            window.addEventListener('beforeunload', function() {
                var data = 'moves=' + moves + '&keys=' + keys + '&time=' + (Date.now() - start);
                navigator.sendBeacon('/hundred-acre-admin/beacon.php', data);
            });
        })();
    </script>
</body>

</html>