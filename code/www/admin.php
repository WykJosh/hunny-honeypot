<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/layout.php';



if (session_status() === PHP_SESSION_NONE) session_start();

$admin = start_page('Admin Panel', true, true);

// Load all users
$users = db()->query('SELECT id, username, email, is_admin, is_enabled, avatar, created_at FROM users ORDER BY id ASC')->fetchAll();

?>
<div class="container" style="padding-top:1.5rem">


    <h1 class="page-title">Admin's Workshop</h1>
    <p class="page-subtitle">Hundred Acre Wood Management Console</p>

    <!-- User management -->
    <div class="card">
        <h2 style="font-family:'Luckiest Guy',cursive;color:var(--honey-dark);font-size:1.4rem;margin-bottom:1rem">
            User Management
        </h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Joined</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $u): ?>
                        <tr>
                            <td><?= $u['id'] ?></td>
                            <td>
                                <?php if (!empty($u['avatar']) && file_exists(UPLOAD_DIR . $u['avatar'])): ?>
                                    <img src="<?= h(UPLOAD_URL . $u['avatar']) ?>"
                                        style="width:28px;height:28px;border-radius:50%;object-fit:cover;vertical-align:middle;margin-right:0.4rem;border:2px solid var(--honey)" />
                                <?php endif; ?>
                                <?= h($u['username']) ?>
                            </td>
                            <td><?= h($u['email']) ?></td>
                            <td>
                                <?php if ($u['is_admin']): ?>
                                    <span class="badge badge-admin">Admin</span>
                                <?php else: ?>
                                    <span class="badge" style="background:#f3f4f6;color:#6b7280">User</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <span class="badge <?= $u['is_enabled'] ? 'badge-on' : 'badge-off' ?>">
                                    <?= $u['is_enabled'] ? 'Enabled' : 'Disabled' ?>
                                </span>
                            </td>
                            <td class="text-muted"><?= h(date('Y-m-d', strtotime($u['created_at']))) ?></td>

                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>




    <?php end_page(); ?>