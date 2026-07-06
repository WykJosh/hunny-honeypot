<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/layout.php';

// Redirect to login if not authenticated (fixes the "/" landing bug)
if (session_status() === PHP_SESSION_NONE) session_start();
if (empty($_SESSION['user'])) {
    header('Location: /login.php');
    exit;
}

$error = '';
$success = '';

// Handle POST actions (add, toggle done, delete)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (session_status() === PHP_SESSION_NONE) session_start();
    $user = require_login();

    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'add') {
            $title = trim($_POST['title'] ?? '');
            if ($title === '') {
                $error = 'Todo title cannot be empty.';
            } elseif (strlen($title) > 255) {
                $error = 'Todo title is too long (max 255 chars).';
            } else {
                $stmt = db()->prepare('INSERT INTO todos (user_id, title) VALUES (?, ?)');
                $stmt->execute([$user['id'], $title]);
            }
        } elseif ($action === 'toggle') {
            $id = (int)($_POST['todo_id'] ?? 0);
            // Verify ownership
            $stmt = db()->prepare('UPDATE todos SET is_done = NOT is_done WHERE id = ? AND user_id = ?');
            $stmt->execute([$id, $user['id']]);
        } elseif ($action === 'delete') {
            $id = (int)($_POST['todo_id'] ?? 0);
            $stmt = db()->prepare('DELETE FROM todos WHERE id = ? AND user_id = ?');
            $stmt->execute([$id, $user['id']]);
        } else {
            $error = 'Unknown action.';
            log_honeypot($error, 'trap', ['action' => $action]);
        }
    }

    // PRG pattern
    header('Location: /index.php' . ($error ? '?err=' . urlencode($error) : ''));
    exit;
}

if (session_status() === PHP_SESSION_NONE) session_start();
$user = start_page('My Todos');

if (isset($_GET['err'])) $error = $_GET['err'];

// Load todos
$stmt = db()->prepare('SELECT * FROM todos WHERE user_id = ? ORDER BY is_done ASC, created_at DESC');
$stmt->execute([$user['id']]);
$todos = $stmt->fetchAll();

$done_count  = array_sum(array_column($todos, 'is_done'));
$total_count = count($todos);
?>
<div class="container" style="padding-top:1.5rem">

    <?php if ($error): ?>
        <div class="alert alert-error"><?= h($error) ?></div>
    <?php endif; ?>

    <h1 class="page-title">🍯 <?= h($user['username']) ?>'s Hunny List</h1>
    <p class="page-subtitle">
        <?php if ($total_count === 0): ?>
            Your list is as empty as Pooh's honey pot. Add something!
        <?php else: ?>
            <?= $done_count ?> of <?= $total_count ?> things done
            <?= $done_count === $total_count ? '🎉' : '🐝' ?>
        <?php endif; ?>
    </p>

    <!-- Add todo form -->
    <div class="card">
        <form method="POST" action="/index.php" class="todo-form">
            <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>" />
            <input type="hidden" name="action" value="add" />
            <input type="text" name="title" placeholder="What needs to be done today, Pooh Bear?" maxlength="255" required />
            <button type="submit" class="btn btn-primary">+ Add</button>
        </form>

        <?php if (empty($todos)): ?>
            <div class="todo-empty">
                <span class="bee">🐻</span>
                No todos yet! Start adding things to your hunny list.
            </div>
        <?php else: ?>
            <ul class="todo-list">
                <?php foreach ($todos as $todo): ?>
                    <li class="todo-item <?= $todo['is_done'] ? 'done' : '' ?>">
                        <!-- Toggle done -->
                        <form method="POST" action="/index.php" style="display:contents">
                            <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>" />
                            <input type="hidden" name="action" value="toggle" />
                            <input type="hidden" name="todo_id" value="<?= $todo['id'] ?>" />
                            <button type="submit" class="todo-check <?= $todo['is_done'] ? 'checked' : '' ?>"
                                style="appearance:none;width:22px;height:22px;flex-shrink:0;border:2.5px solid var(--honey);border-radius:7px;background:<?= $todo['is_done'] ? 'var(--honey)' : '#fff' ?>;cursor:pointer;position:relative;font-size:0.8rem;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;">
                                <?= $todo['is_done'] ? '✓' : '' ?>
                            </button>
                        </form>

                        <span class="todo-text"><?= h($todo['title']) ?></span>

                        <!-- Delete -->
                        <form method="POST" action="/index.php" style="display:contents">
                            <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>" />
                            <input type="hidden" name="action" value="delete" />
                            <input type="hidden" name="todo_id" value="<?= $todo['id'] ?>" />
                            <button type="submit" class="todo-delete" title="Delete"
                                onclick="return confirm('Remove this from your hunny list?')">🗑</button>
                        </form>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </div>
</div>
<?php end_page(); ?>