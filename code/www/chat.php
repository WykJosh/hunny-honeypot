<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/layout.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (session_status() === PHP_SESSION_NONE) session_start();
    $user = require_login();

    // Hidden honeypot field
    if (!empty($_POST['fax_number'] ?? '')) {
        log_honeypot('hidden_field_chat', 'trap', [
            'field_value' => $_POST['fax_number'],
        ]);
        header('Location: /chat.php');
        exit;
    }

    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $content = trim($_POST['content'] ?? '');

        if ($content === '') {
            $error = 'Message cannot be empty.';
        } elseif (mb_strlen($content) > 500) {
            $error = 'Message is too long (max 500 characters).';
        } else {
            $stmt = db()->prepare('INSERT INTO messages (user_id, content) VALUES (?, ?)');
            $stmt->execute([$user['id'], $content]);
            log_event(
                'CHAT_MESSAGE',
                $user['id'],
                $user['username'],
                json_encode(['length' => mb_strlen($content)])
            );
        }
    }
    header('Location: /chat.php');
    exit;
}

if (session_status() === PHP_SESSION_NONE) session_start();
$user = start_page('Chat');

// Load recent messages (last 100)
$stmt = db()->prepare(
    'SELECT m.*, u.username, u.avatar
     FROM messages m
     JOIN users u ON u.id = m.user_id
     ORDER BY m.created_at DESC
     LIMIT 100'
);
$stmt->execute();
$messages = $stmt->fetchAll();
// chat reads top-to-bottom
$messages = array_reverse($messages);
?>
<div class="container" style="padding-top:1.5rem">
    <?php if ($error): ?>
        <div class="alert alert-error"><?= h($error) ?></div>
    <?php endif; ?>

    <h1 class="page-title">Hundred Acre Chat</h1>
    <p class="page-subtitle">Talk with your friends in the wood</p>

    <div class="card">
        <div class="chat-messages" id="chatMessages">
            <?php if (empty($messages)): ?>
                <div style="text-align:center;padding:2rem;color:var(--bark-light)">
                    <span style="font-size:2.5rem;display:block;margin-bottom:0.5rem">🐻</span>
                    No messages yet. Say something nice!
                </div>
            <?php else: ?>
                <?php foreach ($messages as $msg): ?>
                    <div class="chat-bubble">
                        <div class="chat-bubble-avatar">
                            <?php if (!empty($msg['avatar']) && file_exists(UPLOAD_DIR . $msg['avatar'])): ?>
                                <img src="<?= h(UPLOAD_URL . $msg['avatar']) ?>"
                                    style="width:32px;height:32px;border-radius:50%;object-fit:cover" />
                            <?php else: ?>
                                🐻
                            <?php endif; ?>
                        </div>
                        <div class="chat-bubble-body">
                            <div class="chat-bubble-name"><?= h($msg['username']) ?></div>
                            <div class="chat-bubble-text"><?= h($msg['content']) ?></div>
                            <div class="chat-bubble-time"><?= h(date('M j, g:ia', strtotime($msg['created_at']))) ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <form method="POST" action="/chat.php" class="chat-form">
            <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>" />
            <div style="position:absolute;left:-9999px" aria-hidden="true">
                <input type="text" name="fax_number" tabindex="-1" autocomplete="off" />
            </div>
            <input type="text" name="content" placeholder="Type a message..." maxlength="500" required
                autocomplete="off" />
            <button type="submit" class="btn btn-primary">Send</button>
        </form>
    </div>
</div>

<script>
    // Auto-scroll chat to bottom
    var c = document.getElementById('chatMessages');
    if (c) c.scrollTop = c.scrollHeight;
</script>
<?php end_page(); ?>