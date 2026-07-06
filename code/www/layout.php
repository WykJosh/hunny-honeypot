<?php
// calls start_page() and end_page()
require_once __DIR__ . '/config.php';


$REAL_ADMIN_PATH = getenv('ADMIN_PATH') ?: '/__no_admin_configured__';

function start_page(string $title, bool $requireLogin = true, bool $requireAdmin = false): array
{
    global $REAL_ADMIN_PATH;
    if (session_status() === PHP_SESSION_NONE) session_start();
    $user = [];
    if ($requireAdmin) {
        $user = require_admin();
    } elseif ($requireLogin) {
        $user = require_login();
    }
?>
    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <title><?= h($title) ?> – Hunny Do</title>
        <link rel="stylesheet" href="/css/style.css" />
        <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🍯</text></svg>" />
    </head>

    <body>
        <div class="honeycomb-deco">🍯</div>
        <!-- FIX: /api/internal/ still responds - remove it -->
        <?php if ($requireLogin || $requireAdmin): ?>
            <header>
                <div class="inner">
                    <a href="/index.php" class="logo"><span>🍯</span> Hunny Do</a>
                    <nav>
                        <a href="/index.php">My Todos</a>
                        <a href="/maze.php">Maze</a>
                        <a href="/leaderboard.php">Scores</a>
                        <a href="/chat.php">Chat</a>
                        <a href="/mad-hatter.php">Riddles</a>
                        <a href="/profile.php">Profile</a>
                        <?php if (!empty($user['is_admin'])): ?>
                            <a href="<?= h($REAL_ADMIN_PATH) ?>" class="admin-link">Admin</a>
                        <?php endif; ?>
                        <a href="/logout.php" class="logout">Logout</a>
                    </nav>
                </div>
            </header>
        <?php endif; ?>
        <main>
        <?php return $user;
    }

    function end_page(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if (empty($_SESSION['pooh_chat_csrf'])) {
            $_SESSION['pooh_chat_csrf'] = bin2hex(random_bytes(32));
        }
        ?>
        </main>

        <div class="pooh-chat-widget">
            <div class="pooh-chat-notification" id="poohChatNotification">
                🍯 Need help?
            </div>

            <button class="pooh-chat-bubble" type="button" onclick="togglePoohChat()" title="Ask Pooh">
                <img src="/images/pooh-chat.png" alt="Ask Pooh">
            </button>

            <div class="pooh-chat-panel" id="poohChatPanel">
                <div class="pooh-chat-header">
                    <strong>Pooh Assistant</strong>

                    <div class="pooh-chat-actions">
                        <button type="button" onclick="clearPoohChat()" title="Clear chat">↺</button>
                        <button type="button" onclick="togglePoohChat()">×</button>
                    </div>
                </div>

                <div class="pooh-chat-messages">
                    <div class="pooh-msg bot">
                        Oh bother... how can I help?
                    </div>
                </div>

                <form class="pooh-chat-form">
                    <input type="hidden" id="poohChatCsrf" value="<?= h($_SESSION['pooh_chat_csrf']) ?>">
                    <input type="text" placeholder="Type a message..." autocomplete="off">
                    <button type="submit">Send</button>
                </form>
            </div>
        </div>

        <script>
            const chatForm = document.querySelector('.pooh-chat-form');
            const chatInput = document.querySelector('.pooh-chat-form input[type="text"]');
            const chatMessages = document.querySelector('.pooh-chat-messages');
            const notification = document.getElementById('poohChatNotification');

            function togglePoohChat() {
                document.getElementById('poohChatPanel').classList.toggle('open');

                if (notification) {
                    notification.style.display = 'none';
                }
            }

            function savePoohChat() {
                localStorage.setItem('poohChatHistory', chatMessages.innerHTML);
            }

            function loadPoohChat() {
                const saved = localStorage.getItem('poohChatHistory');

                if (saved) {
                    chatMessages.innerHTML = saved;
                }

                chatMessages.scrollTop = chatMessages.scrollHeight;
            }

            function clearPoohChat() {
                localStorage.removeItem('poohChatHistory');

                chatMessages.innerHTML = `
        <div class="pooh-msg bot">
            Oh bother... how can I help?
        </div>
    `;

                chatMessages.scrollTop = chatMessages.scrollHeight;
            }

            loadPoohChat();

            if (notification) {
                notification.style.display = 'block';

                setTimeout(() => {
                    notification.style.display = 'none';
                }, 5000);
            }

            chatForm.addEventListener('submit', async function(e) {
                e.preventDefault();

                const message = chatInput.value.trim();
                if (!message) return;

                const sendButton = chatForm.querySelector('button[type="submit"]');

                chatInput.disabled = true;
                sendButton.disabled = true;
                sendButton.textContent = '...';

                const userMsg = document.createElement('div');
                userMsg.className = 'pooh-msg user';
                userMsg.textContent = message;
                chatMessages.appendChild(userMsg);

                chatInput.value = "";
                chatMessages.scrollTop = chatMessages.scrollHeight;
                savePoohChat();

                const typingMsg = document.createElement('div');
                typingMsg.className = 'pooh-msg bot pooh-typing';
                typingMsg.textContent = 'Pooh is thinking...';
                chatMessages.appendChild(typingMsg);
                chatMessages.scrollTop = chatMessages.scrollHeight;

                try {
                    const response = await fetch('pooh-bot.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            message,
                            csrf: document.getElementById('poohChatCsrf').value
                        })
                    });

                    const data = await response.json();

                    await new Promise(resolve => setTimeout(resolve, 1200));

                    typingMsg.remove();

                    const botMsg = document.createElement('div');
                    botMsg.className = 'pooh-msg bot';
                    botMsg.textContent = data.reply;
                    chatMessages.appendChild(botMsg);

                    chatMessages.scrollTop = chatMessages.scrollHeight;
                    savePoohChat();

                } catch (error) {
                    typingMsg.remove();

                    const errorMsg = document.createElement('div');
                    errorMsg.className = 'pooh-msg bot';
                    errorMsg.textContent = 'Oh bother... something went wrong.';
                    chatMessages.appendChild(errorMsg);

                    chatMessages.scrollTop = chatMessages.scrollHeight;
                    savePoohChat();

                } finally {
                    chatInput.disabled = false;
                    sendButton.disabled = false;
                    sendButton.textContent = 'Send';
                    chatInput.focus();
                }
            });

            document.addEventListener('click', function(e) {
                const widget = document.querySelector('.pooh-chat-widget');
                const panel = document.getElementById('poohChatPanel');

                if (!widget.contains(e.target) && panel.classList.contains('open')) {
                    panel.classList.remove('open');
                }
            });
        </script>

    </body>

    </html>
<?php } ?>