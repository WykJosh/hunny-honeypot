<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/layout.php';

// Handle score submission via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (session_status() === PHP_SESSION_NONE) session_start();
    $user = require_login();

    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid request']);
        exit;
    }

    $score   = (int)($_POST['score'] ?? 0);
    $timeSec = (float)($_POST['time_sec'] ?? 0);

    if ($score > 0 && $timeSec > 0) {
        $stmt = db()->prepare('INSERT INTO game_scores (user_id, game, score, time_sec) VALUES (?, ?, ?, ?)');
        $stmt->execute([$user['id'], 'maze', $score, $timeSec]);
        log_event(
            'GAME_SCORE',
            $user['id'],
            $user['username'],
            json_encode(['game' => 'maze', 'score' => $score, 'time' => $timeSec])
        );
    }

    header('Content-Type: application/json');
    echo json_encode(['ok' => true]);
    exit;
}

if (session_status() === PHP_SESSION_NONE) session_start();
$user = start_page('Maze Game');

// Get user's best score
$stmt = db()->prepare('SELECT MAX(score) as best, MIN(time_sec) as fastest FROM game_scores WHERE user_id = ? AND game = ?');
$stmt->execute([$user['id'], 'maze']);
$personal = $stmt->fetch();
?>
<div class="container" style="padding-top:1.5rem">
    <h1 class="page-title">The Hundred Acre Maze</h1>
    <p class="page-subtitle">
        Help Pooh find his honey! Use arrow keys or WASD to navigate.
        <?php if ($personal['best']): ?>
            Your best: <?= (int)$personal['best'] ?> pts (<?= round($personal['fastest'], 1) ?>s)
        <?php endif; ?>
    </p>

    <div class="card" style="text-align:center">
        <canvas id="mazeCanvas" width="360" height="360"
            style="border:3px solid var(--honey);border-radius:12px;max-width:100%;cursor:crosshair;background:#fffbeb"></canvas>

        <div id="gameStatus" style="margin-top:1rem;font-weight:600;font-size:1.1rem;color:var(--honey-dark)">
            Press any arrow key to start!
        </div>

        <div style="display:flex;justify-content:center;gap:2rem;margin-top:0.8rem">
            <div>
                <span style="font-size:0.85rem;color:var(--bark-light)">Time</span>
                <div id="timer" style="font-family:'Luckiest Guy',cursive;font-size:1.5rem;color:var(--honey-dark)">0.0s</div>
            </div>
            <div>
                <span style="font-size:0.85rem;color:var(--bark-light)">Moves</span>
                <div id="moves" style="font-family:'Luckiest Guy',cursive;font-size:1.5rem;color:var(--honey-dark)">0</div>
            </div>
        </div>

        <div style="margin-top:1rem">
            <button onclick="resetGame()" class="btn btn-outline btn-sm">New Maze</button>
            <a href="/leaderboard.php" class="btn btn-primary btn-sm" style="margin-left:0.5rem">Leaderboard</a>
        </div>
    </div>
</div>

<script>
    (function() {
        var canvas = document.getElementById('mazeCanvas');
        var ctx = canvas.getContext('2d');
        var CELL = 36,
            COLS = 10,
            ROWS = 10;
        canvas.width = COLS * CELL;
        canvas.height = ROWS * CELL;

        var maze, player, honey, moves, startTime, timerInterval, gameActive, gameStarted;
        var csrf = '<?= h(csrf_token()) ?>';

        function initMaze() {
            // Generate maze using recursive backtracker
            maze = [];
            for (var r = 0; r < ROWS; r++) {
                maze[r] = [];
                for (var c = 0; c < COLS; c++) {
                    maze[r][c] = {
                        top: true,
                        right: true,
                        bottom: true,
                        left: true,
                        visited: false
                    };
                }
            }
            var stack = [{
                r: 0,
                c: 0
            }];
            maze[0][0].visited = true;

            while (stack.length > 0) {
                var cur = stack[stack.length - 1];
                var neighbors = [];
                var dirs = [{
                        dr: -1,
                        dc: 0,
                        wall: 'top',
                        opp: 'bottom'
                    }, {
                        dr: 1,
                        dc: 0,
                        wall: 'bottom',
                        opp: 'top'
                    },
                    {
                        dr: 0,
                        dc: -1,
                        wall: 'left',
                        opp: 'right'
                    }, {
                        dr: 0,
                        dc: 1,
                        wall: 'right',
                        opp: 'left'
                    }
                ];
                for (var i = 0; i < dirs.length; i++) {
                    var nr = cur.r + dirs[i].dr,
                        nc = cur.c + dirs[i].dc;
                    if (nr >= 0 && nr < ROWS && nc >= 0 && nc < COLS && !maze[nr][nc].visited) {
                        neighbors.push({
                            r: nr,
                            c: nc,
                            wall: dirs[i].wall,
                            opp: dirs[i].opp
                        });
                    }
                }
                if (neighbors.length > 0) {
                    var next = neighbors[Math.floor(Math.random() * neighbors.length)];
                    maze[cur.r][cur.c][next.wall] = false;
                    maze[next.r][next.c][next.opp] = false;
                    maze[next.r][next.c].visited = true;
                    stack.push({
                        r: next.r,
                        c: next.c
                    });
                } else {
                    stack.pop();
                }
            }
        }

        function draw() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // Draw cells
            ctx.strokeStyle = '#c8780a';
            ctx.lineWidth = 2;
            for (var r = 0; r < ROWS; r++) {
                for (var c = 0; c < COLS; c++) {
                    var x = c * CELL,
                        y = r * CELL;
                    var cell = maze[r][c];
                    if (cell.top) {
                        ctx.beginPath();
                        ctx.moveTo(x, y);
                        ctx.lineTo(x + CELL, y);
                        ctx.stroke();
                    }
                    if (cell.right) {
                        ctx.beginPath();
                        ctx.moveTo(x + CELL, y);
                        ctx.lineTo(x + CELL, y + CELL);
                        ctx.stroke();
                    }
                    if (cell.bottom) {
                        ctx.beginPath();
                        ctx.moveTo(x, y + CELL);
                        ctx.lineTo(x + CELL, y + CELL);
                        ctx.stroke();
                    }
                    if (cell.left) {
                        ctx.beginPath();
                        ctx.moveTo(x, y);
                        ctx.lineTo(x, y + CELL);
                        ctx.stroke();
                    }
                }
            }

            // Draw honey pot (goal)
            ctx.font = '22px serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('🍯', honey.c * CELL + CELL / 2, honey.r * CELL + CELL / 2);

            // Draw Pooh (player)
            ctx.font = '22px serif';
            ctx.fillText('🐻', player.c * CELL + CELL / 2, player.r * CELL + CELL / 2);
        }

        function move(dr, dc) {
            if (!gameActive) return;
            if (!gameStarted) {
                gameStarted = true;
                startTime = Date.now();
                timerInterval = setInterval(updateTimer, 100);
            }

            var cell = maze[player.r][player.c];
            var nr = player.r + dr,
                nc = player.c + dc;

            // Check walls
            if (dr === -1 && cell.top) return;
            if (dr === 1 && cell.bottom) return;
            if (dc === -1 && cell.left) return;
            if (dc === 1 && cell.right) return;
            if (nr < 0 || nr >= ROWS || nc < 0 || nc >= COLS) return;

            player.r = nr;
            player.c = nc;
            moves++;
            document.getElementById('moves').textContent = moves;
            draw();

            // Check win
            if (player.r === honey.r && player.c === honey.c) {
                gameActive = false;
                clearInterval(timerInterval);
                var timeSec = (Date.now() - startTime) / 1000;
                var score = Math.max(1, Math.round(10000 / (moves + timeSec)));
                document.getElementById('gameStatus').textContent =
                    'You found the honey! Score: ' + score + ' pts (' + timeSec.toFixed(1) + 's)';
                document.getElementById('gameStatus').style.color = '#15803d';
                submitScore(score, timeSec);
            }
        }

        function updateTimer() {
            if (startTime) {
                var t = (Date.now() - startTime) / 1000;
                document.getElementById('timer').textContent = t.toFixed(1) + 's';
            }
        }

        function submitScore(score, timeSec) {
            var form = new FormData();
            form.append('csrf_token', csrf);
            form.append('score', score);
            form.append('time_sec', timeSec.toFixed(2));
            fetch('/maze.php', {
                method: 'POST',
                body: form
            });
        }

        window.resetGame = function() {
            clearInterval(timerInterval);
            initMaze();
            player = {
                r: 0,
                c: 0
            };
            honey = {
                r: ROWS - 1,
                c: COLS - 1
            };
            moves = 0;
            startTime = null;
            gameActive = true;
            gameStarted = false;
            document.getElementById('moves').textContent = '0';
            document.getElementById('timer').textContent = '0.0s';
            document.getElementById('gameStatus').textContent = 'Press any arrow key to start!';
            document.getElementById('gameStatus').style.color = 'var(--honey-dark)';
            draw();
        };

        document.addEventListener('keydown', function(e) {
            switch (e.key) {
                case 'ArrowUp':
                case 'w':
                case 'W':
                    e.preventDefault();
                    move(-1, 0);
                    break;
                case 'ArrowDown':
                case 's':
                case 'S':
                    e.preventDefault();
                    move(1, 0);
                    break;
                case 'ArrowLeft':
                case 'a':
                case 'A':
                    e.preventDefault();
                    move(0, -1);
                    break;
                case 'ArrowRight':
                case 'd':
                case 'D':
                    e.preventDefault();
                    move(0, 1);
                    break;
            }
        });

        resetGame();
    })();
</script>
<?php end_page(); ?>