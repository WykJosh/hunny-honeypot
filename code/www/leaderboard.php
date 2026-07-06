<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/layout.php';

if (session_status() === PHP_SESSION_NONE) session_start();
$user = start_page('Leaderboard');

// Top 20 scores (best score per user)
$topScores = db()->query(
    'SELECT gs.*, u.username, u.avatar,
            ROW_NUMBER() OVER (ORDER BY gs.score DESC) as rank_num
     FROM game_scores gs
     JOIN users u ON u.id = gs.user_id
     WHERE gs.game = "maze"
     AND gs.score = (
         SELECT MAX(gs2.score) FROM game_scores gs2
         WHERE gs2.user_id = gs.user_id AND gs2.game = "maze"
     )
     GROUP BY gs.user_id
     ORDER BY gs.score DESC
     LIMIT 20'
)->fetchAll();

// Current user's stats
$stmt = db()->prepare(
    'SELECT MAX(score) as best, MIN(time_sec) as fastest, COUNT(*) as plays
     FROM game_scores WHERE user_id = ? AND game = ?'
);
$stmt->execute([$user['id'], 'maze']);
$myStats = $stmt->fetch();
?>
<div class="container" style="padding-top:1.5rem">
    <h1 class="page-title">Leaderboard</h1>
    <p class="page-subtitle">
        Top maze runners in the Hundred Acre Wood
    </p>

    <?php if ($myStats['plays'] > 0): ?>
    <div class="card" style="text-align:center;padding:1.2rem">
        <span style="font-size:0.85rem;color:var(--bark-light)">Your stats</span>
        <div style="display:flex;justify-content:center;gap:2rem;margin-top:0.5rem">
            <div>
                <div style="font-family:'Luckiest Guy',cursive;font-size:1.6rem;color:var(--honey-dark)"><?= (int)$myStats['best'] ?></div>
                <div style="font-size:0.8rem;color:var(--bark-light)">Best score</div>
            </div>
            <div>
                <div style="font-family:'Luckiest Guy',cursive;font-size:1.6rem;color:var(--honey-dark)"><?= round($myStats['fastest'], 1) ?>s</div>
                <div style="font-size:0.8rem;color:var(--bark-light)">Fastest time</div>
            </div>
            <div>
                <div style="font-family:'Luckiest Guy',cursive;font-size:1.6rem;color:var(--honey-dark)"><?= (int)$myStats['plays'] ?></div>
                <div style="font-size:0.8rem;color:var(--bark-light)">Games played</div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <div class="card">
        <?php if (empty($topScores)): ?>
            <div style="text-align:center;padding:2rem;color:var(--bark-light)">
                <span style="font-size:2.5rem;display:block;margin-bottom:0.5rem">🏆</span>
                No scores yet! Be the first to <a href="/maze.php" style="color:var(--honey-dark);font-weight:700">play the maze</a>.
            </div>
        <?php else: ?>
            <ol class="leaderboard-list">
                <?php foreach ($topScores as $i => $entry): ?>
                <li class="leaderboard-item" <?php if ((int)$entry['user_id'] === (int)$user['id']): ?>style="background:var(--honey-light);border-radius:10px;padding:0.75rem 1rem"<?php endif; ?>>
                    <span class="leaderboard-rank <?php
                        if ($i === 0) echo 'gold';
                        elseif ($i === 1) echo 'silver';
                        elseif ($i === 2) echo 'bronze';
                    ?>">
                        <?php if ($i === 0): ?>🥇
                        <?php elseif ($i === 1): ?>🥈
                        <?php elseif ($i === 2): ?>🥉
                        <?php else: ?><?= $i + 1 ?><?php endif; ?>
                    </span>
                    <span class="leaderboard-name">
                        <?php if (!empty($entry['avatar']) && file_exists(UPLOAD_DIR . $entry['avatar'])): ?>
                            <img src="<?= h(UPLOAD_URL . $entry['avatar']) ?>"
                                 style="width:24px;height:24px;border-radius:50%;object-fit:cover;vertical-align:middle;margin-right:0.4rem;border:2px solid var(--honey)"/>
                        <?php endif; ?>
                        <?= h($entry['username']) ?>
                        <?php if ((int)$entry['user_id'] === (int)$user['id']): ?>
                            <span style="font-size:0.75rem;color:var(--bark-light)">(you)</span>
                        <?php endif; ?>
                    </span>
                    <span class="leaderboard-score"><?= (int)$entry['score'] ?> pts</span>
                    <span style="font-size:0.8rem;color:var(--bark-light);margin-left:0.5rem"><?= round($entry['time_sec'], 1) ?>s</span>
                </li>
                <?php endforeach; ?>
            </ol>
        <?php endif; ?>
    </div>

    <div style="text-align:center;margin-top:1rem">
        <a href="/maze.php" class="btn btn-primary">Play the Maze</a>
    </div>
</div>
<?php end_page(); ?>
