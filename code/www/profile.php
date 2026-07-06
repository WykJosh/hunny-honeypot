<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/layout.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (session_status() === PHP_SESSION_NONE) session_start();
    $user = require_login();

    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $action = $_POST['action'] ?? '';

        // Update email
        if ($action === 'update_profile') {
            $email = trim($_POST['email'] ?? '');

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $error = 'Enter a valid email address.';
            } else {
                // Check email not taken by someone else
                $stmt = db()->prepare('SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1');
                $stmt->execute([$email, $user['id']]);
                if ($stmt->fetch()) {
                    $error = 'Email already in use by another account.';
                } else {
                    $stmt = db()->prepare('UPDATE users SET email = ? WHERE id = ?');
                    $stmt->execute([$email, $user['id']]);
                    // Refresh session
                    $_SESSION['user']['email'] = $email;
                    $success = 'Profile updated!';
                    log_event(
                        'PROFILE_UPDATE',
                        $user['id'],
                        $user['username'],
                        json_encode(['email_changed' => true])
                    );
                }
            }
        }
    }
    // Avatar upload
    if ($action === 'upload_avatar' && isset($_FILES['avatar'])) {
        $file = $_FILES['avatar'];

        if ($file['error'] !== UPLOAD_ERR_OK) {
            $error = 'Upload error. Try again.';
        } elseif ($file['size'] > MAX_AVATAR_SIZE) {
            $error = 'Image too large (max 2 MB).';
        } elseif (!is_uploaded_file($file['tmp_name'])) {
            $error = 'Invalid upload.';
        } else {
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime = $finfo->file($file['tmp_name']);

            if (!in_array($mime, ALLOWED_IMAGE_TYPES, true)) {
                $error = 'Only JPEG, PNG or WebP images are allowed.';
                log_event('AVATAR_UPLOAD', $user['id'], $user['username'], 'Rejected: bad mime ' . ($mime ?: 'unknown'));
            } else {
                $imgInfo = @getimagesize($file['tmp_name']);

                if (!$imgInfo || ($imgInfo['mime'] ?? '') !== $mime) {
                    $error = 'Invalid image file.';
                    log_event('AVATAR_UPLOAD', $user['id'], $user['username'], 'Rejected: image validation mismatch');
                } else {
                    $image = match ($mime) {
                        'image/jpeg' => @imagecreatefromjpeg($file['tmp_name']),
                        'image/png'  => @imagecreatefrompng($file['tmp_name']),
                        'image/webp' => @imagecreatefromwebp($file['tmp_name']),
                        default      => false,
                    };

                    if (!$image) {
                        $error = 'Could not process image.';
                        log_event('AVATAR_UPLOAD', $user['id'], $user['username'], 'Rejected: image decode failed');
                    } else {
                        if (!is_dir(UPLOAD_DIR)) {
                            mkdir(UPLOAD_DIR, 0755, true);
                        }

                        $filename = 'avatar_' . $user['id'] . '_' . bin2hex(random_bytes(8)) . '.png';
                        $destPath = UPLOAD_DIR . $filename;

                        imagealphablending($image, false);
                        imagesavealpha($image, true);

                        if (!imagepng($image, $destPath)) {
                            imagedestroy($image);
                            $error = 'Failed to save image. Try again.';
                        } else {
                            imagedestroy($image);
                            chmod($destPath, 0644);

                            if (!empty($user['avatar'])) {
                                $old = UPLOAD_DIR . basename($user['avatar']);
                                if (file_exists($old)) @unlink($old);
                            }

                            $stmt = db()->prepare('UPDATE users SET avatar = ? WHERE id = ?');
                            $stmt->execute([$filename, $user['id']]);
                            $_SESSION['user']['avatar'] = $filename;
                            $success = 'Avatar updated!';
                            log_event('AVATAR_UPLOAD', $user['id'], $user['username'], json_encode(['file' => $filename]));
                        }
                    }
                }
            }
        }
    }
}

if (session_status() === PHP_SESSION_NONE) session_start();
$user = start_page('My Profile');

// Fresh data from DB
$stmt = db()->prepare('SELECT * FROM users WHERE id = ? LIMIT 1');
$stmt->execute([$user['id']]);
$dbUser = $stmt->fetch();
?>
<div class="container" style="padding-top:1.5rem">
    <?php if ($error):   ?><div class="alert alert-error"><?= h($error) ?></div><?php endif; ?>
    <?php if ($success): ?><div class="alert alert-success"><?= h($success) ?></div><?php endif; ?>

    <h1 class="page-title">🐝 My Profile</h1>

    <!-- Avatar -->
    <div class="card">
        <div class="avatar-wrap">
            <?php if (!empty($dbUser['avatar']) && file_exists(UPLOAD_DIR . $dbUser['avatar'])): ?>
                <img src="<?= h(UPLOAD_URL . $dbUser['avatar']) ?>"
                    alt="Avatar" class="avatar-img" />
            <?php else: ?>
                <div class="avatar-placeholder">🐻</div>
            <?php endif; ?>
            <strong><?= h($dbUser['username']) ?></strong>
            <?php if ($dbUser['is_admin']): ?>
                <span class="badge badge-admin" style="margin-top:0.3rem">Admin</span>
            <?php endif; ?>
        </div>

        <form method="POST" action="/profile.php" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>" />
            <input type="hidden" name="action" value="upload_avatar" />
            <div class="form-group">
                <label for="avatar">Upload new avatar <span class="text-muted">(JPEG/PNG/WebP, max 2 MB)</span></label>
                <div class="btn-over">
                    <label for="avatar" class="btn btn-primary btn-sm">📁 Choose File</label>
                    <span id="file-name" class="text-muted" style="font-size:0.85rem;">No file chosen</span>
                </div>
                <input type="file" id="avatar" name="avatar" accept="image/jpeg,image/png,image/webp"
                    style="padding:0.5rem; background:#fff;" onchange="document.getElementById('file-name').textContent = this.files[0]?.name || 'No file chosen'" />
            </div>
            <button type="submit" class="btn btn-primary btn-sm">🍯 Upload Avatar</button>
        </form>
    </div>

    <hr class="honey-divider" />

    <!-- Update email -->
    <div class="card">
        <h2 style="font-family:'Luckiest Guy',cursive;color:var(--honey-dark);margin-bottom:1rem;font-size:1.3rem">
            Update Details
        </h2>
        <form method="POST" action="/profile.php">
            <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>" />
            <input type="hidden" name="action" value="update_profile" />
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email"
                    value="<?= h($dbUser['email']) ?>" required maxlength="100" />
            </div>
            <button type="submit" class="btn btn-primary">💾 Save Changes</button>
        </form>
    </div>
</div>
<?php end_page(); ?>