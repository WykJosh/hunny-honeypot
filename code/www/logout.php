<?php
require_once __DIR__ . '/config.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$user = $_SESSION['user'] ?? null;
if ($user) {
    log_event('LOGOUT', $user['id'], $user['username'], '');
}
session_unset();
session_destroy();
header('Location: /login.php');
exit;
