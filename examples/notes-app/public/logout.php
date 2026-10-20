<?php
require __DIR__ . '/../bootstrap.php';
check_csrf();

$tokens = $_SESSION['tokens'] ?? null;
if (!empty($tokens['refresh_token'])) {
    try { identvia()->revoke($tokens['refresh_token']); } catch (\Throwable) { /* best effort */ }
}
$_SESSION = [];
session_regenerate_id(true);
$_SESSION['flash'] = 'You are signed out of Notes.';
header('Location: /', true, 303);
