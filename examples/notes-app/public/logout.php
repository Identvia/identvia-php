<?php
require __DIR__ . '/../bootstrap.php';
check_csrf();

$tokens = $_SESSION['tokens'] ?? null;
// Revoke what Identvia gave us (best effort): the refresh token if any (this also kills its access tokens), else the access token.
try {
    if (!empty($tokens['refresh_token'])) { identvia()->revoke($tokens['refresh_token']); }
    elseif (!empty($tokens['access_token'])) { identvia()->revoke($tokens['access_token'], 'access_token'); }
} catch (\Throwable) { /* best effort */ }
$_SESSION = [];
session_regenerate_id(true);
$_SESSION['flash'] = 'You are signed out of Notes.';
header('Location: /', true, 303);
