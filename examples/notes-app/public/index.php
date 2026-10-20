<?php
require __DIR__ . '/../bootstrap.php';

$user = current_user();
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
$f = $flash ? '<p class="flash" role="status">' . e($flash) . '</p>' : '';

if (!$user) {
    page('Welcome', $f . '<section class="hero"><h1>Your notes, everywhere.</h1><p>Sign in to keep a few private notes. No password to remember.</p>'
        . '<a class="identvia-btn" href="/login.php" data-theme="auto" data-size="large" data-testid="signin">Sign in with Identvia</a>'
        . '<p class="small">We only receive your email address and name if you choose to share them.</p></section>');
    exit;
}

$notes = load_notes($user['sub']);
$list = '';
foreach (array_reverse($notes, true) as $i => $n) {
    $list .= '<li><p>' . e($n['text']) . '</p><form method="post" action="/notes.php"><input type="hidden" name="csrf" value="' . e(csrf_token()) . '">'
           . '<input type="hidden" name="delete" value="' . (int) $i . '"><button class="link" type="submit" aria-label="Delete note">Delete</button></form></li>';
}
page('Your notes', $f . '<section><h1>Hi, ' . e($user['name'] ?: $user['email'] ?: 'there') . '</h1>'
    . '<p class="small" data-testid="whoami">Signed in with Identvia as <strong>' . e($user['email'] ?? 'no email shared') . '</strong>'
    . ' · your ID in this app: <code data-testid="sub">' . e($user['sub']) . '</code></p>'
    . '<form class="new" method="post" action="/notes.php"><input type="hidden" name="csrf" value="' . e(csrf_token()) . '">'
    . '<label for="text">New note</label><textarea id="text" name="text" rows="3" maxlength="2000" required></textarea><button type="submit">Save note</button></form>'
    . '<ul class="notes" data-testid="notes">' . ($list ?: '<li class="empty">No notes yet.</li>') . '</ul></section>');
