<?php
require __DIR__ . '/../bootstrap.php';
check_csrf();
$user = current_user();
if (!$user) { header('Location: /login.php', true, 303); exit; }
$notes = load_notes($user['sub']);
if (isset($_POST['delete'])) {
    unset($notes[(int) $_POST['delete']]);
} else {
    $text = trim(mb_substr((string) ($_POST['text'] ?? ''), 0, 2000));
    if ($text !== '') { $notes[] = ['text' => $text, 'at' => time()]; }
}
save_notes($user['sub'], $notes);
header('Location: /', true, 303);
