<?php
declare(strict_types=1);

// Identvia Notes: a tiny third-party app that signs people in with the identvia/identvia-php SDK.
// Plain PHP, no framework: drop it on any shared host, point the web root at public/.

require is_file(__DIR__ . '/vendor/autoload.php') ? __DIR__ . '/vendor/autoload.php' : __DIR__ . '/../../vendor/autoload.php';

use Identvia\Sdk\Identvia;

$fileConfig = is_file(__DIR__ . '/config.php') ? require __DIR__ . '/config.php' : [];
$env = static fn (string $k) => ($v = getenv($k)) === false || $v === '' ? null : $v;
$config = [
    'issuer' => $env('IDENTVIA_ISSUER') ?? $fileConfig['issuer'] ?? '',
    'client_id' => $env('IDENTVIA_CLIENT_ID') ?? $fileConfig['client_id'] ?? '',
    'client_secret' => $env('IDENTVIA_CLIENT_SECRET') ?? $fileConfig['client_secret'] ?? null,
    'redirect_uri' => $env('IDENTVIA_REDIRECT_URI') ?? $fileConfig['redirect_uri'] ?? '',
    'scopes' => $fileConfig['scopes'] ?? ['email', 'profile'],
    'cache_dir' => __DIR__ . '/storage/cache',
];
if ($env('IDENTVIA_CA_BUNDLE')) { $config['ca_bundle'] = $env('IDENTVIA_CA_BUNDLE'); }
$ISSUER = rtrim((string) $config['issuer'], '/');

$https = (($_SERVER['HTTPS'] ?? '') !== '' && $_SERVER['HTTPS'] !== 'off');
session_name('notes_sid');
session_start(['cookie_httponly' => true, 'cookie_secure' => $https, 'cookie_samesite' => 'Lax', 'use_strict_mode' => true, 'use_only_cookies' => true]);

// Strict CSP: no inline script or style anywhere. The Identvia button is loaded from the issuer.
$csp = "default-src 'none'; script-src 'self' $ISSUER; style-src 'self' $ISSUER; img-src 'self'; font-src 'self'; connect-src 'self'; "
     . "form-action 'self' $ISSUER; frame-ancestors 'none'; base-uri 'none'";
header('Content-Security-Policy: ' . $csp);
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('Cache-Control: no-store');

function identvia(): Identvia
{
    static $c = null;
    global $config;
    return $c ??= new Identvia($config);
}

function e(?string $s): string { return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function current_user(): ?array { return $_SESSION['user'] ?? null; }

function csrf_token(): string { return $_SESSION['csrf'] ??= bin2hex(random_bytes(16)); }

function check_csrf(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !hash_equals(csrf_token(), (string) ($_POST['csrf'] ?? ''))) {
        http_response_code(400); exit('Bad request');
    }
}

function notes_file(string $sub): string { return __DIR__ . '/storage/notes-' . hash('sha256', $sub) . '.json'; }

function load_notes(string $sub): array
{
    $raw = @file_get_contents(notes_file($sub));
    return $raw ? (json_decode($raw, true) ?: []) : [];
}

function save_notes(string $sub, array $notes): void
{
    file_put_contents(notes_file($sub), json_encode(array_values($notes)), LOCK_EX);
}

function page(string $title, string $body): void
{
    global $ISSUER;
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
       . '<meta name="color-scheme" content="light dark"><title>' . e($title) . ' · Identvia Notes</title>'
       . '<link rel="stylesheet" href="/style.css"><script src="' . e($ISSUER) . '/sdk/v1/button.js" async></script></head><body>'
       . '<header class="top"><a class="brand" href="/"><span class="logo" aria-hidden="true">N</span> Notes</a>'
       . (current_user() ? '<form method="post" action="/logout.php"><input type="hidden" name="csrf" value="' . e(csrf_token()) . '"><button class="link" type="submit">Sign out</button></form>' : '')
       . '</header><main id="main">' . $body . '</main><footer>A demo app for the <a href="' . e($ISSUER) . '/developers/docs/php">Identvia PHP SDK</a>.</footer></body></html>';
}
