<?php
require __DIR__ . '/../bootstrap.php';

use Identvia\Sdk\Exception\AuthorizationException;
use Identvia\Sdk\Exception\IdentviaException;
use Identvia\Sdk\Exception\InvalidStateException;

// Step 2: Identvia sends the user back here with ?code=…&state=…&iss=…
try {
    $signIn = identvia()->handleCallback($_GET);
} catch (AuthorizationException $e) {
    $_SESSION['flash'] = $e->userCancelled() ? 'Sign-in cancelled.' : 'Identvia could not sign you in (' . $e->error . ').';
    header('Location: /', true, 303); exit;
} catch (InvalidStateException $e) {
    $_SESSION['flash'] = 'That sign-in link expired. Please try again.';
    header('Location: /', true, 303); exit;
} catch (IdentviaException $e) {
    error_log('Identvia sign-in failed: ' . $e->getMessage());
    http_response_code(502);
    page('Sign-in failed', '<h1>Sign-in failed</h1><p>Something went wrong talking to Identvia. Please try again.</p>');
    exit;
}

session_regenerate_id(true); // new session ID after login (session fixation)
$claims = ['sub' => $signIn->sub(), 'email' => $signIn->email(), 'name' => $signIn->name()];
// ID tokens carry email/name; if your app needs the freshest profile, ask the userinfo endpoint.
// The SDK checks that userinfo's "sub" matches the ID token's.
try {
    $profile = identvia()->userinfo($signIn->tokens->accessToken, $signIn->sub());
    $claims['email'] = $profile['email'] ?? $claims['email'];
    $claims['name'] = $profile['name'] ?? $claims['name'];
} catch (IdentviaException $e) {
    error_log('Identvia userinfo failed: ' . $e->getMessage()); // the ID token claims are still good
}
$_SESSION['user'] = $claims;
// Keep tokens server-side only if you need to call Identvia later (userinfo, refresh, revoke).
$_SESSION['tokens'] = $signIn->tokens->toArray();
header('Location: ' . ($signIn->returnTo ?? '/'), true, 303);
