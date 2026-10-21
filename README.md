# identvia/identvia-php

Sign in with Identvia for PHP 8.1+. OpenID Connect authorization code flow with PKCE (S256), `state` and
`nonce`, RFC 9207 `iss` check, ID token validation against Identvia's JWKS (cached, key-rotation aware),
userinfo, refresh-token rotation and revocation. No framework needed; works on plain shared hosting.
The only dependency is [firebase/php-jwt](https://github.com/firebase/php-jwt), which does the signature checks.

## Install

* Composer: `composer require identvia/identvia-php`
* No Composer or SSH: download `identvia-php-1.1.0.zip` from your Identvia server
  (`/sdk/php/identvia-php-1.1.0.zip`). It includes `vendor/`. Upload it beside your site and
  `require __DIR__ . '/identvia-php/vendor/autoload.php';`

## Use

```php
$identvia = new Identvia\Sdk\Identvia([
    'issuer'        => 'https://id.example.com',
    'client_id'     => getenv('IDENTVIA_CLIENT_ID'),
    'client_secret' => getenv('IDENTVIA_CLIENT_SECRET'), // omit for public clients
    'redirect_uri'  => 'https://app.example.com/callback.php',
    'scopes'        => ['email', 'profile'],            // openid is always added
]);

// login.php
$identvia->redirectToSignIn(['return_to' => '/dashboard']);

// callback.php
$signIn = $identvia->handleCallback($_GET);   // throws on anything suspicious
$_SESSION['user'] = ['sub' => $signIn->sub(), 'email' => $signIn->email()];
```

Store `sub`, not the email: it is stable and private to your app (pairwise).
Full guide: `/developers/docs/php` on your Identvia server.

## Delegation (token exchange, CIBA, rich authorization requests)

Switch the features on for your environment in the developer console (Delegation card) first.

```php
// RFC 8693: a narrower, short-lived token for another Identvia app; $agentJwt (optional) names the agent → "act" claim
$t = $identvia->tokenExchange($accessToken, audience: 'oid_other_app', scope: 'openid email', actorToken: $agentJwt);

// OpenID CIBA, poll mode
$req = $identvia->cibaAuthorize('person@example.com', scope: 'email', bindingMessage: 'Desk 4 · 7Q2K');
$interval = $req['interval'];
while (($tokens = $identvia->cibaPoll($req['auth_req_id'], $interval)) === null) { sleep($interval); }

// CIBA ping mode: in your notification endpoint
$authReqId = Identvia\Sdk\Identvia::verifyCibaPing($_SERVER['HTTP_AUTHORIZATION'] ?? '', file_get_contents('php://input'), $storedToken);

// RFC 9396 on sign-in
$identvia->redirectToSignIn(['authorization_details' => [['type' => 'agent_task', 'actions' => ['read']]]]);
```

## Tests

`composer install && vendor/bin/phpunit` (29 tests against a fake Identvia with real RSA keys).

## Example

`examples/notes-app/`: a tiny notes app using the button and this SDK under a strict CSP.

MIT licensed.
