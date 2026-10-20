# identvia/identvia-php

Sign in with Identvia for PHP 8.1+. OpenID Connect authorization code flow with PKCE (S256), `state` and
`nonce`, RFC 9207 `iss` check, ID token validation against Identvia's JWKS (cached, key-rotation aware),
userinfo, refresh-token rotation and revocation. No framework needed; works on plain shared hosting.
The only dependency is [firebase/php-jwt](https://github.com/firebase/php-jwt), which does the signature checks.

## Install

* Composer: `composer require identvia/identvia-php`
* No Composer or SSH: download `identvia-php-1.0.0.zip` from your Identvia server
  (`/sdk/php/identvia-php-1.0.0.zip`). It includes `vendor/`. Upload it beside your site and
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

## Tests

`composer install && vendor/bin/phpunit` (29 tests against a fake Identvia with real RSA keys).

## Example

`examples/notes-app/`: a tiny notes app using the button and this SDK under a strict CSP.

MIT licensed.
