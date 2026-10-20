# Identvia Notes — example app

A small third-party app that lets people sign in with Identvia using **identvia/identvia-php**.
Plain PHP 8.1+, no framework, no database; notes are saved as JSON files in `storage/`.

## Run it locally

1. In the Identvia developer console create an app with a **Development** environment,
   type **Server-side (confidential)**, redirect URI `http://localhost:9999/callback.php`.
2. `cp config.example.php config.php` and paste the issuer, client ID, secret and redirect URI.
3. `php -S localhost:9999 -t public`
4. Open http://localhost:9999 and press **Sign in with Identvia**.

## Deploy on shared hosting (cPanel)

* Upload the whole `identvia-php/` folder from the SDK download (it already contains `vendor/`;
  the example loads `../../vendor/autoload.php`) and point the domain's document root at
  `identvia-php/examples/notes-app/public/`. If you can't change the document root, the `.htaccess`
  files keep `config.php` and `storage/` private.
* Add a **Production** environment in the console with `https://your-domain/callback.php` and put its
  credentials in `config.php` (or the `IDENTVIA_*` environment variables).
* Make `storage/` writable by PHP.

What the files do: `login.php` starts sign-in, `callback.php` finishes it (state, PKCE, nonce and the
ID token are all checked by the SDK), `logout.php` revokes the tokens at Identvia and ends the session.
`callback.php` also calls the userinfo endpoint to show how (the SDK checks its `sub` matches the ID token).
The pages send a strict Content-Security-Policy; the button script is allowed from the issuer only.
