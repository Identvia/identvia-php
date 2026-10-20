<?php
// Copy to config.php and fill in the values from the Identvia developer console
// (Apps → your app → environment). Or set the IDENTVIA_* environment variables instead.
return [
    'issuer'        => 'https://id.example.com',
    'client_id'     => 'oid_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'client_secret' => 'ivs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', // keep this out of git
    'redirect_uri'  => 'https://notes.example.com/callback.php',
    'scopes'        => ['email', 'profile'],
];
