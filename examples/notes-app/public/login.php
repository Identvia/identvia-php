<?php
require __DIR__ . '/../bootstrap.php';

// Step 1: send the user to Identvia. The SDK stores state, nonce and the PKCE verifier in the session.
identvia()->redirectToSignIn(['return_to' => $_GET['return_to'] ?? '/']);
