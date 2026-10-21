<?php
declare(strict_types=1);

namespace Identvia\Sdk\Tests;

use Firebase\JWT\JWT;
use Identvia\Sdk\Http\HttpClient;
use Identvia\Sdk\Http\Response;

/** An in-memory Identvia: discovery, JWKS, token, userinfo and revocation endpoints with real RSA/EC signatures. */
final class FakeIdentvia implements HttpClient
{
    public const ISSUER = 'https://id.example.test';
    public const CLIENT = 'oid_0123456789abcdef0123456789abcdef';
    public const SECRET = 'ivs_test-secret_value';
    public const REDIRECT = 'https://app.example.test/callback.php';

    /** @var list<array{method:string,url:string,headers:array,body:?string}> */
    public array $requests = [];
    /** @var array<string, array{0:\OpenSSLAsymmetricKey,1:array,2:string}> kid => [private, public jwk, alg] */
    public array $keys = [];
    public array $publishedKids = [];
    /** @var array<string, array> code => [challenge, claims overrides] */
    public array $codes = [];
    public array $claimsOverride = [];
    public ?string $signKid = null;
    public array $discoveryOverride = [];
    public ?array $tokenError = null;
    public string $accessToken = 'at_live_token_value';
    public ?string $idTokenOverride = null;
    public array $userinfo = [];
    public int $now;
    /** CIBA: auth_req_id => 'pending' | 'slow' | 'approved' | 'denied' | 'expired' */
    public array $ciba = [];
    public ?array $lastForm = null;

    public function __construct()
    {
        $this->now = time();
        $this->addKey('rsa-1', 'RS256');
        $this->signKid = 'rsa-1';
    }

    public function addKey(string $kid, string $alg, bool $publish = true): void
    {
        $k = $alg === 'ES256'
            ? openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'])
            : openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $d = openssl_pkey_get_details($k);
        $b = fn ($s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $jwk = $alg === 'ES256'
            ? ['kty' => 'EC', 'crv' => 'P-256', 'x' => $b($d['ec']['x']), 'y' => $b($d['ec']['y']), 'kid' => $kid, 'use' => 'sig', 'alg' => 'ES256']
            : ['kty' => 'RSA', 'n' => $b($d['rsa']['n']), 'e' => $b($d['rsa']['e']), 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256'];
        $this->keys[$kid] = [$k, $jwk, $alg];
        if ($publish) { $this->publishedKids[] = $kid; }
    }

    public function issueCode(string $challenge, string $nonce): string
    {
        $code = 'code_' . bin2hex(random_bytes(8));
        $this->codes[$code] = ['challenge' => $challenge, 'nonce' => $nonce];
        return $code;
    }

    public function idToken(array $claims = [], ?string $kid = null): string
    {
        $kid ??= $this->signKid;
        [$priv, , $alg] = $this->keys[$kid];
        $base = ['iss' => self::ISSUER, 'aud' => self::CLIENT, 'azp' => self::CLIENT, 'sub' => 'pw_user_123', 'iat' => $this->now, 'exp' => $this->now + 300,
            'auth_time' => $this->now - 5, 'email' => 'ada@example.test', 'email_verified' => true, 'name' => 'Ada', 'amr' => ['hwk', 'user'],
            'at_hash' => \Identvia\Sdk\IdTokenValidator::atHash($this->accessToken)];
        $c = array_filter(array_merge($base, $this->claimsOverride, $claims), fn ($v) => $v !== null);
        openssl_pkey_export($priv, $pem);
        return JWT::encode($c, $pem, $alg, $kid);
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null): Response
    {
        $this->requests[] = compact('method', 'url', 'headers', 'body');
        $path = substr($url, strlen(self::ISSUER));
        $json = fn (int $s, array $d) => new Response($s, (string) json_encode($d), ['content-type' => 'application/json']);
        switch (strtok($path, '?')) {
            case '/.well-known/openid-configuration':
                return $json(200, array_merge([
                    'issuer' => self::ISSUER, 'authorization_endpoint' => self::ISSUER . '/oauth/authorize', 'token_endpoint' => self::ISSUER . '/oauth/token',
                    'userinfo_endpoint' => self::ISSUER . '/oauth/userinfo', 'jwks_uri' => self::ISSUER . '/oauth/jwks.json',
                    'revocation_endpoint' => self::ISSUER . '/oauth/revoke', 'end_session_endpoint' => self::ISSUER . '/oauth/logout',
                    'authorization_response_iss_parameter_supported' => true,
                    'backchannel_authentication_endpoint' => self::ISSUER . '/oauth/bc-authorize',
                ], $this->discoveryOverride));
            case '/oauth/jwks.json':
                return $json(200, ['keys' => array_map(fn ($k) => $this->keys[$k][1], $this->publishedKids)]);
            case '/oauth/token':
                parse_str((string) $body, $f);
                $auth = $headers['Authorization'] ?? '';
                $clientOk = $auth === 'Basic ' . base64_encode(self::CLIENT . ':' . self::SECRET)
                    || (($f['client_id'] ?? '') === self::CLIENT && ($f['client_secret'] ?? null) === self::SECRET)
                    || (($f['client_id'] ?? '') === self::CLIENT && !isset($f['client_secret']) && $auth === '');
                if (!$clientOk) { return $json(401, ['error' => 'invalid_client']); }
                if ($this->tokenError) { return $json(400, $this->tokenError); }
                $this->lastForm = $f;
                if (($f['grant_type'] ?? '') === 'urn:ietf:params:oauth:grant-type:token-exchange') {
                    if (($f['subject_token'] ?? '') !== $this->accessToken || ($f['subject_token_type'] ?? '') !== 'urn:ietf:params:oauth:token-type:access_token') {
                        return $json(400, ['error' => 'invalid_request', 'error_description' => 'bad subject_token']);
                    }
                    $r = ['access_token' => 'at_exchanged', 'issued_token_type' => 'urn:ietf:params:oauth:token-type:access_token', 'token_type' => 'Bearer',
                        'expires_in' => 300, 'scope' => $f['scope'] ?? 'openid'];
                    if (isset($f['authorization_details'])) { $r['authorization_details'] = json_decode($f['authorization_details'], true); }
                    return $json(200, $r);
                }
                if (($f['grant_type'] ?? '') === 'urn:openid:params:grant-type:ciba') {
                    $st = $this->ciba[$f['auth_req_id'] ?? ''] ?? null;
                    return match ($st) {
                        null => $json(400, ['error' => 'invalid_grant']),
                        'pending' => $json(400, ['error' => 'authorization_pending']),
                        'slow' => $json(400, ['error' => 'slow_down']),
                        'denied' => $json(400, ['error' => 'access_denied']),
                        'expired' => $json(400, ['error' => 'expired_token']),
                        default => $json(200, ['access_token' => $this->accessToken, 'token_type' => 'Bearer', 'expires_in' => 900, 'scope' => 'openid email',
                            'id_token' => $this->idTokenOverride ?? $this->idToken(), 'refresh_token' => 'rt_1']),
                    };
                }
                if (($f['grant_type'] ?? '') === 'authorization_code') {
                    $c = $this->codes[$f['code'] ?? ''] ?? null;
                    unset($this->codes[$f['code'] ?? '']);
                    $ok = $c && ($f['redirect_uri'] ?? '') === self::REDIRECT
                        && hash_equals($c['challenge'], rtrim(strtr(base64_encode(hash('sha256', (string) ($f['code_verifier'] ?? ''), true)), '+/', '-_'), '='));
                    if (!$ok) { return $json(400, ['error' => 'invalid_grant', 'error_description' => 'bad code or verifier']); }
                    return $json(200, ['access_token' => $this->accessToken, 'token_type' => 'Bearer', 'expires_in' => 900, 'scope' => 'openid email profile',
                        'id_token' => $this->idTokenOverride ?? $this->idToken(['nonce' => $c['nonce']]), 'refresh_token' => 'rt_1']);
                }
                if (($f['grant_type'] ?? '') === 'refresh_token') {
                    if (($f['refresh_token'] ?? '') !== 'rt_1') { return $json(400, ['error' => 'invalid_grant']); }
                    return $json(200, ['access_token' => $this->accessToken, 'token_type' => 'Bearer', 'expires_in' => 900, 'id_token' => $this->idToken(), 'refresh_token' => 'rt_2']);
                }
                return $json(400, ['error' => 'unsupported_grant_type']);
            case '/oauth/bc-authorize':
                parse_str((string) $body, $f);
                $this->lastForm = $f;
                if (($headers['Authorization'] ?? '') !== 'Basic ' . base64_encode(self::CLIENT . ':' . self::SECRET)) { return $json(401, ['error' => 'invalid_client']); }
                if (!str_contains(' ' . ($f['scope'] ?? '') . ' ', ' openid ')) { return $json(400, ['error' => 'invalid_scope']); }
                $id = 'req_' . bin2hex(random_bytes(8));
                $this->ciba[$id] = 'pending';
                return $json(200, ['auth_req_id' => $id, 'expires_in' => 120, 'interval' => 5]);
            case '/oauth/userinfo':
                if (($headers['Authorization'] ?? '') !== 'Bearer ' . $this->accessToken) { return $json(401, ['error' => 'invalid_token']); }
                return $json(200, $this->userinfo ?: ['sub' => 'pw_user_123', 'email' => 'ada@example.test']);
            case '/oauth/revoke':
                return new Response(200, '');
        }
        return new Response(404, 'not found');
    }

    public function count(string $pathPrefix): int
    {
        return count(array_filter($this->requests, fn ($r) => str_starts_with($r['url'], self::ISSUER . $pathPrefix)));
    }
}
