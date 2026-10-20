<?php
declare(strict_types=1);

namespace Identvia\Sdk;

use Identvia\Sdk\Cache\ApcuCache;
use Identvia\Sdk\Cache\Cache;
use Identvia\Sdk\Cache\FileCache;
use Identvia\Sdk\Exception\AuthorizationException;
use Identvia\Sdk\Exception\ConfigurationException;
use Identvia\Sdk\Exception\HttpException;
use Identvia\Sdk\Exception\InvalidStateException;
use Identvia\Sdk\Exception\TokenException;
use Identvia\Sdk\Exception\ValidationException;
use Identvia\Sdk\Http\CurlHttpClient;
use Identvia\Sdk\Http\HttpClient;
use Identvia\Sdk\Http\StreamHttpClient;
use Identvia\Sdk\State\SessionStateStore;
use Identvia\Sdk\State\StateStore;

/**
 * Sign in with Identvia: OpenID Connect authorization code flow with PKCE (S256), state and nonce,
 * ID token validation against Identvia's cached JWKS, and userinfo/refresh/revoke/logout helpers.
 *
 *   $identvia = new Identvia([
 *       'issuer'        => 'https://id.example.com',
 *       'client_id'     => 'oid_…',
 *       'client_secret' => 'ivs_…',            // omit for public (browser/mobile) apps
 *       'redirect_uri'  => 'https://app.example.com/callback.php',
 *   ]);
 *   header('Location: ' . $identvia->authorizationUrl()); // login.php
 *   $signIn = $identvia->handleCallback($_GET);            // callback.php
 */
final class Identvia
{
    public const VERSION = '1.0.0';
    public const DISCOVERY_TTL = 3600;
    public const JWKS_TTL = 3600;
    public const JWKS_REFETCH_INTERVAL = 60;

    private string $issuer;
    private string $clientId;
    private ?string $clientSecret;
    private string $redirectUri;
    /** @var list<string> */
    private array $scopes;
    private string $tokenAuth;
    private int $leeway;
    private HttpClient $http;
    private Cache $cache;
    private StateStore $state;
    private ?\Closure $clock;
    private ?array $discovery = null;

    /**
     * @param array{issuer:string, client_id:string, client_secret?:?string, redirect_uri:string, scopes?:list<string>,
     *   token_auth?:'client_secret_basic'|'client_secret_post', leeway?:int, timeout?:int, ca_bundle?:?string,
     *   cache_dir?:?string, cache?:Cache, http?:HttpClient, state_store?:StateStore, clock?:\Closure} $config
     */
    public function __construct(array $config)
    {
        foreach (['issuer', 'client_id', 'redirect_uri'] as $k) {
            if (!is_string($config[$k] ?? null) || trim($config[$k]) === '') { throw new ConfigurationException("Missing required option '$k'."); }
        }
        $this->issuer = rtrim($config['issuer'], '/');
        self::assertSecureUrl($this->issuer, 'issuer');
        $this->clientId = $config['client_id'];
        $this->clientSecret = isset($config['client_secret']) && $config['client_secret'] !== '' ? (string) $config['client_secret'] : null;
        $this->redirectUri = $config['redirect_uri'];
        self::assertSecureUrl($this->redirectUri, 'redirect_uri');
        $this->scopes = array_values(array_unique(array_merge(['openid'], $config['scopes'] ?? ['email', 'profile'])));
        $this->tokenAuth = $config['token_auth'] ?? 'client_secret_basic';
        if (!in_array($this->tokenAuth, ['client_secret_basic', 'client_secret_post'], true)) { throw new ConfigurationException('token_auth must be client_secret_basic or client_secret_post.'); }
        $this->leeway = max(0, min(300, (int) ($config['leeway'] ?? 60)));
        $timeout = (int) ($config['timeout'] ?? 10);
        $ca = $config['ca_bundle'] ?? null;
        $this->http = $config['http'] ?? (function_exists('curl_init') ? new CurlHttpClient($timeout, $ca) : new StreamHttpClient($timeout, $ca));
        $this->cache = $config['cache'] ?? (ApcuCache::available() && !isset($config['cache_dir']) ? new ApcuCache() : new FileCache($config['cache_dir'] ?? null));
        $this->state = $config['state_store'] ?? new SessionStateStore();
        $this->clock = $config['clock'] ?? null;
    }

    /** https everywhere, except http://localhost / 127.0.0.1 for local development. */
    private static function assertSecureUrl(string $url, string $what): void
    {
        $u = parse_url($url);
        $host = strtolower((string) ($u['host'] ?? ''));
        $scheme = strtolower((string) ($u['scheme'] ?? ''));
        if ($host === '' || isset($u['user']) || isset($u['fragment'])) { throw new ConfigurationException("$what must be an absolute URL without credentials or #fragment."); }
        if ($scheme === 'https') { return; }
        if ($scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '[::1]'], true)) { return; }
        throw new ConfigurationException("$what must use https:// (http is only allowed for localhost).");
    }

    private function now(): int
    {
        return $this->clock ? (int) ($this->clock)() : time();
    }

    private static function b64url(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    // ------------------------------------------------------------------ metadata
    /** @return array<string,mixed> the issuer's OpenID configuration (cached for an hour) */
    public function discovery(): array
    {
        if ($this->discovery !== null) { return $this->discovery; }
        $key = 'discovery:' . $this->issuer;
        $raw = $this->cache->get($key);
        $doc = $raw !== null ? json_decode($raw, true) : null;
        if (!is_array($doc)) {
            $res = $this->http->request('GET', $this->issuer . '/.well-known/openid-configuration', ['Accept' => 'application/json']);
            if ($res->status !== 200) { throw new HttpException("Could not load Identvia's configuration (HTTP {$res->status})."); }
            $doc = $res->json();
            if (($doc['issuer'] ?? null) !== $this->issuer) { throw new ConfigurationException('The discovery document is for a different issuer (' . ($doc['issuer'] ?? 'none') . '). Check the issuer option.'); }
            foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $k) {
                if (!is_string($doc[$k] ?? null)) { throw new HttpException("Discovery document has no $k."); }
                self::assertSecureUrl($doc[$k], $k);
            }
            $this->cache->set($key, (string) json_encode($doc), self::DISCOVERY_TTL);
        }
        return $this->discovery = $doc;
    }

    private function endpoint(string $name): string
    {
        $u = $this->discovery()[$name] ?? null;
        if (!is_string($u)) { throw new HttpException("Identvia does not advertise $name."); }
        return $u;
    }

    /** @return array<string,mixed> JWKS; $force refetches at most once a minute (handles key rotation) */
    public function jwks(bool $force = false): array
    {
        $key = 'jwks:' . $this->issuer;
        if (!$force && ($raw = $this->cache->get($key)) !== null && is_array($doc = json_decode($raw, true))) { return $doc; }
        if ($force && $this->cache->get($key . ':refetched') !== null && ($raw = $this->cache->get($key)) !== null) {
            return json_decode($raw, true) ?: ['keys' => []]; // refetched recently: don't let bad tokens hammer Identvia
        }
        $res = $this->http->request('GET', $this->endpoint('jwks_uri'), ['Accept' => 'application/json']);
        if ($res->status !== 200) { throw new HttpException("Could not load Identvia's signing keys (HTTP {$res->status})."); }
        $doc = $res->json();
        if (!is_array($doc['keys'] ?? null)) { throw new HttpException('JWKS has no keys.'); }
        $this->cache->set($key, (string) json_encode($doc), self::JWKS_TTL);
        $this->cache->set($key . ':refetched', '1', self::JWKS_REFETCH_INTERVAL);
        return $doc;
    }

    public function validator(): IdTokenValidator
    {
        return new IdTokenValidator($this->issuer, $this->clientId, fn (bool $force) => $this->jwks($force), $this->leeway, $this->clock);
    }

    // ------------------------------------------------------------------ sign-in
    /**
     * Builds the URL to send the user to and remembers state, nonce and the PKCE verifier.
     *
     * @param array{scopes?:list<string>, prompt?:string, max_age?:int, login_hint?:string, return_to?:string} $options
     */
    public function authorizationUrl(array $options = []): string
    {
        $state = self::b64url(random_bytes(32));
        $nonce = self::b64url(random_bytes(32));
        $verifier = self::b64url(random_bytes(48)); // 64 chars, RFC 7636 §4.1
        $scopes = array_values(array_unique(array_merge(['openid'], $options['scopes'] ?? $this->scopes)));
        $returnTo = self::safeReturnTo($options['return_to'] ?? null);
        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::b64url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ];
        if (isset($options['prompt'])) {
            if (!in_array($options['prompt'], ['none', 'login', 'consent'], true)) { throw new ConfigurationException('prompt must be none, login or consent.'); }
            $params['prompt'] = $options['prompt'];
        }
        $maxAge = isset($options['max_age']) ? max(0, (int) $options['max_age']) : null;
        if ($maxAge !== null) { $params['max_age'] = (string) $maxAge; }
        if (isset($options['login_hint'])) { $params['login_hint'] = substr((string) $options['login_hint'], 0, 254); }
        $this->state->put($state, ['nonce' => $nonce, 'verifier' => $verifier, 'return_to' => $returnTo, 'max_age' => $maxAge, 'created' => $this->now()]);
        $ep = $this->endpoint('authorization_endpoint');
        return $ep . (str_contains($ep, '?') ? '&' : '?') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /** Sends the redirect and stops the script. */
    public function redirectToSignIn(array $options = []): never
    {
        header('Cache-Control: no-store');
        header('Location: ' . $this->authorizationUrl($options), true, 302);
        exit;
    }

    /** Only same-site relative paths, so return_to can't be turned into an open redirect. */
    public static function safeReturnTo(?string $to): ?string
    {
        if ($to === null || $to === '') { return null; }
        if (!preg_match('#^/(?![/\\\\])#', $to) || preg_match('/[\x00-\x1f\x7f\\\\]/', $to) || strlen($to) > 2000) { return null; }
        return $to;
    }

    /**
     * Completes sign-in on your redirect URI. Pass $_GET.
     *
     * @param array<string,mixed> $query
     * @throws InvalidStateException  unknown/expired/reused state, or wrong issuer: start sign-in again
     * @throws AuthorizationException the user cancelled, or Identvia returned an error
     * @throws TokenException|ValidationException|HttpException
     */
    public function handleCallback(array $query): SignIn
    {
        $state = $query['state'] ?? null;
        if (!is_string($state) || $state === '' || strlen($state) > 512) { throw new InvalidStateException('The sign-in response has no state. Start again.'); }
        $pending = $this->state->pull($state);
        if ($pending === null) { throw new InvalidStateException('This sign-in link expired or was already used. Start again.'); }

        // RFC 9207: the response must say which issuer sent it (defends against IdP mix-up).
        $iss = $query['iss'] ?? null;
        if ($iss !== null) {
            if ($iss !== $this->issuer) { throw new InvalidStateException('The sign-in response came from a different issuer.'); }
        } elseif (!empty($this->discovery()['authorization_response_iss_parameter_supported'])) {
            throw new InvalidStateException('The sign-in response is missing the iss parameter.');
        }

        if (isset($query['error'])) {
            throw new AuthorizationException(substr((string) $query['error'], 0, 100), isset($query['error_description']) ? substr((string) $query['error_description'], 0, 500) : null, $pending['return_to'] ?? null);
        }
        $code = $query['code'] ?? null;
        if (!is_string($code) || $code === '' || strlen($code) > 2048) { throw new InvalidStateException('The sign-in response has no authorization code.'); }

        $tokens = $this->tokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => (string) $pending['verifier'],
        ]);
        if ($tokens->idToken === null) { throw new ValidationException('Identvia did not return an ID token (is the openid scope enabled?).'); }
        $claims = $this->validator()->validate($tokens->idToken, [
            'nonce' => (string) $pending['nonce'], 'require_nonce' => true, 'max_age' => $pending['max_age'] ?? null, 'access_token' => $tokens->accessToken,
        ]);
        return new SignIn($claims, $tokens, $pending['return_to'] ?? null);
    }

    // ------------------------------------------------------------------ tokens
    /** @param array<string,string> $form */
    private function tokenRequest(array $form): TokenSet
    {
        $data = $this->post($this->endpoint('token_endpoint'), $form);
        if (!is_string($data['access_token'] ?? null) || strcasecmp((string) ($data['token_type'] ?? ''), 'Bearer') !== 0) {
            throw new TokenException('invalid_response', 'Token response has no Bearer access token.');
        }
        return TokenSet::fromResponse($data, $this->now());
    }

    /** POST with client authentication. @param array<string,string> $form @return array<string,mixed> */
    private function post(string $url, array $form, bool $expectJson = true): array
    {
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json'];
        if ($this->clientSecret !== null && $this->tokenAuth === 'client_secret_basic') {
            // RFC 6749 §2.3.1: each part is form-urlencoded before base64
            $headers['Authorization'] = 'Basic ' . base64_encode(rawurlencode($this->clientId) . ':' . rawurlencode($this->clientSecret));
        } else {
            $form['client_id'] = $this->clientId;
            if ($this->clientSecret !== null) { $form['client_secret'] = $this->clientSecret; }
        }
        $res = $this->http->request('POST', $url, $headers, http_build_query($form, '', '&', PHP_QUERY_RFC1738));
        if ($res->status >= 200 && $res->status < 300) { return $expectJson ? $res->json() : []; }
        $err = json_decode($res->body, true);
        throw new TokenException(is_array($err) && is_string($err['error'] ?? null) ? $err['error'] : 'http_error',
            is_array($err) && is_string($err['error_description'] ?? null) ? $err['error_description'] : null, $res->status);
    }

    /**
     * Gets fresh tokens with a refresh token (needs the offline_access scope). Identvia rotates refresh
     * tokens: store the new one and discard the old; reusing an old one revokes the whole chain.
     */
    public function refresh(string $refreshToken, ?string $expectedSub = null): TokenSet
    {
        $t = $this->tokenRequest(['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken]);
        if ($t->idToken !== null) {
            $claims = $this->validator()->validate($t->idToken, ['access_token' => $t->accessToken]);
            if ($expectedSub !== null && $claims['sub'] !== $expectedSub) { throw new ValidationException('Refreshed ID token is for a different user.'); }
        }
        return $t;
    }

    /** @return array<string,mixed> the user's claims from the userinfo endpoint */
    public function userinfo(string $accessToken, ?string $expectedSub = null): array
    {
        $res = $this->http->request('GET', $this->endpoint('userinfo_endpoint'), ['Authorization' => 'Bearer ' . $accessToken, 'Accept' => 'application/json']);
        if ($res->status === 401) { throw new TokenException('invalid_token', 'The access token is invalid or expired.', 401); }
        if ($res->status !== 200) { throw new HttpException("Userinfo request failed (HTTP {$res->status})."); }
        $data = $res->json();
        if (!is_string($data['sub'] ?? null)) { throw new ValidationException('Userinfo response has no sub.'); }
        if ($expectedSub !== null && !hash_equals($expectedSub, $data['sub'])) { throw new ValidationException('Userinfo is for a different user than the ID token.'); }
        return $data;
    }

    /** Revokes a refresh or access token (RFC 7009). Call it when the user signs out. */
    public function revoke(string $token, string $hint = 'refresh_token'): void
    {
        $this->post($this->endpoint('revocation_endpoint'), ['token' => $token, 'token_type_hint' => $hint], false);
    }

    /** URL that signs the user out of Identvia too (RP-initiated logout). Optional: most apps only end their own session. */
    public function logoutUrl(?string $idTokenHint = null, ?string $postLogoutRedirectUri = null, ?string $state = null): string
    {
        $p = ['client_id' => $this->clientId];
        if ($idTokenHint !== null) { $p['id_token_hint'] = $idTokenHint; }
        if ($postLogoutRedirectUri !== null) { self::assertSecureUrl($postLogoutRedirectUri, 'post_logout_redirect_uri'); $p['post_logout_redirect_uri'] = $postLogoutRedirectUri; }
        if ($state !== null) { $p['state'] = $state; }
        $ep = $this->endpoint('end_session_endpoint');
        return $ep . (str_contains($ep, '?') ? '&' : '?') . http_build_query($p, '', '&', PHP_QUERY_RFC3986);
    }

    public function issuer(): string { return $this->issuer; }

    public function clientId(): string { return $this->clientId; }
}
