<?php
declare(strict_types=1);

namespace Identvia\Sdk;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Identvia\Sdk\Exception\ValidationException;

/**
 * Validates Identvia ID tokens (OpenID Connect Core §3.1.3.7) using firebase/php-jwt for the
 * signature and time checks. Only asymmetric algorithms are accepted, so a token signed with the
 * client secret or "none" can never pass.
 */
final class IdTokenValidator
{
    public const ALGORITHMS = ['RS256', 'ES256'];

    /** @param \Closure(bool $force): array $jwks returns the JWKS document; $force=true asks for a fresh copy */
    public function __construct(
        private readonly string $issuer,
        private readonly string $clientId,
        private readonly \Closure $jwks,
        private readonly int $leeway = 60,
        private readonly ?\Closure $clock = null,
    ) {
    }

    private function now(): int
    {
        return $this->clock ? (int) ($this->clock)() : time();
    }

    /** @return array{alg:string,kid:?string,typ:?string} */
    public static function header(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) { throw new ValidationException('ID token is not a signed JWT.'); }
        $h = json_decode(JWT::urlsafeB64Decode($parts[0]), true);
        if (!is_array($h) || !is_string($h['alg'] ?? null)) { throw new ValidationException('ID token header is invalid.'); }
        return ['alg' => $h['alg'], 'kid' => isset($h['kid']) ? (string) $h['kid'] : null, 'typ' => isset($h['typ']) ? (string) $h['typ'] : null];
    }

    /** @return array<string, Key> keyed by kid */
    private function keys(bool $force): array
    {
        $doc = ($this->jwks)($force);
        $out = [];
        foreach ((array) ($doc['keys'] ?? []) as $jwk) {
            if (!is_array($jwk) || !isset($jwk['kid'], $jwk['kty'])) { continue; }
            if (isset($jwk['use']) && $jwk['use'] !== 'sig') { continue; }
            $alg = $jwk['alg'] ?? match ($jwk['kty']) { 'RSA' => 'RS256', 'EC' => ($jwk['crv'] ?? '') === 'P-256' ? 'ES256' : null, default => null };
            if (!in_array($alg, self::ALGORITHMS, true)) { continue; }
            try {
                $key = JWK::parseKey($jwk, $alg);
            } catch (\Throwable) {
                continue;
            }
            if ($key) { $out[(string) $jwk['kid']] = $key; }
        }
        return $out;
    }

    /**
     * @param array{nonce?:?string, max_age?:?int, access_token?:?string, require_nonce?:bool} $expect
     * @return array<string,mixed> the validated claims
     */
    public function validate(string $jwt, array $expect = []): array
    {
        $h = self::header($jwt);
        if (!in_array($h['alg'], self::ALGORITHMS, true)) { throw new ValidationException("ID token algorithm {$h['alg']} is not allowed."); }
        if ($h['kid'] === null) { throw new ValidationException('ID token has no key ID (kid).'); }
        $keys = $this->keys(false);
        if (!isset($keys[$h['kid']])) {
            $keys = $this->keys(true); // Identvia may have rotated keys: refetch once (rate-limited by the caller)
            if (!isset($keys[$h['kid']])) { throw new ValidationException('ID token was signed with an unknown key.'); }
        }
        $key = $keys[$h['kid']];
        if ($key->getAlgorithm() !== $h['alg']) { throw new ValidationException('ID token algorithm does not match its key.'); }

        [$oldLeeway, $oldTs] = [JWT::$leeway, JWT::$timestamp];
        JWT::$leeway = $this->leeway;
        JWT::$timestamp = $this->now();
        try {
            $claims = (array) JWT::decode($jwt, [$h['kid'] => $key]);
        } catch (\Throwable $e) {
            throw new ValidationException('ID token rejected: ' . $e->getMessage(), 0, $e);
        } finally {
            JWT::$leeway = $oldLeeway;
            JWT::$timestamp = $oldTs;
        }
        $claims = json_decode((string) json_encode($claims), true) ?: [];
        $now = $this->now();

        if (($claims['iss'] ?? null) !== $this->issuer) { throw new ValidationException('ID token issuer mismatch.'); }
        $aud = $claims['aud'] ?? null;
        $auds = is_array($aud) ? $aud : [$aud];
        if (!in_array($this->clientId, $auds, true)) { throw new ValidationException('ID token was not issued for this client.'); }
        if (count($auds) > 1 && ($claims['azp'] ?? null) !== $this->clientId) { throw new ValidationException('ID token azp mismatch.'); }
        if (isset($claims['azp']) && $claims['azp'] !== $this->clientId) { throw new ValidationException('ID token azp mismatch.'); }
        if (!is_string($claims['sub'] ?? null) || $claims['sub'] === '' || strlen($claims['sub']) > 255) { throw new ValidationException('ID token has no subject.'); }
        if (!isset($claims['exp'], $claims['iat']) || !is_int($claims['exp']) || !is_int($claims['iat'])) { throw new ValidationException('ID token is missing exp/iat.'); }
        if ($claims['iat'] > $now + $this->leeway) { throw new ValidationException('ID token was issued in the future.'); }

        $nonce = $expect['nonce'] ?? null;
        if ($nonce !== null || !empty($expect['require_nonce'])) {
            if (!is_string($claims['nonce'] ?? null) || $nonce === null || !hash_equals($nonce, $claims['nonce'])) { throw new ValidationException('ID token nonce mismatch (possible replay).'); }
        }
        if (isset($expect['max_age'])) {
            if (!is_int($claims['auth_time'] ?? null)) { throw new ValidationException('ID token has no auth_time but max_age was requested.'); }
            if ($claims['auth_time'] + (int) $expect['max_age'] + $this->leeway < $now) { throw new ValidationException('The user signed in too long ago for the requested max_age.'); }
        }
        if (isset($claims['at_hash']) && !empty($expect['access_token'])) {
            if (!hash_equals(self::atHash((string) $expect['access_token']), (string) $claims['at_hash'])) { throw new ValidationException('ID token at_hash does not match the access token.'); }
        }
        return $claims;
    }

    /** OIDC Core §3.1.3.6: left half of SHA-256 (RS256/ES256), base64url. */
    public static function atHash(string $accessToken): string
    {
        return rtrim(strtr(base64_encode(substr(hash('sha256', $accessToken, true), 0, 16)), '+/', '-_'), '=');
    }
}
