<?php
declare(strict_types=1);

namespace Identvia\Sdk;

/** Tokens from the token endpoint. Keep refresh tokens server-side; never send them to the browser. */
final class TokenSet
{
    public function __construct(
        public readonly string $accessToken,
        public readonly ?string $idToken,
        public readonly ?string $refreshToken,
        public readonly int $expiresAt,
        public readonly string $scope,
        public readonly string $tokenType = 'Bearer',
        /** RFC 9396 authorization_details granted with this token, if any. @var list<array<string,mixed>>|null */
        public readonly ?array $authorizationDetails = null,
        /** RFC 8693 issued_token_type (token exchange only). */
        public readonly ?string $issuedTokenType = null,
    ) {
    }

    /** @param array<string,mixed> $r */
    public static function fromResponse(array $r, ?int $now = null): self
    {
        $now ??= time();
        return new self((string) $r['access_token'], isset($r['id_token']) ? (string) $r['id_token'] : null,
            isset($r['refresh_token']) ? (string) $r['refresh_token'] : null, $now + max(0, (int) ($r['expires_in'] ?? 0)),
            (string) ($r['scope'] ?? ''), (string) ($r['token_type'] ?? 'Bearer'),
            isset($r['authorization_details']) && is_array($r['authorization_details']) ? array_values($r['authorization_details']) : null,
            isset($r['issued_token_type']) ? (string) $r['issued_token_type'] : null);
    }

    public function expired(int $skew = 30): bool
    {
        return time() + $skew >= $this->expiresAt;
    }

    /** @return array<string,mixed> for storing in a session */
    public function toArray(): array
    {
        return ['access_token' => $this->accessToken, 'id_token' => $this->idToken, 'refresh_token' => $this->refreshToken,
            'expires_at' => $this->expiresAt, 'scope' => $this->scope, 'token_type' => $this->tokenType,
            'authorization_details' => $this->authorizationDetails, 'issued_token_type' => $this->issuedTokenType];
    }

    /** @param array<string,mixed> $a */
    public static function fromArray(array $a): self
    {
        return new self((string) $a['access_token'], $a['id_token'] ?? null, $a['refresh_token'] ?? null, (int) $a['expires_at'], (string) ($a['scope'] ?? ''), (string) ($a['token_type'] ?? 'Bearer'),
            isset($a['authorization_details']) && is_array($a['authorization_details']) ? $a['authorization_details'] : null, $a['issued_token_type'] ?? null);
    }
}
