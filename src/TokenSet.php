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
    ) {
    }

    /** @param array<string,mixed> $r */
    public static function fromResponse(array $r, ?int $now = null): self
    {
        $now ??= time();
        return new self((string) $r['access_token'], isset($r['id_token']) ? (string) $r['id_token'] : null,
            isset($r['refresh_token']) ? (string) $r['refresh_token'] : null, $now + max(0, (int) ($r['expires_in'] ?? 0)),
            (string) ($r['scope'] ?? ''), (string) ($r['token_type'] ?? 'Bearer'));
    }

    public function expired(int $skew = 30): bool
    {
        return time() + $skew >= $this->expiresAt;
    }

    /** @return array<string,mixed> for storing in a session */
    public function toArray(): array
    {
        return ['access_token' => $this->accessToken, 'id_token' => $this->idToken, 'refresh_token' => $this->refreshToken,
            'expires_at' => $this->expiresAt, 'scope' => $this->scope, 'token_type' => $this->tokenType];
    }

    /** @param array<string,mixed> $a */
    public static function fromArray(array $a): self
    {
        return new self((string) $a['access_token'], $a['id_token'] ?? null, $a['refresh_token'] ?? null, (int) $a['expires_at'], (string) ($a['scope'] ?? ''), (string) ($a['token_type'] ?? 'Bearer'));
    }
}
