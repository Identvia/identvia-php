<?php
declare(strict_types=1);

namespace Identvia\Sdk;

/** A completed, validated sign-in. Use sub() as the user's stable ID in your database (it is unique to your app). */
final class SignIn
{
    /** @param array<string,mixed> $claims validated ID token claims */
    public function __construct(public readonly array $claims, public readonly TokenSet $tokens, public readonly ?string $returnTo = null)
    {
    }

    public function sub(): string { return (string) $this->claims['sub']; }

    public function email(): ?string { return isset($this->claims['email']) ? (string) $this->claims['email'] : null; }

    public function emailVerified(): bool { return ($this->claims['email_verified'] ?? false) === true; }

    public function name(): ?string { return isset($this->claims['name']) ? (string) $this->claims['name'] : null; }

    public function picture(): ?string { return isset($this->claims['picture']) ? (string) $this->claims['picture'] : null; }

    public function authTime(): ?int { return isset($this->claims['auth_time']) ? (int) $this->claims['auth_time'] : null; }

    /** @return list<string> Authentication methods, e.g. ["hwk","user"] for a passkey. */
    public function amr(): array { return array_values(array_map('strval', (array) ($this->claims['amr'] ?? []))); }
}
