<?php
declare(strict_types=1);

namespace Identvia\Sdk\State;

/** Remembers pending sign-ins (state → nonce, PKCE verifier, return URL) between the redirect and the callback. */
interface StateStore
{
    /** @param array<string,mixed> $data */
    public function put(string $state, array $data): void;

    /** Returns and deletes the entry (single use), or null if unknown/expired. @return array<string,mixed>|null */
    public function pull(string $state): ?array;
}
