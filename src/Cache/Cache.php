<?php
declare(strict_types=1);

namespace Identvia\Sdk\Cache;

/** Tiny key/value cache for discovery and JWKS documents (public data only; never tokens). */
interface Cache
{
    public function get(string $key): ?string;

    public function set(string $key, string $value, int $ttl): void;

    public function delete(string $key): void;
}
