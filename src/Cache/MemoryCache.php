<?php
declare(strict_types=1);

namespace Identvia\Sdk\Cache;

/** Per-request cache, mostly for tests. */
final class MemoryCache implements Cache
{
    /** @var array<string, array{0:int,1:string}> */
    private array $items = [];

    public function get(string $key): ?string
    {
        $i = $this->items[$key] ?? null;
        return $i && $i[0] >= time() ? $i[1] : null;
    }

    public function set(string $key, string $value, int $ttl): void
    {
        $this->items[$key] = [time() + $ttl, $value];
    }

    public function delete(string $key): void
    {
        unset($this->items[$key]);
    }
}
