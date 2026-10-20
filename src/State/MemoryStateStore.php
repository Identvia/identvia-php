<?php
declare(strict_types=1);

namespace Identvia\Sdk\State;

/** In-memory store for tests and CLI tools. */
final class MemoryStateStore implements StateStore
{
    /** @var array<string, array<string,mixed>> */
    public array $items = [];

    public function put(string $state, array $data): void { $this->items[$state] = $data; }

    public function pull(string $state): ?array
    {
        $d = $this->items[$state] ?? null;
        unset($this->items[$state]);
        return $d;
    }
}
