<?php
declare(strict_types=1);

namespace Identvia\Sdk\Cache;

final class ApcuCache implements Cache
{
    public static function available(): bool
    {
        return function_exists('apcu_fetch') && filter_var(ini_get(PHP_SAPI === 'cli' ? 'apc.enable_cli' : 'apc.enabled'), FILTER_VALIDATE_BOOLEAN);
    }

    public function get(string $key): ?string
    {
        $v = apcu_fetch('identvia:' . $key, $ok);
        return $ok && is_string($v) ? $v : null;
    }

    public function set(string $key, string $value, int $ttl): void
    {
        apcu_store('identvia:' . $key, $value, $ttl);
    }

    public function delete(string $key): void
    {
        apcu_delete('identvia:' . $key);
    }
}
