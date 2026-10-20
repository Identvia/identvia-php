<?php
declare(strict_types=1);

namespace Identvia\Sdk\Cache;

use Identvia\Sdk\Exception\ConfigurationException;

/** File cache that works on any shared host. Stores only public metadata (discovery document, signing keys). */
final class FileCache implements Cache
{
    private string $dir;

    public function __construct(?string $dir = null)
    {
        $dir ??= rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'identvia-php-' . substr(hash('sha256', __DIR__), 0, 12);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new ConfigurationException("Cache directory $dir does not exist and could not be created.");
        }
        $this->dir = rtrim($dir, '/\\');
    }

    private function path(string $key): string
    {
        return $this->dir . DIRECTORY_SEPARATOR . hash('sha256', $key) . '.cache';
    }

    public function get(string $key): ?string
    {
        $raw = @file_get_contents($this->path($key));
        if ($raw === false || strlen($raw) < 11) { return null; }
        $exp = (int) substr($raw, 0, 10);
        if ($exp < time()) { return null; }
        return substr($raw, 11);
    }

    public function set(string $key, string $value, int $ttl): void
    {
        $tmp = $this->path($key) . '.' . bin2hex(random_bytes(4));
        if (@file_put_contents($tmp, sprintf('%010d', time() + $ttl) . "\n" . $value, LOCK_EX) !== false) {
            @chmod($tmp, 0600);
            @rename($tmp, $this->path($key)); // atomic replace
        }
    }

    public function delete(string $key): void
    {
        @unlink($this->path($key));
    }
}
