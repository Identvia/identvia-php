<?php
declare(strict_types=1);

namespace Identvia\Sdk\State;

use Identvia\Sdk\Exception\ConfigurationException;

/**
 * Stores pending sign-ins in the PHP session. Several tabs can sign in at once (one entry per state);
 * entries expire after 10 minutes and at most 10 are kept.
 *
 * The session cookie must be sent on the top-level redirect back from Identvia, so it needs
 * SameSite=Lax (PHP's default is no SameSite attribute, which browsers treat as Lax). Not "Strict".
 */
final class SessionStateStore implements StateStore
{
    public const KEY = '_identvia_pending';
    public const TTL = 600;
    public const MAX = 10;

    public function __construct(private readonly bool $autoStart = true)
    {
    }

    private function ensure(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) { return; }
        if (!$this->autoStart) { throw new ConfigurationException('Start the PHP session (session_start()) before using the Identvia SDK.'); }
        if (headers_sent($file, $line)) { throw new ConfigurationException("Cannot start the session: output already started at $file:$line."); }
        $https = (($_SERVER['HTTPS'] ?? '') !== '' && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['SERVER_PORT'] ?? '') === '443';
        session_start(['cookie_httponly' => true, 'cookie_secure' => $https, 'cookie_samesite' => 'Lax', 'use_strict_mode' => true]);
    }

    public function put(string $state, array $data): void
    {
        $this->ensure();
        $all = $this->fresh($_SESSION[self::KEY] ?? []);
        $all[hash('sha256', $state)] = ['t' => time(), 'd' => $data];
        if (count($all) > self::MAX) { $all = array_slice($all, -self::MAX, null, true); }
        $_SESSION[self::KEY] = $all;
    }

    public function pull(string $state): ?array
    {
        $this->ensure();
        $all = $this->fresh($_SESSION[self::KEY] ?? []);
        $k = hash('sha256', $state);
        $hit = $all[$k] ?? null;
        unset($all[$k]);
        $_SESSION[self::KEY] = $all;
        return $hit ? $hit['d'] : null;
    }

    /** @param mixed $all */
    private function fresh($all): array
    {
        if (!is_array($all)) { return []; }
        return array_filter($all, fn ($e) => is_array($e) && isset($e['t'], $e['d']) && $e['t'] + self::TTL >= time());
    }
}
