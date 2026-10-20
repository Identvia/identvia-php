<?php
declare(strict_types=1);

namespace Identvia\Sdk\Http;

/** Minimal HTTP transport. Implementations must verify TLS certificates and must not follow redirects. */
interface HttpClient
{
    /** @param array<string,string> $headers */
    public function request(string $method, string $url, array $headers = [], ?string $body = null): Response;
}
