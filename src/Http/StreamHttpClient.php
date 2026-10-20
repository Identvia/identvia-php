<?php
declare(strict_types=1);

namespace Identvia\Sdk\Http;

use Identvia\Sdk\Exception\HttpException;

/** Fallback transport for hosts without ext-curl (uses PHP's https:// stream wrapper with peer verification). */
final class StreamHttpClient implements HttpClient
{
    public function __construct(private readonly int $timeout = 10, private readonly ?string $caBundle = null)
    {
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null): Response
    {
        $h = ['User-Agent: identvia-php/' . \Identvia\Sdk\Identvia::VERSION, 'Connection: close'];
        foreach ($headers as $k => $v) { $h[] = "$k: $v"; }
        $ssl = ['verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false];
        if ($this->caBundle) { $ssl['cafile'] = $this->caBundle; }
        $ctx = stream_context_create([
            'http' => ['method' => $method, 'header' => implode("\r\n", $h), 'content' => $body ?? '', 'timeout' => $this->timeout,
                'ignore_errors' => true, 'follow_location' => 0, 'max_redirects' => 0, 'protocol_version' => 1.1],
            'ssl' => $ssl,
        ]);
        $fh = @fopen($url, 'rb', false, $ctx);
        if ($fh === false) { throw new HttpException('Request to Identvia failed: ' . (error_get_last()['message'] ?? 'unknown error')); }
        $buf = (string) stream_get_contents($fh, CurlHttpClient::MAX_BYTES + 1);
        $meta = stream_get_meta_data($fh);
        fclose($fh);
        if (strlen($buf) > CurlHttpClient::MAX_BYTES) { throw new HttpException('Response from Identvia was too large.'); }
        $status = 0; $respHeaders = [];
        foreach ((array) ($meta['wrapper_data'] ?? []) as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', (string) $line, $m)) { $status = (int) $m[1]; $respHeaders = []; continue; }
            $p = strpos((string) $line, ':');
            if ($p !== false) { $respHeaders[strtolower(trim(substr($line, 0, $p)))] = trim(substr($line, $p + 1)); }
        }
        return new Response($status, $buf, $respHeaders);
    }
}
