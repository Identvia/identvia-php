<?php
declare(strict_types=1);

namespace Identvia\Sdk\Http;

use Identvia\Sdk\Exception\HttpException;

final class CurlHttpClient implements HttpClient
{
    public const MAX_BYTES = 1048576;

    public function __construct(private readonly int $timeout = 10, private readonly ?string $caBundle = null)
    {
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null): Response
    {
        $ch = curl_init($url);
        if ($ch === false) { throw new HttpException('Could not initialise cURL.'); }
        $respHeaders = [];
        $buf = '';
        $h = [];
        foreach ($headers as $k => $v) { $h[] = "$k: $v"; }
        $opts = [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $h,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => min(5, $this->timeout),
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_USERAGENT => 'identvia-php/' . \Identvia\Sdk\Identvia::VERSION,
            CURLOPT_HEADERFUNCTION => function ($ch, string $line) use (&$respHeaders): int {
                $p = strpos($line, ':');
                if ($p !== false) { $respHeaders[strtolower(trim(substr($line, 0, $p)))] = trim(substr($line, $p + 1)); }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($ch, string $chunk) use (&$buf): int {
                if (strlen($buf) + strlen($chunk) > self::MAX_BYTES) { return 0; } // abort oversized responses
                $buf .= $chunk;
                return strlen($chunk);
            },
        ];
        if ($body !== null) { $opts[CURLOPT_POSTFIELDS] = $body; }
        if ($this->caBundle) { $opts[CURLOPT_CAINFO] = $this->caBundle; }
        curl_setopt_array($ch, $opts);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($ok === false) { throw new HttpException('Request to Identvia failed: ' . ($err ?: 'unknown error')); }
        return new Response($status, $buf, $respHeaders);
    }
}
