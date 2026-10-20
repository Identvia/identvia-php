<?php
declare(strict_types=1);

namespace Identvia\Sdk\Http;

use Identvia\Sdk\Exception\HttpException;

final class Response
{
    /** @param array<string,string> $headers lower-cased names */
    public function __construct(public readonly int $status, public readonly string $body, public readonly array $headers = [])
    {
    }

    /** @return array<string,mixed> */
    public function json(): array
    {
        try {
            $data = json_decode($this->body, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new HttpException("Identvia returned a non-JSON response (HTTP {$this->status}).");
        }
        if (!is_array($data)) { throw new HttpException('Identvia returned an unexpected JSON value.'); }
        return $data;
    }
}
