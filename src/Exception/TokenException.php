<?php
declare(strict_types=1);

namespace Identvia\Sdk\Exception;

/** The token endpoint rejected a request (invalid_grant, invalid_client, ...). */
final class TokenException extends IdentviaException
{
    public function __construct(public readonly string $error, public readonly ?string $description = null, public readonly int $status = 0)
    {
        parent::__construct(($description ? "$error: $description" : $error) . ($status ? " (HTTP $status)" : ''));
    }
}
