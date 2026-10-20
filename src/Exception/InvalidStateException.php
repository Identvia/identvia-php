<?php
declare(strict_types=1);

namespace Identvia\Sdk\Exception;

/**
 * The callback did not match a sign-in this browser started (missing, unknown, expired or reused state),
 * or the response came from the wrong issuer. Treat as a possible CSRF/mix-up attack: start over.
 */
final class InvalidStateException extends IdentviaException
{
}
