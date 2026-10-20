<?php
declare(strict_types=1);

namespace Identvia\Sdk\Exception;

/** Network or protocol failure talking to Identvia (timeout, TLS error, unexpected response). */
final class HttpException extends IdentviaException
{
}
