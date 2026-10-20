<?php
declare(strict_types=1);

namespace Identvia\Sdk\Exception;

/** Base class for every error the SDK throws. Messages are safe to log but are not meant for end users. */
class IdentviaException extends \RuntimeException
{
}
