<?php
declare(strict_types=1);

namespace Identvia\Sdk\Exception;

/** An ID token (or userinfo response) failed validation. Never sign the user in when this is thrown. */
final class ValidationException extends IdentviaException
{
}
