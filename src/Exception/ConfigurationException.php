<?php
declare(strict_types=1);

namespace Identvia\Sdk\Exception;

/** The SDK was configured incorrectly (missing client ID, non-https issuer, ...). */
final class ConfigurationException extends IdentviaException
{
}
