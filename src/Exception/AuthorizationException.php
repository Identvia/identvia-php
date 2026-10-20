<?php
declare(strict_types=1);

namespace Identvia\Sdk\Exception;

/** Identvia returned an OAuth error, e.g. the user pressed Cancel (access_denied) or prompt=none failed (login_required). */
final class AuthorizationException extends IdentviaException
{
    public function __construct(public readonly string $error, public readonly ?string $description = null, public readonly ?string $returnTo = null)
    {
        parent::__construct($description ? "$error: $description" : $error);
    }

    public function userCancelled(): bool
    {
        return $this->error === 'access_denied';
    }
}
