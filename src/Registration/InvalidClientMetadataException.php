<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Registration;

/**
 * A registration request the server refuses, with the error code of RFC 7591 section 3.2.2.
 *
 * @internal
 */
final class InvalidClientMetadataException extends \InvalidArgumentException
{
    public const INVALID_CLIENT_METADATA = 'invalid_client_metadata';
    public const INVALID_REDIRECT_URI = 'invalid_redirect_uri';

    public function __construct(
        private readonly string $error,
        string $description,
    ) {
        parent::__construct($description);
    }

    public function getError(): string
    {
        return $this->error;
    }
}
