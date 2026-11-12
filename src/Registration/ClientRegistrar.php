<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Registration;

use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\AbstractClient;
use League\Bundle\OAuth2ServerBundle\ValueObject\Grant;
use League\Bundle\OAuth2ServerBundle\ValueObject\RedirectUri;
use League\Bundle\OAuth2ServerBundle\ValueObject\Scope;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;

/**
 * Validates the metadata of an RFC 7591 registration request and stores the client it describes.
 *
 * @internal
 */
final readonly class ClientRegistrar
{
    public const MAX_REDIRECT_URI_LENGTH = 2000;

    /** the length of the column that stores the name */
    public const MAX_NAME_LENGTH = 128;

    private const AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'none'];

    /**
     * @param class-string<AbstractClient> $clientClass
     * @param list<non-empty-string> $allowedGrants grants a client may ask for
     * @param list<non-empty-string> $allowedScopes scopes a client may ask for
     * @param list<non-empty-string> $defaultScopes scopes of a client that asks for none
     */
    public function __construct(
        private ClientManagerInterface $clientManager,
        private PasswordHasherInterface $passwordHasher,
        private RedirectUriPolicy $redirectUriPolicy,
        private string $clientClass,
        private array $allowedGrants,
        private array $allowedScopes,
        private array $defaultScopes,
        private int $maxRedirectUris,
    ) {
    }

    /**
     * @param array<mixed> $metadata
     *
     * @return array<string, mixed> the registered metadata of RFC 7591 section 3.2.1
     *
     * @throws InvalidClientMetadataException
     */
    public function register(array $metadata): array
    {
        $grants = $this->grantTypes($metadata);
        $this->assertResponseTypes($metadata, $grants);

        $redirectUris = $this->redirectUris($metadata, \in_array('authorization_code', $grants, true));
        $name = $this->clientName($metadata);
        $authMethod = $this->authMethod($metadata);
        $this->assertCompatible($grants, $authMethod);
        $scopes = $this->scopes($metadata);

        $identifier = bin2hex(random_bytes(16));
        $secret = 'none' === $authMethod ? null : bin2hex(random_bytes(32));

        $client = new $this->clientClass($name, $identifier, null === $secret ? null : $this->passwordHasher->hash($secret));
        $client
            ->setRedirectUris(...array_map(static fn (string $uri): RedirectUri => new RedirectUri($uri), $redirectUris))
            ->setGrants(...array_map(static fn (string $grant): Grant => new Grant($grant), $grants))
            ->setScopes(...array_map(static fn (string $scope): Scope => new Scope($scope), $scopes))
            ->setActive(true)
        ;
        $client->setAllowPlainTextPkce(false);

        $this->clientManager->save($client);

        $registered = [
            'client_id' => $identifier,
            'client_id_issued_at' => time(),
            'client_name' => $name,
            'redirect_uris' => $redirectUris,
            'grant_types' => $grants,
            'response_types' => \in_array('authorization_code', $grants, true) ? ['code'] : [],
            'token_endpoint_auth_method' => $authMethod,
            'scope' => implode(' ', $scopes),
        ];

        if (null !== $secret) {
            $registered['client_secret'] = $secret;
            // The secret does not expire
            $registered['client_secret_expires_at'] = 0;
        }

        return $registered;
    }

    /**
     * @param array<mixed> $metadata
     *
     * @return list<non-empty-string>
     */
    private function grantTypes(array $metadata): array
    {
        $grants = $this->listOfStrings($metadata, 'grant_types') ?? ['authorization_code'];

        if ([] === $grants) {
            throw $this->invalid('grant_types must not be empty.');
        }

        foreach ($grants as $grant) {
            if (!\in_array($grant, $this->allowedGrants, true)) {
                throw $this->invalid(\sprintf('Unsupported grant type "%s".', $this->shorten($grant)));
            }
        }

        return array_values(array_unique($grants));
    }

    /**
     * @param list<non-empty-string> $grants
     */
    private function assertCompatible(array $grants, string $authMethod): void
    {
        // The client credentials grant refuses a client without a secret
        if ('none' === $authMethod && \in_array('client_credentials', $grants, true)) {
            throw $this->invalid('The client_credentials grant requires a client secret, token_endpoint_auth_method must not be "none".');
        }

        // A refresh token only comes with a grant that issues one
        if (\in_array('refresh_token', $grants, true) && [] === array_intersect($grants, ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'])) {
            throw $this->invalid('The refresh_token grant requires the authorization_code or the device code grant.');
        }
    }

    /**
     * @param array<mixed> $metadata
     * @param list<non-empty-string> $grants
     */
    private function assertResponseTypes(array $metadata, array $grants): void
    {
        $responseTypes = $this->listOfStrings($metadata, 'response_types');
        if (null === $responseTypes) {
            return;
        }

        $usesCode = \in_array('authorization_code', $grants, true);

        if (array_values(array_unique($responseTypes)) !== ($usesCode ? ['code'] : [])) {
            throw $this->invalid('response_types must be ["code"] for the authorization_code grant and empty without it.');
        }
    }

    /**
     * @param array<mixed> $metadata
     *
     * @return list<non-empty-string>
     */
    private function redirectUris(array $metadata, bool $required): array
    {
        $redirectUris = $this->listOfStrings($metadata, 'redirect_uris') ?? [];

        if ($required && [] === $redirectUris) {
            throw new InvalidClientMetadataException(InvalidClientMetadataException::INVALID_REDIRECT_URI, 'redirect_uris is required.');
        }

        if (\count($redirectUris) > $this->maxRedirectUris) {
            throw new InvalidClientMetadataException(InvalidClientMetadataException::INVALID_REDIRECT_URI, \sprintf('redirect_uris may contain at most %d entries.', $this->maxRedirectUris));
        }

        foreach ($redirectUris as $redirectUri) {
            if (\strlen($redirectUri) > self::MAX_REDIRECT_URI_LENGTH) {
                throw new InvalidClientMetadataException(InvalidClientMetadataException::INVALID_REDIRECT_URI, \sprintf('A redirect URI may be at most %d characters long.', self::MAX_REDIRECT_URI_LENGTH));
            }

            if (!$this->redirectUriPolicy->isAllowed($redirectUri)) {
                throw new InvalidClientMetadataException(InvalidClientMetadataException::INVALID_REDIRECT_URI, \sprintf('Invalid redirect URI "%s". Use HTTPS, an HTTP loopback URI or a private-use scheme with a path, without fragments.', $this->shorten($redirectUri)));
            }
        }

        return array_values(array_unique($redirectUris));
    }

    /**
     * @param array<mixed> $metadata
     */
    private function clientName(array $metadata): string
    {
        $name = $metadata['client_name'] ?? 'Dynamically registered client';

        if (!\is_string($name) || '' === $name) {
            throw $this->invalid('client_name must be a non-empty string.');
        }

        // The name reaches terminals and consent screens, and a NUL byte makes some databases fail
        if (1 !== preg_match('//u', $name) || 0 !== preg_match('/\p{C}/u', $name)) {
            throw $this->invalid('client_name must not contain control characters.');
        }

        if (mb_strlen($name) > self::MAX_NAME_LENGTH) {
            throw $this->invalid(\sprintf('client_name may be at most %d characters long.', self::MAX_NAME_LENGTH));
        }

        return $name;
    }

    /**
     * @param array<mixed> $metadata
     */
    private function authMethod(array $metadata): string
    {
        $method = $metadata['token_endpoint_auth_method'] ?? 'client_secret_basic';

        if (!\is_string($method) || !\in_array($method, self::AUTH_METHODS, true)) {
            throw $this->invalid('token_endpoint_auth_method must be one of: ' . implode(', ', self::AUTH_METHODS) . '.');
        }

        return $method;
    }

    /**
     * @param array<mixed> $metadata
     *
     * @return list<non-empty-string>
     */
    private function scopes(array $metadata): array
    {
        $scope = $metadata['scope'] ?? null;

        if (null === $scope || '' === $scope) {
            return $this->defaultScopes;
        }

        if (!\is_string($scope)) {
            throw $this->invalid('scope must be a string.');
        }

        $requested = array_values(array_unique(array_filter(explode(' ', $scope), static fn (string $part): bool => '' !== $part)));
        $granted = array_values(array_intersect($requested, $this->allowedScopes));

        if ([] === $granted) {
            throw $this->invalid('scope must include at least one supported scope.');
        }

        return $granted;
    }

    /**
     * @param array<mixed> $metadata
     *
     * @return list<non-empty-string>|null null when the key is absent
     */
    private function listOfStrings(array $metadata, string $key): ?array
    {
        if (!\array_key_exists($key, $metadata)) {
            return null;
        }

        $value = $metadata[$key];

        if (!\is_array($value) || !array_is_list($value)) {
            throw $this->invalid(\sprintf('%s must be an array of strings.', $key));
        }

        foreach ($value as $item) {
            if (!\is_string($item) || '' === $item) {
                throw $this->invalid(\sprintf('%s must be an array of strings.', $key));
            }
        }

        return $value;
    }

    private function invalid(string $description): InvalidClientMetadataException
    {
        return new InvalidClientMetadataException(InvalidClientMetadataException::INVALID_CLIENT_METADATA, $description);
    }

    private function shorten(string $value): string
    {
        return mb_substr($value, 0, 100);
    }
}
