<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Controller;

use League\Bundle\OAuth2ServerBundle\Registration\ClientRegistrar;
use League\Bundle\OAuth2ServerBundle\Registration\InvalidClientMetadataException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

/**
 * RFC 7591 dynamic client registration.
 */
final readonly class ClientRegistrationController
{
    /**
     * @param bool $enabled whether the registration is enabled in the bundle configuration
     * @param string|null $initialAccessToken a bearer token every registration request must carry
     */
    public function __construct(
        private ClientRegistrar $registrar,
        private bool $enabled,
        private ?string $initialAccessToken,
        private ?RateLimiterFactoryInterface $rateLimiterFactory,
    ) {
    }

    public function indexAction(Request $request): JsonResponse
    {
        if (!$this->enabled) {
            throw new NotFoundHttpException();
        }

        // Before the token check, so a guessed token costs the caller a request of the budget too
        if (null !== $this->rateLimiterFactory) {
            $limit = $this->rateLimiterFactory->create($request->getClientIp() ?? 'unknown')->consume();

            if (!$limit->isAccepted()) {
                return $this->error('too_many_requests', 'Too many registrations. Try again later.', Response::HTTP_TOO_MANY_REQUESTS, [
                    'Retry-After' => (string) max(1, $limit->getRetryAfter()->getTimestamp() - time()),
                ]);
            }
        }

        if (null !== $this->initialAccessToken && !hash_equals($this->initialAccessToken, $this->bearerToken($request))) {
            return $this->error('invalid_token', 'A valid initial access token is required.', Response::HTTP_UNAUTHORIZED, [
                'WWW-Authenticate' => 'Bearer error="invalid_token"',
            ]);
        }

        try {
            $metadata = json_decode($request->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $this->error(InvalidClientMetadataException::INVALID_CLIENT_METADATA, 'The request body must be valid JSON.');
        }

        if (!\is_array($metadata) || ([] !== $metadata && array_is_list($metadata))) {
            return $this->error(InvalidClientMetadataException::INVALID_CLIENT_METADATA, 'The request body must be a JSON object.');
        }

        try {
            $registered = $this->registrar->register($metadata);
        } catch (InvalidClientMetadataException $e) {
            return $this->error($e->getError(), $e->getMessage());
        }

        return new JsonResponse($registered, Response::HTTP_CREATED, [
            // The response carries the client secret
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }

    private function bearerToken(Request $request): string
    {
        $header = (string) $request->headers->get('Authorization');

        return 1 === preg_match('/^Bearer +(\S+)$/i', $header, $matches) ? $matches[1] : '';
    }

    /**
     * @param array<string, string> $headers
     */
    private function error(string $error, string $description, int $status = Response::HTTP_BAD_REQUEST, array $headers = []): JsonResponse
    {
        return new JsonResponse(['error' => $error, 'error_description' => $description], $status, $headers);
    }
}
