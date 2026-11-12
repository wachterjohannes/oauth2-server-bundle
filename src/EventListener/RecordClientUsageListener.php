<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\EventListener;

use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\AbstractClient;
use League\OAuth2\Server\RequestAccessTokenEvent;

/**
 * Notes when a client that registered itself last got an access token, so that clients nobody uses can be found.
 *
 * The time is only written when the last one is a day old, so a busy client does not cost a write per token.
 *
 * @internal
 */
final readonly class RecordClientUsageListener
{
    public const RESOLUTION = 86400;

    /**
     * @param (\Closure(): \DateTimeImmutable)|null $now
     */
    public function __construct(
        private ClientManagerInterface $clientManager,
        private ?\Closure $now = null,
    ) {
    }

    public function __invoke(RequestAccessTokenEvent $event): void
    {
        $identifier = $event->getAccessToken()->getClient()->getIdentifier();
        $client = $this->clientManager->find($identifier);

        // A client that did not register itself is none of our business
        if (!$client instanceof AbstractClient || null === $client->getRegisteredAt()) {
            return;
        }

        $now = null === $this->now ? new \DateTimeImmutable() : ($this->now)();
        $lastUsedAt = $client->getLastUsedAt();

        if (null !== $lastUsedAt && $now->getTimestamp() - $lastUsedAt->getTimestamp() < self::RESOLUTION) {
            return;
        }

        $client->setLastUsedAt($now);
        $this->clientManager->save($client);
    }
}
