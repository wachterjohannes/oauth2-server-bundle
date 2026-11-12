<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\EventListener;

use Doctrine\ORM\EntityManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\AbstractClient;
use League\OAuth2\Server\RequestAccessTokenEvent;
use Psr\Log\LoggerInterface;

/**
 * Notes when a client that registered itself last got an access token, so that clients nobody uses can be found.
 *
 * The time is only written when the last one is a day old, so a busy client does not cost a write per token.
 * It is one UPDATE that does not go through the client manager, because a token request must not run the
 * listeners of a client save or flush unrelated changes.
 *
 * @internal
 */
final readonly class RecordClientUsageListener
{
    public const RESOLUTION = 86400;

    /**
     * @param class-string<AbstractClient> $clientFqcn
     * @param (\Closure(): \DateTimeImmutable)|null $now
     */
    public function __construct(
        private EntityManagerInterface $entityManager,
        private string $clientFqcn,
        private ?LoggerInterface $logger = null,
        private ?\Closure $now = null,
    ) {
    }

    public function __invoke(RequestAccessTokenEvent $event): void
    {
        $now = null === $this->now ? new \DateTimeImmutable() : ($this->now)();

        // The grant has revoked the old tokens by now, so a failing bookkeeping write must not fail the request
        try {
            $this->entityManager->createQueryBuilder()
                ->update($this->clientFqcn, 'c')
                ->set('c.lastUsedAt', ':now')
                // A client that did not register itself is none of our business
                ->where('c.identifier = :identifier')
                ->andWhere('c.registeredAt IS NOT NULL')
                ->andWhere('c.lastUsedAt IS NULL OR c.lastUsedAt <= :threshold')
                ->setParameter('now', $now, 'datetime_immutable')
                ->setParameter('threshold', $now->modify('-' . self::RESOLUTION . ' seconds'), 'datetime_immutable')
                ->setParameter('identifier', $event->getAccessToken()->getClient()->getIdentifier())
                ->getQuery()
                ->execute();
        } catch (\Throwable $e) {
            $this->logger?->error('The usage of a client could not be recorded.', ['exception' => $e]);
        }
    }
}
