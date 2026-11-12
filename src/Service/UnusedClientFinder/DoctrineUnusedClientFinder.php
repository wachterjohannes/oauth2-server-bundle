<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Service\UnusedClientFinder;

use Doctrine\ORM\EntityManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\AbstractClient;

/**
 * Finds the clients that registered themselves and have neither registered nor got an access token since a date.
 *
 * @internal
 */
final readonly class DoctrineUnusedClientFinder
{
    /**
     * @param class-string<AbstractClient> $clientFqcn
     */
    public function __construct(
        private EntityManagerInterface $entityManager,
        private string $clientFqcn,
    ) {
    }

    /**
     * @return list<AbstractClient>
     */
    public function find(\DateTimeImmutable $since): array
    {
        /** @var list<AbstractClient> */
        return $this->entityManager->createQueryBuilder()
            ->select('c')
            ->from($this->clientFqcn, 'c')
            ->where('c.registeredAt IS NOT NULL')
            ->andWhere('COALESCE(c.lastUsedAt, c.registeredAt) < :since')
            ->orderBy('c.registeredAt', 'ASC')
            ->setParameter('since', $since, 'datetime_immutable')
            ->getQuery()
            ->getResult();
    }
}
