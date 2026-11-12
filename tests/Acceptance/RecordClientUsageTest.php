<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Acceptance;

use Doctrine\ORM\EntityManagerInterface;
use League\Bundle\OAuth2ServerBundle\Entity\AccessToken as AccessTokenEntity;
use League\Bundle\OAuth2ServerBundle\Entity\Client as ClientEntity;
use League\Bundle\OAuth2ServerBundle\EventListener\RecordClientUsageListener;
use League\Bundle\OAuth2ServerBundle\Manager\AccessTokenManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\AuthorizationCodeManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\DeviceCodeManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\RefreshTokenManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\ScopeManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\AbstractClient;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use League\Bundle\OAuth2ServerBundle\Tests\Fixtures\FixtureFactory;
use League\OAuth2\Server\RequestAccessTokenEvent;
use Psr\Http\Message\ServerRequestInterface;

final class RecordClientUsageTest extends AbstractAcceptanceTestCase
{
    private const NOW = '2026-11-12 12:00:00';

    protected function setUp(): void
    {
        parent::setUp();

        FixtureFactory::initializeFixtures(
            $this->client->getContainer()->get(ScopeManagerInterface::class),
            $this->client->getContainer()->get(ClientManagerInterface::class),
            $this->client->getContainer()->get(AccessTokenManagerInterface::class),
            $this->client->getContainer()->get(RefreshTokenManagerInterface::class),
            $this->client->getContainer()->get(AuthorizationCodeManagerInterface::class),
            $this->client->getContainer()->get(DeviceCodeManagerInterface::class)
        );
    }

    public function testATokenRequestRecordsTheUsageOfARegisteredClient(): void
    {
        $this->markRegistered(FixtureFactory::FIXTURE_CLIENT_FIRST, null);

        $this->client->request('POST', '/token', [
            'client_id' => FixtureFactory::FIXTURE_CLIENT_FIRST,
            'client_secret' => 'secret',
            'grant_type' => 'client_credentials',
        ]);

        $this->assertSame(200, $this->client->getResponse()->getStatusCode());
        $lastUsedAt = $this->storedClient(FixtureFactory::FIXTURE_CLIENT_FIRST)->getLastUsedAt();
        $this->assertNotNull($lastUsedAt);
        $this->assertLessThan(60, abs(time() - $lastUsedAt->getTimestamp()));
    }

    public function testATokenRequestLeavesAClientThatDidNotRegisterItselfAlone(): void
    {
        $this->client->request('POST', '/token', [
            'client_id' => FixtureFactory::FIXTURE_CLIENT_FIRST,
            'client_secret' => 'secret',
            'grant_type' => 'client_credentials',
        ]);

        $this->assertSame(200, $this->client->getResponse()->getStatusCode());
        $this->assertNull($this->storedClient(FixtureFactory::FIXTURE_CLIENT_FIRST)->getLastUsedAt());
    }

    public function testAClientIsWrittenAgainOnlyAfterADay(): void
    {
        $this->markRegistered(FixtureFactory::FIXTURE_CLIENT_FIRST, null);

        $this->record(FixtureFactory::FIXTURE_CLIENT_FIRST, '2026-11-12 03:00:00');
        $this->assertSame('2026-11-12 03:00:00', $this->storedClient(FixtureFactory::FIXTURE_CLIENT_FIRST)->getLastUsedAt()?->format('Y-m-d H:i:s'));

        $this->record(FixtureFactory::FIXTURE_CLIENT_FIRST, '2026-11-13 02:59:59');
        $this->assertSame('2026-11-12 03:00:00', $this->storedClient(FixtureFactory::FIXTURE_CLIENT_FIRST)->getLastUsedAt()?->format('Y-m-d H:i:s'));

        $this->record(FixtureFactory::FIXTURE_CLIENT_FIRST, '2026-11-13 03:00:00');
        $this->assertSame('2026-11-13 03:00:00', $this->storedClient(FixtureFactory::FIXTURE_CLIENT_FIRST)->getLastUsedAt()?->format('Y-m-d H:i:s'));
    }

    public function testAFailingWriteDoesNotFailTheRequest(): void
    {
        $this->markRegistered(FixtureFactory::FIXTURE_CLIENT_FIRST, null);

        $listener = new RecordClientUsageListener($this->entityManager(), 'League\Bundle\OAuth2ServerBundle\Model\NoSuchClient');

        $listener($this->event(FixtureFactory::FIXTURE_CLIENT_FIRST));

        $this->assertNull($this->storedClient(FixtureFactory::FIXTURE_CLIENT_FIRST)->getLastUsedAt());
    }

    private function record(string $identifier, string $at): void
    {
        $listener = new RecordClientUsageListener($this->entityManager(), Client::class, null, static fn (): \DateTimeImmutable => new \DateTimeImmutable($at));
        $listener($this->event($identifier));
    }

    private function event(string $identifier): RequestAccessTokenEvent
    {
        $client = new ClientEntity();
        $client->setIdentifier($identifier);

        $token = new AccessTokenEntity();
        $token->setClient($client);

        return new RequestAccessTokenEvent('access_token.issued', $this->createMock(ServerRequestInterface::class), $token);
    }

    private function markRegistered(string $identifier, ?string $lastUsedAt): void
    {
        $client = $this->storedClient($identifier);
        $client->setRegisteredAt(new \DateTimeImmutable('-100 days'));
        $client->setLastUsedAt(null === $lastUsedAt ? null : new \DateTimeImmutable($lastUsedAt));
        $this->client->getContainer()->get(ClientManagerInterface::class)->save($client);
        $this->entityManager()->clear();
    }

    private function storedClient(string $identifier): AbstractClient
    {
        $this->entityManager()->clear();

        $client = $this->client->getContainer()->get(ClientManagerInterface::class)->find($identifier);
        \assert($client instanceof AbstractClient);

        return $client;
    }

    private function entityManager(): EntityManagerInterface
    {
        return $this->client->getContainer()->get('doctrine.orm.entity_manager');
    }
}
