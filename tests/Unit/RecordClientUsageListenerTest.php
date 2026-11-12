<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Unit;

use League\Bundle\OAuth2ServerBundle\Entity\AccessToken as AccessTokenEntity;
use League\Bundle\OAuth2ServerBundle\Entity\Client as ClientEntity;
use League\Bundle\OAuth2ServerBundle\EventListener\RecordClientUsageListener;
use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use League\OAuth2\Server\RequestAccessTokenEvent;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class RecordClientUsageListenerTest extends TestCase
{
    private const NOW = '2026-11-12 12:00:00';

    private ClientManagerInterface&MockObject $manager;

    protected function setUp(): void
    {
        $this->manager = $this->createMock(ClientManagerInterface::class);
    }

    public function testTheFirstTokenOfARegisteredClientIsRecorded(): void
    {
        $client = $this->registered(null);
        $this->manager->method('find')->willReturn($client);
        $this->manager->expects($this->once())->method('save')->with($client);

        $this->invoke();

        $this->assertEquals(new \DateTimeImmutable(self::NOW), $client->getLastUsedAt());
    }

    public function testAClientUsedTodayIsNotWrittenAgain(): void
    {
        $client = $this->registered(new \DateTimeImmutable('2026-11-12 03:00:00'));
        $this->manager->method('find')->willReturn($client);
        $this->manager->expects($this->never())->method('save');

        $this->invoke();
    }

    public function testAClientUsedYesterdayIsWrittenAgain(): void
    {
        $client = $this->registered(new \DateTimeImmutable('2026-11-11 11:00:00'));
        $this->manager->method('find')->willReturn($client);
        $this->manager->expects($this->once())->method('save');

        $this->invoke();

        $this->assertEquals(new \DateTimeImmutable(self::NOW), $client->getLastUsedAt());
    }

    public function testAClientThatDidNotRegisterItselfIsLeftAlone(): void
    {
        $this->manager->method('find')->willReturn(new Client('manual', 'manual', null));
        $this->manager->expects($this->never())->method('save');

        $this->invoke();
    }

    public function testAnUnknownClientIsIgnored(): void
    {
        $this->manager->method('find')->willReturn(null);
        $this->manager->expects($this->never())->method('save');

        $this->invoke();
    }

    private function registered(?\DateTimeImmutable $lastUsedAt): Client
    {
        $client = new Client('registered', 'registered', null);
        $client->setRegisteredAt(new \DateTimeImmutable('2026-01-01'));
        $client->setLastUsedAt($lastUsedAt);

        return $client;
    }

    private function invoke(): void
    {
        $leagueClient = new ClientEntity();
        $leagueClient->setIdentifier('registered');

        $token = new AccessTokenEntity();
        $token->setClient($leagueClient);

        $listener = new RecordClientUsageListener($this->manager, static fn (): \DateTimeImmutable => new \DateTimeImmutable(self::NOW));
        $listener(new RequestAccessTokenEvent('access_token.issued', $this->createMock(ServerRequestInterface::class), $token));
    }
}
