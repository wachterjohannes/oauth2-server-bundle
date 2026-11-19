<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Acceptance;

use Doctrine\ORM\EntityManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\AccessTokenManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\AccessToken;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class ClearUnusedClientsCommandTest extends AbstractAcceptanceTestCase
{
    private const TOKEN = 'a-token-of-the-unused-client';

    protected function setUp(): void
    {
        parent::setUp();

        $this->saveClient('unused', registeredAt: '-100 days');
        $this->saveClient('used-lately', registeredAt: '-100 days', lastUsedAt: '-10 days');
        $this->saveClient('used-long-ago', registeredAt: '-100 days', lastUsedAt: '-90 days');
        $this->saveClient('registered-lately', registeredAt: '-1 day');
        $this->saveClient('created-by-hand');

        $this->client->getContainer()->get(AccessTokenManagerInterface::class)->save(
            new AccessToken(self::TOKEN, new \DateTimeImmutable('-99 days'), $this->clients()->find('unused'), null, [])
        );

        $this->entityManager()->clear();
    }

    public function testClientsThatWereNotUsedForAWhileAreRemoved(): void
    {
        $tester = $this->executeClearCommand(['--older-than' => 'P60D']);

        $this->assertSame(Command::SUCCESS, $tester->getStatusCode());
        $this->assertStringContainsString('Removed 2 unused clients.', $tester->getDisplay());

        $this->assertSame(['created-by-hand', 'registered-lately', 'used-lately'], $this->remainingClients());
    }

    public function testTheTokensOfARemovedClientGoWithIt(): void
    {
        $this->executeClearCommand([]);

        $this->assertNull($this->client->getContainer()->get(AccessTokenManagerInterface::class)->find(self::TOKEN));
    }

    public function testADryRunListsTheClientsAndKeepsThem(): void
    {
        $tester = $this->executeClearCommand(['--dry-run' => true]);

        $this->assertSame(Command::SUCCESS, $tester->getStatusCode());
        $this->assertStringContainsString('unused', $tester->getDisplay());
        $this->assertStringContainsString('used-long-ago', $tester->getDisplay());
        $this->assertStringContainsString('2 clients would be removed.', $tester->getDisplay());

        $this->assertCount(5, $this->remainingClients());
    }

    public function testAClientThatWasNeverRegisteredByItselfIsNeverRemoved(): void
    {
        $this->executeClearCommand(['--older-than' => 'P40D']);

        $this->assertContains('created-by-hand', $this->remainingClients());
    }

    #[DataProvider('refusedWindowProvider')]
    public function testAWindowShorterThanARefreshTokenLifetimeIsRefused(string $window, string $message): void
    {
        $tester = $this->executeClearCommand(['--older-than' => $window]);

        $this->assertSame(Command::FAILURE, $tester->getStatusCode());
        $this->assertStringContainsString($message, (string) preg_replace('/\s+/', ' ', $tester->getDisplay()));
        $this->assertCount(5, $this->remainingClients());
    }

    public static function refusedWindowProvider(): iterable
    {
        yield 'the lifetime of a refresh token' => ['P1M', 'longer than the lifetime of the longest token'];
        yield 'a week' => ['P7D', 'longer than the lifetime of the longest token'];
        yield 'no time at all' => ['PT0S', 'longer than the lifetime of the longest token'];
        yield 'something that is no interval' => ['yesterday', 'must be a date interval specification'];
    }

    /**
     * @param array<string, mixed> $options
     */
    private function executeClearCommand(array $options): CommandTester
    {
        $command = $this->application->find('league:oauth2-server:clear-unused-clients');
        $tester = new CommandTester($command);
        $tester->execute($options);

        $this->entityManager()->clear();

        return $tester;
    }

    /**
     * @return list<string>
     */
    private function remainingClients(): array
    {
        $this->entityManager()->clear();

        $identifiers = array_map(static fn (Client $client): string => $client->getIdentifier(), $this->clients()->list(null));
        sort($identifiers);

        return $identifiers;
    }

    private function entityManager(): EntityManagerInterface
    {
        return $this->client->getContainer()->get('doctrine.orm.entity_manager');
    }

    private function clients(): ClientManagerInterface
    {
        return $this->client->getContainer()->get(ClientManagerInterface::class);
    }

    private function saveClient(string $identifier, ?string $registeredAt = null, ?string $lastUsedAt = null): void
    {
        $client = new Client($identifier, $identifier, null);
        $client->setRegisteredAt(null === $registeredAt ? null : new \DateTimeImmutable($registeredAt));
        $client->setLastUsedAt(null === $lastUsedAt ? null : new \DateTimeImmutable($lastUsedAt));

        $this->clients()->save($client);
    }
}
