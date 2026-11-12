<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Acceptance;

use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Tests\TestHelper;
use Symfony\Bundle\FrameworkBundle\Console\Application;

final class ClientRegistrationAccessControlTest extends AbstractAcceptanceTestCase
{
    private const BODY = '{"redirect_uris": ["https://example.com/callback"]}';

    protected function setUp(): void
    {
        // Every test boots the kernel of its own environment
    }

    public function testWithoutAnInitialAccessTokenNothingIsRegistered(): void
    {
        $this->boot('registration_token');

        $this->client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'application/json'], self::BODY);

        $this->assertSame(401, $this->client->getResponse()->getStatusCode());
        $this->assertSame('Bearer', $this->client->getResponse()->headers->get('WWW-Authenticate'));
        $this->assertSame('invalid_token', json_decode($this->client->getResponse()->getContent(), true)['error']);
        $this->assertCount(0, $this->client->getContainer()->get(ClientManagerInterface::class)->list(null));
    }

    public function testAWrongInitialAccessTokenIsRefused(): void
    {
        $this->boot('registration_token');

        $this->client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => 'Bearer wrong-token'], self::BODY);

        $this->assertSame(401, $this->client->getResponse()->getStatusCode());
        $this->assertSame('Bearer error="invalid_token"', $this->client->getResponse()->headers->get('WWW-Authenticate'));
    }

    public function testTheInitialAccessTokenLetsAClientRegister(): void
    {
        $this->boot('registration_token');

        $this->client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => 'Bearer secret-token'], self::BODY);

        $this->assertSame(201, $this->client->getResponse()->getStatusCode());
    }

    public function testAnImportedRouteAnswersNotFoundWhileTheRegistrationIsOff(): void
    {
        $this->boot('registration_disabled');

        $this->client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'application/json'], self::BODY);

        $this->assertSame(404, $this->client->getResponse()->getStatusCode());
    }

    private function boot(string $environment): void
    {
        $this->client = self::createClient(['environment' => $environment]);
        $this->application = new Application($this->client->getKernel());

        TestHelper::initializeDoctrineSchema($this->application);
    }
}
