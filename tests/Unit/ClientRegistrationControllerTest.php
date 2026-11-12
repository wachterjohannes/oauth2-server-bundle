<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Unit;

use League\Bundle\OAuth2ServerBundle\Controller\ClientRegistrationController;
use League\Bundle\OAuth2ServerBundle\Manager\InMemory\ClientManager;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use League\Bundle\OAuth2ServerBundle\Registration\ClientRegistrar;
use League\Bundle\OAuth2ServerBundle\Registration\RedirectUriPolicy;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

final class ClientRegistrationControllerTest extends TestCase
{
    public function testTheRateLimiterAnswersTooManyRequestsAndKeepsCountPerAddress(): void
    {
        $manager = new ClientManager(new EventDispatcher());
        $controller = $this->controller($manager, new RateLimiterFactory(['id' => 'registration', 'policy' => 'fixed_window', 'limit' => 2, 'interval' => '1 hour'], new InMemoryStorage()));

        $this->assertSame(201, $controller->indexAction($this->request('203.0.113.1'))->getStatusCode());
        $this->assertSame(201, $controller->indexAction($this->request('203.0.113.1'))->getStatusCode());

        $refused = $controller->indexAction($this->request('203.0.113.1'));

        $this->assertSame(429, $refused->getStatusCode());
        $this->assertSame('too_many_requests', json_decode($refused->getContent(), true)['error']);
        $this->assertGreaterThan(0, (int) $refused->headers->get('Retry-After'));
        $this->assertCount(2, $manager->list(null));

        $this->assertSame(201, $controller->indexAction($this->request('203.0.113.2'))->getStatusCode());
    }

    public function testARefusedRegistrationCountsAgainstTheBudget(): void
    {
        $controller = $this->controller(new ClientManager(new EventDispatcher()), new RateLimiterFactory(['id' => 'registration', 'policy' => 'fixed_window', 'limit' => 1, 'interval' => '1 hour'], new InMemoryStorage()));

        $this->assertSame(400, $controller->indexAction($this->request('203.0.113.1', '{}'))->getStatusCode());
        $this->assertSame(429, $controller->indexAction($this->request('203.0.113.1'))->getStatusCode());
    }

    public function testATokenThatDiffersOnlyInCaseIsRefused(): void
    {
        $controller = $this->controller(new ClientManager(new EventDispatcher()), null, 'Secret-Token');

        $request = $this->request('203.0.113.1');
        $request->headers->set('Authorization', 'Bearer secret-token');

        $this->assertSame(401, $controller->indexAction($request)->getStatusCode());
    }

    private function controller(ClientManager $manager, ?RateLimiterFactory $limiter, ?string $initialAccessToken = null): ClientRegistrationController
    {
        $registrar = new ClientRegistrar($manager, new NativePasswordHasher(), new RedirectUriPolicy(), Client::class, ['authorization_code', 'refresh_token'], ['fancy'], ['fancy'], 10);

        return new ClientRegistrationController($registrar, true, $initialAccessToken, $limiter);
    }

    private function request(string $ip, string $body = '{"redirect_uris": ["https://example.com/callback"]}'): Request
    {
        return Request::create('/register', 'POST', [], [], [], ['REMOTE_ADDR' => $ip, 'CONTENT_TYPE' => 'application/json'], $body);
    }
}
