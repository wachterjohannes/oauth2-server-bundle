<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Acceptance;

use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\ClientInterface;
use PHPUnit\Framework\Attributes\DataProvider;

final class ClientRegistrationEndpointTest extends AbstractAcceptanceTestCase
{
    public function testAPublicClientIsRegistered(): void
    {
        $response = $this->register([
            'client_name' => 'My client',
            'redirect_uris' => ['https://example.com/callback', 'http://127.0.0.1:8080/callback', 'com.example.app:/oauth'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_method' => 'none',
            'scope' => 'fancy',
        ]);

        $this->assertSame(201, $response['status']);
        $this->assertStringContainsString('no-store', $this->client->getResponse()->headers->get('Cache-Control'));

        $registered = $response['body'];
        $this->assertArrayNotHasKey('client_secret', $registered);
        $this->assertSame('My client', $registered['client_name']);
        $this->assertSame(['authorization_code', 'refresh_token'], $registered['grant_types']);
        $this->assertSame(['code'], $registered['response_types']);
        $this->assertSame('fancy', $registered['scope']);
        $this->assertSame('none', $registered['token_endpoint_auth_method']);
        $this->assertGreaterThan(0, $registered['client_id_issued_at']);

        $client = $this->storedClient($registered['client_id']);
        $this->assertFalse($client->isConfidential());
        $this->assertFalse($client->isPlainTextPkceAllowed());
        $this->assertTrue($client->isActive());
        $this->assertSame(['https://example.com/callback', 'http://127.0.0.1:8080/callback', 'com.example.app:/oauth'], array_map(strval(...), $client->getRedirectUris()));
        $this->assertSame(['authorization_code', 'refresh_token'], array_map(strval(...), $client->getGrants()));
        $this->assertSame($registered['client_id_issued_at'], $client->getRegisteredAt()?->getTimestamp());
        $this->assertNull($client->getLastUsedAt());
    }

    public function testAConfidentialClientGetsASecretThatIsStoredHashed(): void
    {
        $response = $this->register(['redirect_uris' => ['https://example.com/callback']]);

        $this->assertSame(201, $response['status']);

        $registered = $response['body'];
        $this->assertSame('client_secret_basic', $registered['token_endpoint_auth_method']);
        $this->assertSame(0, $registered['client_secret_expires_at']);
        $this->assertSame(64, \strlen($registered['client_secret']));

        $client = $this->storedClient($registered['client_id']);
        $this->assertTrue($client->isConfidential());
        $this->assertNotSame($registered['client_secret'], $client->getSecret());
        $this->assertTrue(password_verify($registered['client_secret'], $client->getSecret()));
    }

    public function testAClientThatAsksForNoScopeGetsTheDefaultScopes(): void
    {
        $response = $this->register(['redirect_uris' => ['https://example.com/callback'], 'token_endpoint_auth_method' => 'none']);

        $this->assertSame('rock', $response['body']['scope']);
    }

    public function testTheMetadataAdvertiseTheRegistrationEndpoint(): void
    {
        $this->client->request('GET', '/.well-known/oauth-authorization-server/auth');

        $metadata = json_decode($this->client->getResponse()->getContent(), true);

        $this->assertSame('https://example.com/register', $metadata['registration_endpoint']);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    #[DataProvider('invalidMetadataProvider')]
    public function testInvalidMetadataIsRefused(array $metadata, string $expectedError): void
    {
        $response = $this->register($metadata);

        $this->assertSame(400, $response['status']);
        $this->assertSame($expectedError, $response['body']['error']);
        $this->assertNotEmpty($response['body']['error_description']);
    }

    public static function invalidMetadataProvider(): iterable
    {
        $valid = ['redirect_uris' => ['https://example.com/callback']];

        yield 'without redirect uris' => [[], 'invalid_redirect_uri'];
        yield 'with an empty redirect uri list' => [['redirect_uris' => []], 'invalid_redirect_uri'];
        yield 'with a redirect uri that is no list' => [['redirect_uris' => 'https://example.com/callback'], 'invalid_client_metadata'];
        yield 'with plain http on a public host' => [['redirect_uris' => ['http://example.com/callback']], 'invalid_redirect_uri'];
        yield 'with a fragment' => [['redirect_uris' => ['https://example.com/callback#top']], 'invalid_redirect_uri'];
        yield 'with a scheme the value object cannot parse' => [['redirect_uris' => ['vbscript.x:foo']], 'invalid_redirect_uri'];
        yield 'with a redirect uri over the length limit' => [['redirect_uris' => ['https://example.com/' . str_repeat('a', 2000)]], 'invalid_redirect_uri'];
        yield 'with too many redirect uris' => [['redirect_uris' => array_map(static fn (int $i): string => "https://example.com/$i", range(1, 11))], 'invalid_redirect_uri'];
        yield 'with a name over the column length' => [$valid + ['client_name' => str_repeat('a', 129)], 'invalid_client_metadata'];
        yield 'with a name that has an escape sequence' => [$valid + ['client_name' => "x\x1b[31my"], 'invalid_client_metadata'];
        yield 'with a name that has a NUL byte' => [$valid + ['client_name' => "x\0y"], 'invalid_client_metadata'];
        yield 'with a name that has a line break' => [$valid + ['client_name' => "x\ny"], 'invalid_client_metadata'];
        yield 'with a name that is no string' => [$valid + ['client_name' => ['a']], 'invalid_client_metadata'];
        yield 'with a grant that is not allowed' => [$valid + ['grant_types' => ['client_credentials']], 'invalid_client_metadata'];
        yield 'with an unknown grant' => [$valid + ['grant_types' => ['password']], 'invalid_client_metadata'];
        yield 'with an empty grant list' => [$valid + ['grant_types' => []], 'invalid_client_metadata'];
        yield 'with response types that do not match the grant' => [$valid + ['response_types' => ['token']], 'invalid_client_metadata'];
        yield 'with an unknown auth method' => [$valid + ['token_endpoint_auth_method' => 'private_key_jwt'], 'invalid_client_metadata'];
        yield 'with a scope that is not available' => [$valid + ['scope' => 'admin'], 'invalid_client_metadata'];
        yield 'with a refresh token and nothing that issues one' => [$valid + ['grant_types' => ['refresh_token']], 'invalid_client_metadata'];
        yield 'with client credentials and no secret' => [$valid + ['grant_types' => ['client_credentials'], 'token_endpoint_auth_method' => 'none'], 'invalid_client_metadata'];
        yield 'with a scope that is no string' => [$valid + ['scope' => ['fancy']], 'invalid_client_metadata'];
    }

    public function testABodyThatIsNotJsonIsRefused(): void
    {
        $this->client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'application/json'], '{not json');

        $this->assertSame(400, $this->client->getResponse()->getStatusCode());
        $this->assertSame('invalid_client_metadata', json_decode($this->client->getResponse()->getContent(), true)['error']);
    }

    public function testABodyThatIsNoObjectIsRefused(): void
    {
        $this->client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'application/json'], '["https://example.com/callback"]');

        $this->assertSame(400, $this->client->getResponse()->getStatusCode());
    }

    public function testAFormPostIsRefused(): void
    {
        $this->client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'text/plain'], '{"redirect_uris": ["https://example.com/callback"]}');

        $this->assertSame(415, $this->client->getResponse()->getStatusCode());
        $this->assertCount(0, $this->client->getContainer()->get(ClientManagerInterface::class)->list(null));
    }

    public function testAJsonContentTypeWithACharsetIsAccepted(): void
    {
        $this->client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'Application/JSON; charset=UTF-8'], '{"redirect_uris": ["https://example.com/callback"]}');

        $this->assertSame(201, $this->client->getResponse()->getStatusCode());
    }

    public function testALargeBodyIsRefused(): void
    {
        $this->client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'application/json'], json_encode(['redirect_uris' => ['https://example.com/callback'], 'padding' => str_repeat('a', 16384)]));

        $this->assertSame(413, $this->client->getResponse()->getStatusCode());
    }

    public function testOtherMethodsAreNotAllowed(): void
    {
        $this->client->request('GET', '/register');

        $this->assertSame(405, $this->client->getResponse()->getStatusCode());
    }

    public function testNoClientIsStoredForARefusedRequest(): void
    {
        $this->register(['redirect_uris' => ['http://example.com/callback']]);

        $this->assertCount(0, $this->client->getContainer()->get(ClientManagerInterface::class)->list(null));
    }

    private function storedClient(string $identifier): ClientInterface
    {
        $client = $this->client->getContainer()->get(ClientManagerInterface::class)->find($identifier);
        $this->assertNotNull($client);

        return $client;
    }

    /**
     * @param array<string, mixed> $metadata
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    private function register(array $metadata): array
    {
        $this->client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'application/json'], json_encode($metadata, \JSON_THROW_ON_ERROR));

        $response = $this->client->getResponse();

        return ['status' => $response->getStatusCode(), 'body' => json_decode($response->getContent(), true)];
    }
}
