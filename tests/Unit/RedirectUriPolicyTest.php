<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Unit;

use League\Bundle\OAuth2ServerBundle\Registration\RedirectUriPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RedirectUriPolicyTest extends TestCase
{
    #[DataProvider('uriProvider')]
    public function testItAllowsHttpsLoopbackAndPrivateUseSchemes(string $uri, bool $expected): void
    {
        $this->assertSame($expected, (new RedirectUriPolicy())->isAllowed($uri));
    }

    public static function uriProvider(): iterable
    {
        yield 'https' => ['https://example.com/callback', true];
        yield 'https with a port and a query' => ['https://example.com:8443/callback?a=b', true];
        yield 'http on localhost' => ['http://localhost/callback', true];
        yield 'http on 127.0.0.1 with a port' => ['http://127.0.0.1:8080/callback', true];
        yield 'http on the IPv6 loopback' => ['http://[::1]:8080/callback', true];
        yield 'a private-use scheme' => ['com.example.app:/oauth', true];
        yield 'http on a public host' => ['http://example.com/callback', false];
        yield 'a fragment' => ['https://example.com/callback#top', false];
        yield 'credentials' => ['https://user:pass@example.com/callback', false];
        yield 'a scheme without a dot' => ['myapp:/oauth', false];
        yield 'javascript' => ['javascript:alert(1)', false];
        yield 'a dotted scheme the value object cannot parse' => ['vbscript.x:foo', false];
        yield 'no scheme' => ['example.com/callback', false];
        yield 'empty' => ['', false];
        yield 'a private-use scheme without a path' => ['com.example.app:', false];
        yield 'a private-use scheme with a host' => ['com.example.app://evil.com/x', false];
        yield 'a trailing newline' => ["https://example.com/callback\n", false];
        yield 'a NUL byte' => ["https://example.com/\0b", false];
        yield 'an escape sequence' => ["https://example.com/\x1b[31mb", false];
        yield 'a space' => ['https://example.com/a b', false];
    }
}
