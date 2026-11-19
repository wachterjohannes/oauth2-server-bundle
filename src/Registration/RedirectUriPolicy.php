<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Registration;

use League\Bundle\OAuth2ServerBundle\ValueObject\RedirectUri;

/**
 * Which redirect URIs a dynamically registered client may use: HTTPS, an HTTP loopback address
 * (RFC 8252 section 7.3) or a private-use scheme for native apps (section 7.1), never with a fragment.
 *
 * @internal
 */
final class RedirectUriPolicy
{
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '::1'];

    public function isAllowed(string $uri): bool
    {
        if ('' === $uri || !$this->matchesPolicy($uri)) {
            return false;
        }

        // The value object throws on a URI its own pattern rejects, for example a private-use scheme without a path
        try {
            new RedirectUri($uri);
        } catch (\Throwable) {
            return false;
        }

        return true;
    }

    private function matchesPolicy(string $uri): bool
    {
        // "$" in the value object's pattern also matches before a trailing newline
        if (1 === preg_match('/[\x00-\x20\x7f]/', $uri)) {
            return false;
        }

        $parts = parse_url($uri);
        if (false === $parts || !isset($parts['scheme']) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);

        if ('https' === $scheme) {
            return isset($parts['host']);
        }

        if ('http' === $scheme) {
            return isset($parts['host']) && \in_array(strtolower(trim($parts['host'], '[]')), self::LOOPBACK_HOSTS, true);
        }

        // Private-use URI scheme for native apps, for example "com.example.app:/oauth"
        return !isset($parts['host']) && '' !== ($parts['path'] ?? '')
            && 1 === preg_match('/^[a-z][a-z0-9+-]*(\.[a-z0-9+-]+)+$/', $scheme);
    }
}
