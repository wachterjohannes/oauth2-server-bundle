# Dynamic client registration

Clients that cannot be set up by hand, such as MCP clients or other generic OAuth clients, can register themselves with the endpoint of [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591).

The endpoint is off by default, and so is its route. Anyone who can reach an enabled endpoint can add a client to your database, so read [Protecting the endpoint](#protecting-the-endpoint) before you turn it on.

## Enabling it

1. Enable it in the bundle configuration:

    ```yaml
    league_oauth2_server:
        authorization_server:
            dynamic_client_registration:
                enabled: true
    ```

1. Import the route:

    ```yaml
    # config/routes/league_oauth2_server.yaml
    league_oauth2_server_registration:
        resource: '@LeagueOAuth2ServerBundle/config/routes_registration.php'
    ```

    The route is `POST /register`. While the registration is not enabled, it answers `404`.

When the [metadata endpoint](authorization-server-metadata.md) is enabled too, it advertises the route as `registration_endpoint`.

## Registering a client

```sh
curl -X POST https://auth.example.com/register \
    -H 'Content-Type: application/json' \
    -d '{
        "client_name": "My client",
        "redirect_uris": ["https://example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none"
    }'
```

The response has the status `201` and carries the metadata that was registered, with the `client_id` and, for confidential clients, the `client_secret`. The secret is stored hashed and shown only once.

| Field                        | Rules                                                                                                              |
|------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `redirect_uris`              | Required for the authorization code grant. At most `max_redirect_uris` entries of 2000 characters. HTTPS, an HTTP loopback address (`localhost`, `127.0.0.1`, `[::1]`) or a private-use scheme with a dot and a path such as `com.example.app:/oauth` (RFC 8252). No fragments, no credentials. |
| `client_name`                | At most 128 characters. Defaults to `Dynamically registered client`.                                               |
| `grant_types`                | Subset of `dynamic_client_registration.grant_types`. Defaults to `["authorization_code"]`. The bundle adds no grant for you, ask for `refresh_token` if the client needs it. |
| `response_types`             | Optional. Must be `["code"]` with the authorization code grant.                                                    |
| `token_endpoint_auth_method` | `client_secret_basic` (the default), `client_secret_post` or `none`. Public clients (`none`) get no secret.        |
| `scope`                      | Space separated. Scopes that are not allowed are dropped, and the request fails when none is left. Without it, the default scopes apply. |

Other metadata is ignored. The registered clients are active, never allow plain text PKCE and are stored through your client manager. Listen to `OAuth2Events::PRE_SAVE_CLIENT` to change a client before it is saved.

Errors follow RFC 7591 section 3.2.2: `400` with `invalid_redirect_uri` or `invalid_client_metadata` and an `error_description`.

## Protecting the endpoint

Without protection, a script can fill your client table. Use at least one of these.

### Initial access token

```yaml
league_oauth2_server:
    authorization_server:
        dynamic_client_registration:
            enabled: true
            initial_access_token: '%env(OAUTH_REGISTRATION_TOKEN)%'
```

Every request must then send `Authorization: Bearer <token>`. Others get `401` with `invalid_token`. Use a long random value and compare it with what you hand out to your clients.

### Rate limit

The bundle uses a rate limiter of the [Symfony RateLimiter component](https://symfony.com/doc/current/rate_limiter.html) (`composer require symfony/rate-limiter`), applied per client IP address:

```yaml
framework:
    rate_limiter:
        oauth2_registration:
            policy: sliding_window
            limit: 10
            interval: '1 hour'

league_oauth2_server:
    authorization_server:
        dynamic_client_registration:
            enabled: true
            rate_limiter: limiter.oauth2_registration
```

A request over the budget gets `429` with a `Retry-After` header. Every request counts, also those that are refused.

Behind a reverse proxy the client IP address is the one of the proxy unless you configure `framework.trusted_proxies`. Without it, all callers share one budget.

### Not covered

The bundle does not delete clients that were registered and never used. Plan a way to clean them up if the endpoint is open to the public.

## Other options

| Option              | Default                                    | Meaning                                                                    |
|---------------------|--------------------------------------------|----------------------------------------------------------------------------|
| `grant_types`       | `authorization_code`, `refresh_token`      | The grants a client may register for. They must be enabled grants.         |
| `scopes`            | all available scopes                       | The scopes a client may register for.                                      |
| `max_redirect_uris` | `10`                                       | How many redirect URIs one client may register.                            |
