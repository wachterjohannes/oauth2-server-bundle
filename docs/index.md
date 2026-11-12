## Important notes

This bundle provides the "glue" between  [thephpleague/oauth2-server](https://github.com/thephpleague/oauth2-server) library and the Symfony framework.
It implements [thephpleague/oauth2-server](https://github.com/thephpleague/oauth2-server) library in a way specified by its official documentation.
For implementation into Symfony projects, please see [bundle documentation](basic-setup.md) and official [Symfony Security documentation](https://symfony.com/doc/current/security.html).

## Features

* API endpoint for client authorization, device code and token issuing
* Configurable client and token persistance (includes [Doctrine](https://www.doctrine-project.org/) support)
* Integration with Symfony's [Security](https://symfony.com/doc/current/security.html) layer

## Requirements

* [PHP 8.2](http://php.net/releases/8_2_0.php) or greater
* [Symfony 7.4](https://symfony.com/roadmap/7.4) or greater

## Installation

1. Require the bundle with Composer:

    ```sh
    composer require league/oauth2-server-bundle
    ```

    If your project is managed using [Symfony Flex](https://github.com/symfony/flex), the rest of the steps are not required. Just follow the post-installation instructions instead! :tada:

1. Create the bundle configuration file under `config/packages/league_oauth2_server.yaml`. Here is a reference configuration file:

    ```yaml
    league_oauth2_server:
        authorization_server: # Required

            # Full path to the private key file.
            # How to generate a private key: https://oauth2.thephpleague.com/installation/#generating-public-and-private-keys
            private_key:          ~ # Required, Example: /var/oauth/private.key

            # Passphrase of the private key, if any
            private_key_passphrase: null

            # The plain string or the ascii safe string used to create a Defuse\Crypto\Key to be used as an encryption key.
            # How to generate an encryption key: https://oauth2.thephpleague.com/installation/#string-password
            encryption_key:       ~ # Required

            # The type of value of 'encryption_key'
            encryption_key_type:  plain # One of "plain"; "defuse"

            # How long the issued access token should be valid for.
            # The value should be a valid interval: http://php.net/manual/en/dateinterval.construct.php#refsect1-dateinterval.construct-parameters
            access_token_ttl:     PT1H

            # How long the issued refresh token should be valid for.
            # The value should be a valid interval: http://php.net/manual/en/dateinterval.construct.php#refsect1-dateinterval.construct-parameters
            refresh_token_ttl:    P1M

            # How long the issued auth code should be valid for.
            # The value should be a valid interval: http://php.net/manual/en/dateinterval.construct.php#refsect1-dateinterval.construct-parameters
            auth_code_ttl:        PT10M

            # Whether to enable the client credentials grant
            enable_client_credentials_grant: true

            # Whether to enable the password grant
            enable_password_grant: false

            # Whether to enable the refresh token grant
            enable_refresh_token_grant: true

            # Whether to enable the authorization code grant
            enable_auth_code_grant: true

            # Whether to require code challenge for public clients for the auth code grant
            require_code_challenge_for_public_clients: true

            # Whether to enable the implicit grant
            enable_implicit_grant: false

            # Whether to enable access token saving to persistence layer (default to true)
            persist_access_token: true

            # Whether to revoke refresh tokens after they were used for all grant types (default to true)
            revoke_refresh_tokens: true

            # Whether to enable the device code grant
            enable_device_code_grant: false

            # The full URI the user will need to visit to enter the user code
            device_code_verification_uri: ''

            # Whether to enable the generation of verification_uri_complete
            enable_device_code_verification_uri_complete_generation: true

            # How soon (in seconds) can the device code be used to poll for the access token without being throttled
            device_code_polling_interval: 5

            # Whether to enable the visibility of polling interval
            enable_device_code_polling_interval_visibility: true

            # Serves the authorization server metadata document (RFC 8414).
            # The route is opt-in as well: import "@LeagueOAuth2ServerBundle/config/routes_metadata.php".
            metadata:
                enabled:              false

                # The issuer identifier: an https URL without query or fragment. Required when the metadata are enabled.
                # It must be a literal: the route path is built from it when the container is compiled, so a parameter or an environment variable cannot be used.
                issuer:               null # Example: https://auth.example.com

            # Lets clients register themselves (RFC 7591).
            # The route is opt-in as well: import "@LeagueOAuth2ServerBundle/config/routes_registration.php".
            dynamic_client_registration:
                enabled:              false

                # A bearer token every registration request must carry. Without it, anyone who can reach the endpoint can register a client.
                initial_access_token: null

                # Service id of a Symfony rate limiter factory (symfony/rate-limiter), applied per client IP address.
                rate_limiter:         null

                # The grants a client may register for. They must be enabled grants.
                grant_types:
                    - authorization_code
                    - refresh_token

                # The scopes a client may register for. All available scopes when empty.
                scopes:               []

                # How many redirect URIs one client may register
                max_redirect_uris:    10

        resource_server:      # Required

            # Full path to the public key file
            # How to generate a public key: https://oauth2.thephpleague.com/installation/#generating-public-and-private-keys
            public_key:           ~ # Required, Example: /var/oauth/public.key

            # The leeway in seconds to allow for clock skew in JWT verification. Default PT0S (no leeway).
            jwt_leeway: null

        scopes:
            # Scopes that you wish to utilize in your application.
            # This should be a simple array of strings.
            available:               []

            # Scopes that will be assigned when no scope given.
            # This should be a simple array of strings.
            default:                 []

        # Configures different persistence methods that can be used by the bundle for saving client and token data.
        # Only one persistence method can be configured at a time.
        persistence:          # Required
            doctrine:

                # Name of the entity manager that you wish to use for managing clients and tokens.
                entity_manager:       default

                # Table name prefix.
                table_prefix:         oauth2_
            in_memory:            ~

        # Set a custom prefix that replaces the default 'ROLE_OAUTH2_' role prefix
        role_prefix:          ROLE_OAUTH2_

        client:
            # Set a custom client class. Must be a League\Bundle\OAuth2ServerBundle\Model\Client
            classname:        League\Bundle\OAuth2ServerBundle\Model\Client
    ```

1. Enable the bundle in `config/bundles.php` by adding it to the array:

    ```php
    League\Bundle\OAuth2ServerBundle\LeagueOAuth2ServerBundle::class => ['all' => true]
    ```

1. Update the database so bundle entities can be persisted using Doctrine:

    ```sh
    bin/console doctrine:schema:update --force
    ```

1. Import the routes inside your `config/routes.yaml` file:

    ```yaml
    oauth2:
        resource: '@LeagueOAuth2ServerBundle/config/routes.php'
        type: php
    ```

## Post-installation

You can verify that everything is working by issuing a `POST` request to the `/token` endpoint.

It is required to control access to the authorization endpoint
so that only logged-in users can approve authorization requests.

You should review your `config/security.yaml` file. Here is a sample configuration:

```yaml
security:
    access_control:
        - { path: ^/authorize, roles: IS_AUTHENTICATED_REMEMBERED }
```

> [!IMPORTANT]
> The requirement for a logged-in user to approve authorization requests was introduced in version `0.9.0`. In previous versions, it was only a recommendation.

## Configuration

* [Basic setup](basic-setup.md)
* [Token scopes](token-scopes.md)
* [Implementing custom grant type](implementing-custom-grant-type.md)
* [Using custom client](using-custom-client.md)
* [Listening to League OAuth Server events](listening-to-league-events.md)
* [Password Grant Handling](password-grant-handling.md)
* [Using custom persistence managers](using-custom-persistence-managers.md)
* [Authorization server metadata](authorization-server-metadata.md)
* [Dynamic client registration](dynamic-client-registration.md)

## Contributing

Please see [CONTRIBUTING](/CONTRIBUTING.md) for details.

## Versioning

This project adheres to [Semantic Versioning 2.0.0](https://semver.org/). Randomly breaking public APIs is not an option.

## Reporting issues

Use the [issue tracker](https://github.com/thephpleague/oauth2-server-bundle/issues) to report any issues you might have.

## License

See the [LICENSE](/LICENSE) file for license rights and limitations (MIT).
