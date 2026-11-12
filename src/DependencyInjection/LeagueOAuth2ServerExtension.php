<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\DependencyInjection;

use Doctrine\Bundle\DoctrineBundle\DoctrineBundle;
use League\Bundle\OAuth2ServerBundle\Command\ClearExpiredTokensCommand;
use League\Bundle\OAuth2ServerBundle\Command\ClearUnusedClientsCommand;
use League\Bundle\OAuth2ServerBundle\Command\CreateClientCommand;
use League\Bundle\OAuth2ServerBundle\Command\GenerateKeyPairCommand;
use League\Bundle\OAuth2ServerBundle\Controller\AuthorizationServerMetadataController;
use League\Bundle\OAuth2ServerBundle\Controller\ClientRegistrationController;
use League\Bundle\OAuth2ServerBundle\DBAL\Type\Grant as GrantType;
use League\Bundle\OAuth2ServerBundle\DBAL\Type\RedirectUri as RedirectUriType;
use League\Bundle\OAuth2ServerBundle\DBAL\Type\Scope as ScopeType;
use League\Bundle\OAuth2ServerBundle\EventListener\RecordClientUsageListener;
use League\Bundle\OAuth2ServerBundle\Manager\AccessTokenManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\AuthorizationCodeManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\DeviceCodeManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\Doctrine\AccessTokenManager;
use League\Bundle\OAuth2ServerBundle\Manager\Doctrine\AuthorizationCodeManager;
use League\Bundle\OAuth2ServerBundle\Manager\Doctrine\ClientManager;
use League\Bundle\OAuth2ServerBundle\Manager\Doctrine\DeviceCodeManager;
use League\Bundle\OAuth2ServerBundle\Manager\Doctrine\RefreshTokenManager;
use League\Bundle\OAuth2ServerBundle\Manager\InMemory\AccessTokenManager as InMemoryAccessTokenManager;
use League\Bundle\OAuth2ServerBundle\Manager\RefreshTokenManagerInterface;
use League\Bundle\OAuth2ServerBundle\Manager\ScopeManagerInterface;
use League\Bundle\OAuth2ServerBundle\OAuth2Grants;
use League\Bundle\OAuth2ServerBundle\Persistence\Mapping\Driver;
use League\Bundle\OAuth2ServerBundle\Registration\ClientRegistrar;
use League\Bundle\OAuth2ServerBundle\Security\Authenticator\OAuth2Authenticator;
use League\Bundle\OAuth2ServerBundle\Service\CredentialsRevoker\DoctrineCredentialsRevoker;
use League\Bundle\OAuth2ServerBundle\Service\CredentialsRevokerInterface;
use League\Bundle\OAuth2ServerBundle\Service\UnusedClientFinder\DoctrineUnusedClientFinder;
use League\Bundle\OAuth2ServerBundle\ValueObject\Scope as ScopeModel;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Grant\DeviceCodeGrant;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResourceServer;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;

final class LeagueOAuth2ServerExtension extends Extension implements PrependExtensionInterface, CompilerPassInterface
{
    private const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

    /**
     * @throws \Exception
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../config'));
        $loader->load('services.php');

        $config = $this->processConfiguration(new Configuration(), $configs);

        $this->configureAccessTokenSaving($loader, $config['authorization_server']);
        $this->configurePersistence($loader, $container, $config);
        $this->configureAuthorizationServer($container, $config['authorization_server']);
        $this->configureMetadata($container, $config['authorization_server'], $config['scopes']['available']);
        $this->configureClientRegistration($container, $config['authorization_server'], $config['scopes'], $config['client']['classname']);
        $this->configureResourceServer($container, $config['resource_server']);
        $this->configureScopes($container, $config['scopes']);

        $container->findDefinition(OAuth2Authenticator::class)
            ->setArgument(3, $config['role_prefix']);

        $container
            ->findDefinition(CreateClientCommand::class)
            ->replaceArgument(1, $config['client']['classname'])
        ;

        $container
            ->findDefinition(GenerateKeyPairCommand::class)
            ->replaceArgument(1, $config['authorization_server']['private_key'])
            ->replaceArgument(2, $config['resource_server']['public_key'])
            ->replaceArgument(3, $config['authorization_server']['private_key_passphrase'])
        ;

        $container
            ->findDefinition(ClearExpiredTokensCommand::class)
            ->replaceArgument(4, $config['authorization_server']['enable_device_code_grant'])
        ;
    }

    public function getAlias(): string
    {
        return 'league_oauth2_server';
    }

    public function prepend(ContainerBuilder $container): void
    {
        // If no doctrine connection is configured, the DBAL connection should
        // be left alone as adding any configuration setting with no connection
        // will result in an invalid configuration leading to a hard failure.
        if (!self::hasDoctrineConnectionsConfigured($container->getExtensionConfig('doctrine'))) {
            return;
        }

        $container->prependExtensionConfig('doctrine', [
            'dbal' => [
                'connections' => null,
                'types' => [
                    'oauth2_grant' => GrantType::class,
                    'oauth2_redirect_uri' => RedirectUriType::class,
                    'oauth2_scope' => ScopeType::class,
                ],
            ],
        ]);
    }

    public function process(ContainerBuilder $container): void
    {
        $this->assertRequiredBundlesAreEnabled($container);

        // The metadata endpoint is opt-in: an application without a router must still compile
        if (!$container->has('router')) {
            $container->removeAlias(AuthorizationServerMetadataController::class);
            $container->removeDefinition('league.oauth2_server.controller.authorization_server_metadata');
            $container->removeAlias(ClientRegistrationController::class);
            $container->removeDefinition('league.oauth2_server.controller.client_registration');
        }
    }

    /**
     * @param mixed[] $configs
     */
    private static function hasDoctrineConnectionsConfigured(array $configs): bool
    {
        foreach ($configs as $config) {
            if (isset($config['dbal'])) {
                return true;
            }
        }

        return false;
    }

    private function assertRequiredBundlesAreEnabled(ContainerBuilder $container): void
    {
        $requiredBundles = [
            'security' => SecurityBundle::class,
        ];

        if ($container->hasParameter('league.oauth2_server.persistence.doctrine.enabled')) {
            $requiredBundles['doctrine'] = DoctrineBundle::class;
        }

        foreach ($requiredBundles as $bundleAlias => $requiredBundle) {
            if (!$container->hasExtension($bundleAlias)) {
                throw new \LogicException(\sprintf('Bundle \'%s\' needs to be enabled in your application kernel.', $requiredBundle));
            }
        }
    }

    /**
     * @param mixed[] $config
     * @param string[] $availableScopes
     */
    private function configureMetadata(ContainerBuilder $container, array $config, array $availableScopes): void
    {
        $issuer = $config['metadata']['enabled'] ? $config['metadata']['issuer'] : null;

        // The configuration validated the issuer
        $parts = null === $issuer ? [] : (array) parse_url($issuer);

        // RFC 8414 section 3.1: the well-known segment goes between the host and the path of the issuer
        $container->setParameter('league.oauth2_server.metadata.path', rtrim($parts['path'] ?? '', '/'));

        $grants = array_keys(array_filter([
            OAuth2Grants::AUTHORIZATION_CODE => $config['enable_auth_code_grant'],
            OAuth2Grants::CLIENT_CREDENTIALS => $config['enable_client_credentials_grant'],
            OAuth2Grants::IMPLICIT => $config['enable_implicit_grant'],
            OAuth2Grants::PASSWORD => $config['enable_password_grant'],
            OAuth2Grants::REFRESH_TOKEN => $config['enable_refresh_token_grant'],
            self::DEVICE_CODE_GRANT => $config['enable_device_code_grant'],
        ]));

        $authorizationEndpoint = $config['enable_auth_code_grant'] || $config['enable_implicit_grant'];
        $tokenEndpoint = [] !== array_diff($grants, [OAuth2Grants::IMPLICIT]);

        $metadata = [
            'response_types_supported' => array_values(array_filter([
                $config['enable_auth_code_grant'] ? 'code' : null,
                $config['enable_implicit_grant'] ? 'token' : null,
            ])),
            'grant_types_supported' => $grants,
            'scopes_supported' => $availableScopes,
        ];

        if ($tokenEndpoint) {
            $metadata['token_endpoint_auth_methods_supported'] = ['client_secret_basic', 'client_secret_post'];

            // The client credentials grant refuses public clients, every other grant at the token endpoint accepts them
            if ([] !== array_diff($grants, [OAuth2Grants::IMPLICIT, OAuth2Grants::CLIENT_CREDENTIALS])) {
                $metadata['token_endpoint_auth_methods_supported'][] = 'none';
            }
        }

        if ($config['enable_auth_code_grant']) {
            $metadata['code_challenge_methods_supported'] = ['S256'];
        }

        $endpoints = array_filter([
            'authorization_endpoint' => $authorizationEndpoint ? 'oauth2_authorize' : null,
            'token_endpoint' => $tokenEndpoint ? 'oauth2_token' : null,
            'device_authorization_endpoint' => $config['enable_device_code_grant'] ? 'oauth2_device_code' : null,
            'registration_endpoint' => $config['dynamic_client_registration']['enabled'] ? 'oauth2_client_registration' : null,
        ]);

        $container->findDefinition(AuthorizationServerMetadataController::class)
            ->replaceArgument(2, $issuer)
            ->replaceArgument(3, null === $issuer ? '' : \sprintf('%s://%s%s', strtolower($parts['scheme'] ?? ''), strtolower($parts['host'] ?? ''), isset($parts['port']) ? ':' . $parts['port'] : ''))
            ->replaceArgument(4, $metadata)
            ->replaceArgument(5, $endpoints)
        ;
    }

    /**
     * @param mixed[] $config
     * @param mixed[] $scopes
     * @param class-string $clientClass
     */
    private function configureClientRegistration(ContainerBuilder $container, array $config, array $scopes, string $clientClass): void
    {
        $registration = $config['dynamic_client_registration'];

        $enabledGrants = array_keys(array_filter([
            OAuth2Grants::AUTHORIZATION_CODE => $config['enable_auth_code_grant'],
            OAuth2Grants::CLIENT_CREDENTIALS => $config['enable_client_credentials_grant'],
            OAuth2Grants::REFRESH_TOKEN => $config['enable_refresh_token_grant'],
            self::DEVICE_CODE_GRANT => $config['enable_device_code_grant'],
        ]));

        $allowedScopes = [] === $registration['scopes'] ? $scopes['available'] : $registration['scopes'];

        if ($registration['enabled']) {
            if ([] !== $disabledGrants = array_diff($registration['grant_types'], $enabledGrants)) {
                throw new \LogicException(\sprintf('Invalid grant types "%s" for path "league_oauth2_server.authorization_server.dynamic_client_registration.grant_types". The grants are not enabled. Permissible values: "%s"', implode('", "', $disabledGrants), implode('", "', $enabledGrants)));
            }

            if ([] !== $unknownScopes = array_diff($allowedScopes, $scopes['available'])) {
                throw new \LogicException(\sprintf('Invalid scopes "%s" for path "league_oauth2_server.authorization_server.dynamic_client_registration.scopes". Permissible values: "%s"', implode('", "', $unknownScopes), implode('", "', $scopes['available'])));
            }
        }

        // Nothing tracks or removes clients that cannot register themselves
        if (!$registration['enabled']) {
            $container->removeDefinition(RecordClientUsageListener::class);
            $container->removeAlias(ClearUnusedClientsCommand::class);
            $container->removeDefinition('league.oauth2_server.command.clear_unused_clients');
            $container->removeDefinition(DoctrineUnusedClientFinder::class);
        }

        $defaultScopes = array_values(array_intersect($scopes['default'], $allowedScopes));

        $container->findDefinition(ClientRegistrar::class)
            ->replaceArgument(3, $clientClass)
            ->replaceArgument(4, array_values($registration['grant_types']))
            ->replaceArgument(5, array_values($allowedScopes))
            ->replaceArgument(6, [] === $defaultScopes ? array_values($allowedScopes) : $defaultScopes)
            ->replaceArgument(7, $registration['max_redirect_uris'])
        ;

        $container->findDefinition(ClientRegistrationController::class)
            ->replaceArgument(1, $registration['enabled'])
            ->replaceArgument(2, $registration['enabled'] ? $registration['initial_access_token'] : null)
            ->replaceArgument(3, $registration['enabled'] && null !== $registration['rate_limiter'] ? new Reference($registration['rate_limiter']) : null)
        ;
    }

    /**
     * @param mixed[] $config
     */
    private function configureAuthorizationServer(ContainerBuilder $container, array $config): void
    {
        $container->setParameter('league.oauth2_server.encryption_key', $config['encryption_key']);
        $container->setParameter('league.oauth2_server.encryption_key.type', $config['encryption_key_type']);
        $container->setParameter('league.oauth2_server.access_token_ttl.default', $config['access_token_ttl']);

        $authorizationServer = $container
            ->findDefinition(AuthorizationServer::class)
            ->replaceArgument(3, new Definition(CryptKey::class, [
                $config['private_key'],
                $config['private_key_passphrase'],
                false,
            ]));

        if ($config['response_type_class']) {
            $authorizationServer->replaceArgument(5, new Reference($config['response_type_class']));
        }

        $authorizationServer->addMethodCall('revokeRefreshTokens', [
            $config['revoke_refresh_tokens'],
        ]);

        if ($config['enable_client_credentials_grant']) {
            $authorizationServer->addMethodCall('enableGrantType', [
                new Reference(ClientCredentialsGrant::class),
                new Definition(\DateInterval::class, [$config['access_token_ttl']]),
            ]);
        }

        if ($config['enable_password_grant']) {
            $authorizationServer->addMethodCall('enableGrantType', [
                new Reference(PasswordGrant::class),
                new Definition(\DateInterval::class, [$config['access_token_ttl']]),
            ]);
        }

        if ($config['enable_refresh_token_grant']) {
            $authorizationServer->addMethodCall('enableGrantType', [
                new Reference(RefreshTokenGrant::class),
                new Definition(\DateInterval::class, [$config['access_token_ttl']]),
            ]);
        }

        if ($config['enable_auth_code_grant']) {
            $authorizationServer->addMethodCall('enableGrantType', [
                new Reference(AuthCodeGrant::class),
                new Definition(\DateInterval::class, [$config['access_token_ttl']]),
            ]);
        }

        if ($config['enable_device_code_grant']) {
            $authorizationServer->addMethodCall('enableGrantType', [
                new Reference(DeviceCodeGrant::class),
                new Definition(\DateInterval::class, [$config['access_token_ttl']]),
            ]);
        }

        if ($config['enable_implicit_grant']) {
            $authorizationServer->addMethodCall('enableGrantType', [
                new Reference(ImplicitGrant::class),
                new Definition(\DateInterval::class, [$config['access_token_ttl']]),
            ]);
        }

        $this->configureGrants($container, $config);
    }

    /**
     * @param mixed[] $config
     */
    private function configureGrants(ContainerBuilder $container, array $config): void
    {
        $container->setParameter('league.oauth2_server.refresh_token_ttl.default', $config['refresh_token_ttl']);

        $container
            ->findDefinition(PasswordGrant::class)
            ->addMethodCall('setRefreshTokenTTL', [
                new Definition(\DateInterval::class, [$config['refresh_token_ttl']]),
            ])
        ;

        $container
            ->findDefinition(RefreshTokenGrant::class)
            ->addMethodCall('setRefreshTokenTTL', [
                new Definition(\DateInterval::class, [$config['refresh_token_ttl']]),
            ])
        ;

        $authCodeGrantDefinition = $container->findDefinition(AuthCodeGrant::class);
        $authCodeGrantDefinition->replaceArgument(2, new Definition(\DateInterval::class, [$config['auth_code_ttl']]))
            ->addMethodCall('setRefreshTokenTTL', [
                new Definition(\DateInterval::class, [$config['refresh_token_ttl']]),
            ])
        ;

        $deviceCodeGrantDefinition = $container->findDefinition(DeviceCodeGrant::class);
        $deviceCodeGrantDefinition
            ->replaceArgument(2, new Definition(\DateInterval::class, [$config['device_code_ttl']]))
            ->replaceArgument(3, $config['device_code_verification_uri'])
            ->replaceArgument(4, $config['device_code_polling_interval'])
            ->addMethodCall('setIncludeVerificationUriComplete', [$config['enable_device_code_verification_uri_complete_generation']])
            ->addMethodCall('setIntervalVisibility', [$config['enable_device_code_polling_interval_visibility']])
            ->addMethodCall('setRefreshTokenTTL', [
                new Definition(\DateInterval::class, [$config['refresh_token_ttl']]),
            ])
        ;

        if (false === $config['require_code_challenge_for_public_clients']) {
            $authCodeGrantDefinition->addMethodCall('disableRequireCodeChallengeForPublicClients');
        }

        $container
            ->findDefinition(ImplicitGrant::class)
            ->replaceArgument(0, new Definition(\DateInterval::class, [$config['access_token_ttl']]))
        ;
    }

    /**
     * @param mixed[] $config
     */
    private function configureAccessTokenSaving(LoaderInterface $loader, array $config): void
    {
        if ($config['persist_access_token']) {
            $loader->load('access_token/default.php');
        } else {
            $loader->load('access_token/null.php');
        }
    }

    /**
     * @param mixed[] $config
     *
     * @throws \Exception
     */
    private function configurePersistence(LoaderInterface $loader, ContainerBuilder $container, array $config): void
    {
        if (\count($config['persistence']) > 1) {
            throw new \LogicException('Only one persistence method can be configured at a time.');
        }

        $persistenceConfig = current($config['persistence']);
        $persistenceMethod = $this->getPersistenceMethod($config);

        switch ($persistenceMethod) {
            case 'in_memory':
                $loader->load('storage/in_memory.php');
                $this->configureInMemoryPersistence($container, $config);
                break;
            case 'doctrine':
                $loader->load('storage/doctrine.php');
                $this->configureDoctrinePersistence($container, $config, $persistenceConfig);
                break;
            case 'custom':
                $this->configureCustomPersistence($container, $persistenceConfig);
                break;
        }
    }

    /**
     * @param mixed[] $config
     */
    private function getPersistenceMethod(array $config): ?string
    {
        $persistenceMethod = key($config['persistence']);

        return \is_string($persistenceMethod) ? $persistenceMethod : null;
    }

    /**
     * @param mixed[] $config
     * @param mixed[] $persistenceConfig
     */
    private function configureDoctrinePersistence(ContainerBuilder $container, array $config, array $persistenceConfig): void
    {
        $entityManagerName = $persistenceConfig['entity_manager'];

        $entityManager = new Reference(
            \sprintf('doctrine.orm.%s_entity_manager', $entityManagerName)
        );

        $container
            ->findDefinition(AccessTokenManager::class)
            ->replaceArgument(0, $entityManager)
            ->replaceArgument(1, $config['authorization_server']['persist_access_token'])
        ;

        $container
            ->findDefinition(ClientManager::class)
            ->replaceArgument(0, $entityManager)
            ->replaceArgument(2, $config['client']['classname'])
        ;

        $container
            ->findDefinition(RefreshTokenManager::class)
            ->replaceArgument(0, $entityManager)
        ;

        $container
            ->findDefinition(AuthorizationCodeManager::class)
            ->replaceArgument(0, $entityManager)
        ;

        $container
            ->findDefinition(DeviceCodeManager::class)
            ->replaceArgument(0, $entityManager)
        ;

        $container
            ->findDefinition(DoctrineCredentialsRevoker::class)
            ->replaceArgument(0, $entityManager)
            ->replaceArgument(2, $config['authorization_server']['persist_access_token'])
            ->replaceArgument(3, $config['authorization_server']['enable_device_code_grant'])
        ;

        $container
            ->findDefinition(Driver::class)
            ->replaceArgument(0, $config['client']['classname'])
            ->replaceArgument(1, $config['authorization_server']['persist_access_token'])
            ->replaceArgument(2, $persistenceConfig['table_prefix'])
            ->replaceArgument(3, $config['authorization_server']['enable_device_code_grant'])
            ->replaceArgument(4, $config['authorization_server']['dynamic_client_registration']['enabled'])
        ;

        $container
            ->findDefinition(DoctrineUnusedClientFinder::class)
            ->replaceArgument(0, $entityManager)
            ->replaceArgument(1, $config['client']['classname'])
        ;

        $container
            ->findDefinition(ClearUnusedClientsCommand::class)
            ->replaceArgument(1, $config['authorization_server']['refresh_token_ttl'])
            ->replaceArgument(2, $config['authorization_server']['access_token_ttl'])
        ;

        $container
            ->findDefinition(RecordClientUsageListener::class)
            ->replaceArgument(0, $entityManager)
            ->replaceArgument(1, $config['client']['classname'])
        ;

        $container->setParameter('league.oauth2_server.persistence.doctrine.enabled', true);
        $container->setParameter('league.oauth2_server.persistence.doctrine.manager', $entityManagerName);
    }

    /**
     * @param mixed[] $config
     */
    private function configureInMemoryPersistence(ContainerBuilder $container, array $config): void
    {
        $container
            ->findDefinition(InMemoryAccessTokenManager::class)
            ->replaceArgument(0, $config['authorization_server']['persist_access_token'])
        ;
        $container->setParameter('league.oauth2_server.persistence.in_memory.enabled', true);
    }

    /**
     * @param mixed[] $persistenceConfig
     */
    private function configureCustomPersistence(ContainerBuilder $container, array $persistenceConfig): void
    {
        $container->setAlias(ClientManagerInterface::class, $persistenceConfig['client_manager']);
        $container->setAlias(AccessTokenManagerInterface::class, $persistenceConfig['access_token_manager']);
        $container->setAlias(RefreshTokenManagerInterface::class, $persistenceConfig['refresh_token_manager']);
        $container->setAlias(DeviceCodeManagerInterface::class, $persistenceConfig['device_code_manager']);
        $container->setAlias(AuthorizationCodeManagerInterface::class, $persistenceConfig['authorization_code_manager']);
        $container->setAlias(CredentialsRevokerInterface::class, $persistenceConfig['credentials_revoker']);

        $container->setParameter('league.oauth2_server.persistence.custom.enabled', true);
    }

    /**
     * @param mixed[] $config
     */
    private function configureResourceServer(ContainerBuilder $container, array $config): void
    {
        $container
            ->findDefinition(ResourceServer::class)
            ->replaceArgument(1, new Definition(CryptKey::class, [
                $config['public_key'],
                null,
                false,
            ]))
        ;
        if (null !== $config['jwt_leeway']) {
            $container
                ->findDefinition(BearerTokenValidator::class)
                ->replaceArgument(1, new Definition(\DateInterval::class, [$config['jwt_leeway']]));
        }
    }

    /**
     * @param mixed[] $scopes
     */
    private function configureScopes(ContainerBuilder $container, array $scopes): void
    {
        $availableScopes = $scopes['available'];
        $defaultScopes = $scopes['default'];

        if ([] !== $invalidDefaultScopes = array_diff($defaultScopes, $availableScopes)) {
            throw new \LogicException(\sprintf('Invalid default scopes "%s" for path "league_oauth2_server.scopes.default". Permissible values: "%s"', implode('", "', $invalidDefaultScopes), implode('", "', $availableScopes)));
        }

        $container->setParameter('league.oauth2_server.scopes.default', $defaultScopes);

        $scopeManager = $container->findDefinition(ScopeManagerInterface::class);
        foreach ($availableScopes as $scope) {
            $scopeManager->addMethodCall('save', [
                new Definition(ScopeModel::class, [$scope]),
            ]);
        }
    }
}
