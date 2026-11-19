<?php

declare(strict_types=1);

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

use League\Bundle\OAuth2ServerBundle\Controller\ClientRegistrationController;
use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Registration\ClientRegistrar;
use League\Bundle\OAuth2ServerBundle\Registration\RedirectUriPolicy;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $container): void {
    $container->services()
        // Its arguments are set by the extension
        ->set(RedirectUriPolicy::class)

        ->set(ClientRegistrar::class)
            ->args([
                service(ClientManagerInterface::class),
                service('league.oauth2_server.password_hasher'),
                service(RedirectUriPolicy::class),
                null,
                [],
                [],
                [],
                10,
            ])

        ->set('league.oauth2_server.controller.client_registration', ClientRegistrationController::class)
            ->args([
                service(ClientRegistrar::class),
                null,
                null,
            ])
            ->tag('controller.service_arguments')
        ->alias(ClientRegistrationController::class, 'league.oauth2_server.controller.client_registration')
    ;
};
