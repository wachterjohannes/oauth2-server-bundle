<?php

declare(strict_types=1);

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

return static function (RoutingConfigurator $routes): void {
    $routes
        ->add('oauth2_client_registration', '/register')
        ->controller(['league.oauth2_server.controller.client_registration', 'indexAction'])
        ->methods(['POST'])
    ;
};
