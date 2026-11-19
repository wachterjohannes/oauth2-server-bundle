<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

return static function (ContainerConfigurator $container): void {
    $container->extension('framework', [
        'secret' => 'nope',
        'test' => true,
        'http_method_override' => false,
        'handle_all_throwables' => true,
        'php_errors' => [
            'log' => true,
        ],
        // An array cache, so the budget does not outlive the test
        'cache' => [
            'pools' => [
                'registration_limiter_cache' => ['adapter' => 'cache.adapter.array'],
            ],
        ],
        'rate_limiter' => [
            'registration' => [
                'policy' => 'fixed_window',
                'limit' => 3,
                'interval' => '1 hour',
                'cache_pool' => 'registration_limiter_cache',
            ],
        ],
    ]);
};
