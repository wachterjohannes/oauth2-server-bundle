<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Unit;

use Doctrine\ORM\Mapping\ClassMetadata;
use League\Bundle\OAuth2ServerBundle\Model\AbstractClient;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use League\Bundle\OAuth2ServerBundle\Model\DeviceCode;
use League\Bundle\OAuth2ServerBundle\Persistence\Mapping\Driver;
use PHPUnit\Framework\TestCase;

final class DriverTest extends TestCase
{
    public function testDeviceCodeIsMappedWhenDeviceCodeGrantIsEnabled(): void
    {
        $driver = new Driver(Client::class, true, 'oauth2_', true);

        $this->assertContains(DeviceCode::class, $driver->getAllClassNames());
    }

    public function testDeviceCodeIsNotMappedWhenDeviceCodeGrantIsDisabled(): void
    {
        $driver = new Driver(Client::class, true, 'oauth2_', false);

        $this->assertNotContains(DeviceCode::class, $driver->getAllClassNames());
    }

    public function testRegistrationColumnsAreMappedOnlyWhenTrackingIsOn(): void
    {
        foreach ([true, false] as $tracking) {
            $metadata = new ClassMetadata(AbstractClient::class);
            (new Driver(Client::class, true, 'oauth2_', false, $tracking))->loadMetadataForClass(AbstractClient::class, $metadata);

            $this->assertSame($tracking, $metadata->hasField('registeredAt'));
            $this->assertSame($tracking, $metadata->hasField('lastUsedAt'));
        }
    }
}
