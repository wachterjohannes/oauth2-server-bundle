<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Command;

use League\Bundle\OAuth2ServerBundle\EventListener\RecordClientUsageListener;
use League\Bundle\OAuth2ServerBundle\Model\AbstractClient;
use League\Bundle\OAuth2ServerBundle\Service\UnusedClientFinder\DoctrineUnusedClientFinder;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'league:oauth2-server:clear-unused-clients', description: 'Removes the clients that registered themselves and were not used for a while')]
final class ClearUnusedClientsCommand extends Command
{
    /**
     * @param string $refreshTokenTtl the lifetime of a refresh token, as a date interval specification
     * @param string $accessTokenTtl the lifetime of an access token, as a date interval specification
     */
    public function __construct(
        private readonly DoctrineUnusedClientFinder $finder,
        private readonly string $refreshTokenTtl,
        private readonly string $accessTokenTtl,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'older-than',
                null,
                InputOption::VALUE_REQUIRED,
                'How long a client must not have been used, as a date interval specification (for example P60D).',
                'P60D'
            )
            ->addOption(
                'dry-run',
                null,
                InputOption::VALUE_NONE,
                'List the clients without removing them.'
            )
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        try {
            $period = new \DateInterval((string) $input->getOption('older-than'));
        } catch (\Exception) {
            $io->error('The "older-than" option must be a date interval specification such as "P60D".');

            return Command::FAILURE;
        }

        $now = new \DateTimeImmutable();
        $since = $now->sub($period);

        // A refresh token does not tell its client once the access token is cleared, and using an access token records nothing.
        // A token can also be issued up to one recording interval after the last recorded use.
        $latestToken = min($now->sub(new \DateInterval($this->refreshTokenTtl)), $now->sub(new \DateInterval($this->accessTokenTtl)));
        if ($since > $latestToken->modify('-' . RecordClientUsageListener::RESOLUTION . ' seconds')) {
            $io->error(\sprintf('The "older-than" option must be longer than the lifetime of the longest token (%s or %s) plus one day, or a client with a valid token could be removed.', $this->refreshTokenTtl, $this->accessTokenTtl));

            return Command::FAILURE;
        }

        $clients = $this->finder->find($since);

        if ($input->getOption('dry-run')) {
            $io->table(
                ['Identifier', 'Name', 'Registered', 'Last used'],
                array_map(static fn (AbstractClient $client): array => [
                    $client->getIdentifier(),
                    $client->getName(),
                    $client->getRegisteredAt()?->format(\DATE_ATOM),
                    $client->getLastUsedAt()?->format(\DATE_ATOM) ?? '-',
                ], $clients),
            );
            $io->note(\sprintf('%d client%s would be removed.', \count($clients), 1 === \count($clients) ? '' : 's'));

            return Command::SUCCESS;
        }

        $removed = $this->finder->remove($since);

        $io->success(\sprintf('Removed %d unused client%s.', $removed, 1 === $removed ? '' : 's'));

        return Command::SUCCESS;
    }
}
