<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Command;

use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
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
     */
    public function __construct(
        private readonly DoctrineUnusedClientFinder $finder,
        private readonly ClientManagerInterface $clientManager,
        private readonly string $refreshTokenTtl,
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

        // A client with a refresh token that is still valid must stay: its tokens do not tell which client they belong to
        if ($since > $now->sub(new \DateInterval($this->refreshTokenTtl))) {
            $io->error(\sprintf('The "older-than" option must be at least as long as the lifetime of a refresh token (%s), or a client with a valid refresh token could be removed.', $this->refreshTokenTtl));

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

        foreach ($clients as $client) {
            $this->clientManager->remove($client);
        }

        $io->success(\sprintf('Removed %d unused client%s.', \count($clients), 1 === \count($clients) ? '' : 's'));

        return Command::SUCCESS;
    }
}
