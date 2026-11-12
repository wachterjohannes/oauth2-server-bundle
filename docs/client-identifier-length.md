# Longer client identifiers

The identifiers the bundle generates are 32 characters long, and so is the column of the default client class. An application that gives its clients other identifiers, for example UUIDs with a prefix or URLs, can make the column longer:

```yaml
league_oauth2_server:
    client:
        identifier_length: 255
```

The value is between `32` (the default) and `255`. The identifier is the primary key of the client table and the clients are referenced by the token tables, so the limit keeps the key within the index size of MySQL.

Changing the option changes the schema. Generate and run a migration:

```console
php bin/console doctrine:migrations:diff
php bin/console doctrine:migrations:migrate
```

Nothing changes for an application that does not set the option.

The option applies to the default client class. A [custom client class](using-custom-client.md) declares its identifier column itself, so change `length` there.
