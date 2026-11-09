# Kestello registry

The list of plugins and themes that Kestello sites can install from **Plugins → Add new** and **Themes → Add new**.

This repository holds the inputs: organisations, packages, advisories and the rules they are checked against. A builder turns them into signed files published at `registry.kestello.com`. Sites only ever read those files; this repository is never contacted by a site.

The formats and rules are specified in the Kestello planning spec, `registry-format.md`.

Not open for submissions yet.

## What is here

| Path | Edited by | Holds |
|---|---|---|
| `rules/` | People | Reserved names, accepted licenses, categories |
| `keys/roots.json` | The key ceremony | The root public keys Kestello ships |
| `keys/keys.json` | The key ceremony | Signed by a root key: the index keys and every revoked key |
| `organisations/<id>.json` | People | An organisation: name, verified domain, prefix, root-signed key certificates |
| `packages/<name>.json` | People | A package: type, organisation, GitHub source, categories; withdrawn versions; for paid packages, the store link |
| `advisories/<id>.json` | People | A security advisory |
| `moves/<name>.json` | The root key | A package moving to another organisation |
| `ledger/<name>.json` | The builder only | Every accepted version and what was checked. Never edited, never deleted |

## Commands

The builder uses Kestello's own code to check what it builds, from a checkout of `kestellohq/cms` at the commit in `cms.lock`:

```sh
git clone https://github.com/kestellohq/cms.git cms
git -C cms checkout "$(jq -r .commit cms.lock)"

php bin/registry check                  # check the inputs and a test build; needs no secrets
php bin/registry test                   # the builder's tests
php bin/registry build --out=build/v1   # the publishing job only: needs KESTELLO_REGISTRY_INDEX_KEY
```

`build` writes nothing unless Kestello's reader accepts the whole build exactly as written.

## License

GPL-2.0-or-later, like Kestello. Any code distributed for Kestello must be licensed under the GPL or a GPL-compatible license; see `rules/licenses.txt`.
