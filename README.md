# Kestello registry

The list of plugins and themes that Kestello sites can install from **Plugins → Add new** and **Themes → Add new**.

This repository holds the inputs: organisations, packages, advisories and the rules they are checked against. A builder turns them into signed files published at `registry.kestello.com`. Sites only ever read those files; this repository is never contacted by a site.

The formats and rules are specified in the Kestello planning spec, `registry-format.md`.

Not open for submissions yet.

## License

GPL-2.0-or-later, like Kestello. Any code distributed for Kestello must be licensed under the GPL or a GPL-compatible license; see `rules/licenses.txt`.
