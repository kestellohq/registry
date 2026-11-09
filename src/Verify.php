<?php

declare(strict_types=1);

namespace Kestello\Registry;

use Kestello\Cms\Package\Registry\Advisories;
use Kestello\Cms\Package\Registry\OrganisationFile;
use Kestello\Cms\Package\Registry\PackageFile;
use Kestello\Cms\Package\Registry\RegistryException;
use Kestello\Cms\Package\Registry\RegistryIndex;
use Kestello\Cms\Package\Registry\RegistryKeys;

/**
 * Reads a build back with Kestello's own reader, the code every site runs, before anything is
 * uploaded (registry-format.md §9.3): one set of rules, not a second implementation. Also checks
 * what a site would only notice later: that nothing the builder wrote was left out as unreadable,
 * and that every version is signed by a key certified for its organisation on its release date.
 *
 * @return list<string> problems; empty when sites will read the build exactly as written
 */
final class Verify
{
    /**
     * @param array<string, string> $files path => bytes (Builder::build())
     * @param array<string, string> $roots key id => raw public key
     * @return list<string>
     */
    public static function build(array $files, Inputs $in, array $roots, int $now): array
    {
        $problems = [];
        try {
            $keys = RegistryKeys::verify($files['keys.json'] ?? '', $roots, $now);
            $index = RegistryIndex::verify($files['index.json'] ?? '', $keys, $roots, $now);
        } catch (RegistryException $e) {
            return [$e->getMessage()];
        }

        $listed = array_keys(array_filter($in->ledger, static fn(array $v): bool => $v !== []));
        foreach (array_diff($listed, array_keys($index->packages)) as $slug) {
            $problems[] = "{$slug}: the index entry was written but sites would leave it out as unreadable.";
        }
        foreach (array_diff(array_keys($in->organisations), array_keys($index->organisations)) as $id) {
            $problems[] = "organisation {$id}: the index entry was written but sites would leave it out as unreadable.";
        }

        $organisations = [];
        foreach ($index->organisations as $id => $entry) {
            try {
                $organisations[$id] = OrganisationFile::parse(self::file($files, $entry['file']->path), $entry, $roots);
            } catch (RegistryException $e) {
                $problems[] = "organisation {$id}: {$e->getMessage()}";
            }
        }

        foreach ($index->packages as $slug => $entry) {
            try {
                $package = PackageFile::parse(self::file($files, $entry['file']->path), $entry);
            } catch (RegistryException $e) {
                $problems[] = "{$slug}: {$e->getMessage()}";
                continue;
            }
            $written = array_column($in->ledger[$slug] ?? [], 'version');
            foreach (array_diff($written, array_column($package['versions'], 'version')) as $version) {
                $problems[] = "{$slug} {$version}: written but sites would leave it out as unreadable.";
            }
            $org = $organisations[$entry['organisation']] ?? null;
            foreach ($package['versions'] as $v) {
                if ($org?->keyAt($v['key'], $v['released_at']) === null) {
                    $problems[] = "{$slug} {$v['version']}: key {$v['key']} was not certified for {$entry['organisation']} on its release date.";
                }
            }
        }

        foreach ($index->moves as $slug => $moves) {
            foreach ($moves as $move) {
                if (!isset($index->organisations[$move['to']])) {
                    $problems[] = "move of {$slug}: the organisation {$move['to']} is not in the registry.";
                }
            }
        }

        try {
            $advisories = Advisories::parse(self::file($files, $index->advisories->path), $index->advisories);
            foreach (array_diff(array_keys($in->advisories), array_column($advisories->all, 'id')) as $id) {
                $problems[] = "advisories/{$id}.json: sites would leave it out as unreadable. Check each field against registry-format.md §8.";
            }
        } catch (RegistryException $e) {
            $problems[] = "advisories: {$e->getMessage()}";
        }

        return $problems;
    }

    /** @param array<string, string> $files */
    private static function file(array $files, string $path): string
    {
        return $files[$path] ?? throw new RegistryException("{$path} is named by the index but was not written.");
    }
}
