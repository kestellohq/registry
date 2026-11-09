<?php

declare(strict_types=1);

namespace Kestello\Registry;

use Kestello\Cms\Package\Registry\Envelope;
use Kestello\Framework\Support\Semver;
use RuntimeException;

/**
 * Turns checked inputs into the files published under v1/ (registry-format.md §2 to §8). Pure:
 * the same inputs, time and index key always give the same bytes.
 *
 *   $files = Builder::build($inputs, $now, $indexSecretKey);   path => bytes, index.json last
 *
 * The serial is the build time in seconds, so it only goes up and needs no stored state.
 */
final class Builder
{
    public const int INDEX_LIFETIME = 14 * 86_400;

    /** @return array<string, string> path => bytes; "keys.json" and "index.json" come last */
    public static function build(Inputs $in, int $now, string $indexSecretKey): array
    {
        if ($in->problems !== []) {
            throw new RuntimeException("The registry can't be built:\n- " . implode("\n- ", $in->problems));
        }
        if ($in->keysJson === null) {
            throw new RuntimeException('The registry can\'t be built without keys/keys.json.');
        }

        $files = [];
        $packages = [];
        foreach ($in->packages as $slug => $input) {
            $versions = $in->ledger[$slug] ?? [];
            if ($versions === []) {
                continue;   // nothing accepted yet: not listed
            }
            $file = self::packageFile($slug, $input, $versions);
            $path = "p/{$slug}/" . hash('sha256', $file) . '.json';
            $files[$path] = $file;
            $packages[] = self::indexEntry($slug, $input, $versions, $path, $file);
        }

        $organisations = [];
        foreach ($in->organisations as $id => $o) {
            $file = Json::encode(array_filter([
                'format' => 1, 'id' => $id, 'name' => $o['name'], 'verified' => $o['verified'],
                'prefix' => $o['prefix'], 'homepage' => $o['homepage'], 'keys' => $o['keys'],
            ], static fn(mixed $v): bool => $v !== null));
            $path = "o/{$id}/" . hash('sha256', $file) . '.json';
            $files[$path] = $file;
            $organisations[] = array_filter(['id' => $id, 'name' => $o['name'], 'verified' => $o['verified']['domain'] ?? null, 'file' => self::ref($path, $file)], static fn(mixed $v): bool => $v !== null);
        }

        $advisories = Json::encode(['format' => 1, 'advisories' => array_values($in->advisories)]);
        $advisoriesPath = 'advisories/' . hash('sha256', $advisories) . '.json';
        $files[$advisoriesPath] = $advisories;

        $index = Json::encode([
            'format' => 1,
            'serial' => $now,
            'issued_at' => self::time($now),
            'expires_at' => self::time($now + self::INDEX_LIFETIME),
            'packages' => $packages,
            'organisations' => $organisations,
            'advisories' => self::ref($advisoriesPath, $advisories),
            'moves' => $in->moves,
        ]);
        $files['keys.json'] = $in->keysJson;
        $files['index.json'] = Json::encode(Envelope::seal($index, [$indexSecretKey], Envelope::INDEX));

        return $files;
    }

    /**
     * @param array<string, mixed> $input packages/<slug>.json
     * @param list<array<string, mixed>> $versions the ledger
     */
    private static function packageFile(string $slug, array $input, array $versions): string
    {
        $paid = isset($input['commerce']);
        $current = self::current($versions, $input);
        $out = [];
        foreach (self::newestFirst($versions) as $v) {
            $requires = (array) $v['requires'];
            $out[] = array_filter([
                'version' => $v['version'],
                'released_at' => $v['released_at'],
                'requires' => array_filter(['core' => $requires['core'], 'php' => $requires['php'] ?? null, 'extensions' => $requires['extensions'] ?? null], static fn(mixed $x): bool => $x !== null),
                'dependencies' => (object) ($v['dependencies'] ?? []),
                'permissions' => (object) ($v['permissions'] ?? []),
                'notes' => $v['notes'] ?? '',
                // free versions are copied into the registry when accepted; paid ones come from the seller (§5.4)
                'download' => $paid ? null : "dl/{$slug}/{$v['version']}/{$v['sha256']}.zip",
                'sha256' => $v['sha256'],
                'size' => $v['size'],
                'key' => $v['key'],
                'withdrawn' => $input['withdrawn'][$v['version']] ?? null,
            ], static fn(mixed $x): bool => $x !== null);
        }

        $file = [
            'format' => 1,
            'slug' => $slug,
            'type' => $input['type'],
            'organisation' => $input['organisation'],
            'name' => $current['name'],
            'summary' => $current['summary'],
            'description' => $current['description'] ?? '',
            'license' => $current['license'],
        ];
        $optional = ['homepage' => $input['homepage'] ?? $current['homepage'] ?? null, 'support' => $input['support'] ?? null];
        foreach ($optional as $key => $value) {
            if ($value !== null) {
                $file[$key] = $value;
            }
        }

        return Json::encode($file + [
            'source' => 'https://github.com/' . $input['source']['github'],
            'categories' => $input['categories'],
            'commerce' => $input['commerce'] ?? null,
            'versions' => $out,
        ]);
    }

    /**
     * @param array<string, mixed> $input
     * @param list<array<string, mixed>> $versions
     * @return array<string, mixed>
     */
    private static function indexEntry(string $slug, array $input, array $versions, string $path, string $file): array
    {
        $current = self::current($versions, $input);
        $live = array_filter($versions, static fn(array $v): bool => !isset($input['withdrawn'][$v['version']]));
        $stable = null;
        $prerelease = null;
        foreach (self::newestFirst(array_values($live)) as $v) {
            if (str_contains((string) $v['version'], '-')) {
                $prerelease ??= $v['version'];
            } else {
                $stable ??= $v['version'];
            }
        }
        // a prerelease older than the newest stable is not worth offering
        if ($stable !== null && $prerelease !== null && Semver::compare($prerelease, $stable) < 0) {
            $prerelease = null;
        }

        return array_filter([
            'slug' => $slug,
            'type' => $input['type'],
            'name' => $current['name'],
            'summary' => $current['summary'],
            'organisation' => $input['organisation'],
            'categories' => $input['categories'],
            'latest' => array_filter(['stable' => $stable, 'prerelease' => $prerelease], static fn(mixed $x): bool => $x !== null),
            'requires_core' => $current['requires']['core'],
            'paid' => isset($input['commerce']),
            'updated_at' => max(array_map(static fn(array $v): string => self::time((int) strtotime((string) $v['released_at'])), $versions)),
            'file' => self::ref($path, $file),
        ], static fn(mixed $x): bool => $x !== null);
    }

    /**
     * The version whose name, summary and readme describe the package: the newest stable one
     * that isn't withdrawn, else the newest that isn't, else the newest.
     *
     * @param list<array<string, mixed>> $versions
     * @param array<string, mixed> $input
     * @return array<string, mixed>
     */
    private static function current(array $versions, array $input): array
    {
        $sorted = self::newestFirst($versions);
        $live = array_values(array_filter($sorted, static fn(array $v): bool => !isset($input['withdrawn'][$v['version']])));
        foreach ($live as $v) {
            if (!str_contains((string) $v['version'], '-')) {
                return $v;
            }
        }

        return $live[0] ?? $sorted[0];
    }

    /**
     * @param list<array<string, mixed>> $versions
     * @return list<array<string, mixed>>
     */
    private static function newestFirst(array $versions): array
    {
        usort($versions, static fn(array $a, array $b): int => Semver::compare((string) $b['version'], (string) $a['version']));

        return $versions;
    }

    /** @return array{path: string, sha256: string, size: int} */
    private static function ref(string $path, string $bytes): array
    {
        return ['path' => $path, 'sha256' => hash('sha256', $bytes), 'size' => strlen($bytes)];
    }

    public static function time(int $t): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $t);
    }
}
