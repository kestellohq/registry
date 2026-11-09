<?php

declare(strict_types=1);

namespace Kestello\Registry;

use Kestello\Framework\Support\Semver;

/**
 * ledger/<slug>.json: every accepted version and what was checked, and the versions refused (so
 * they aren't tried again until their zip changes). Written by the intake only; an accepted
 * version is never changed or removed (registry-format.md §9.2).
 *
 *   {"format": 1, "versions": [ … oldest first ], "refused": {"1.5.1": {"sha256", "reason", "at"}}}
 */
final class Ledger
{
    /** @return array{format: int, versions: list<array<string, mixed>>, refused: array<string, array{sha256: ?string, reason: string, at: string}>} */
    public static function load(string $root, string $slug): array
    {
        $file = "{$root}/ledger/{$slug}.json";
        $d = is_file($file) ? Json::read($file) : [];

        return [
            'format' => 1,
            'versions' => is_array($d['versions'] ?? null) ? array_values($d['versions']) : [],
            'refused' => is_array($d['refused'] ?? null) ? $d['refused'] : [],
        ];
    }

    /** @param array{format: int, versions: list<array<string, mixed>>, refused: array<string, mixed>} $ledger */
    public static function save(string $root, string $slug, array $ledger): void
    {
        usort($ledger['versions'], static fn(array $a, array $b): int => Semver::compare((string) $a['version'], (string) $b['version']));
        uksort($ledger['refused'], static fn(string $a, string $b): int => Semver::compare($a, $b));
        if (!is_dir("{$root}/ledger")) {
            mkdir("{$root}/ledger", 0o755, true);
        }
        $json = json_encode(
            ['format' => 1, 'versions' => $ledger['versions'], 'refused' => (object) $ledger['refused']],
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        );
        file_put_contents("{$root}/ledger/{$slug}.json", $json . "\n");
    }
}
