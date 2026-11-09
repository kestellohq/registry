<?php

declare(strict_types=1);

namespace Kestello\Registry;

use Kestello\Cms\Extension\Manifest;
use Kestello\Cms\Extension\ManifestException;
use Kestello\Cms\Extension\PackageChecker;
use Kestello\Cms\Extension\PackageType;
use Kestello\Cms\Package\PackageSignature;
use Kestello\Cms\Package\Registry\OrganisationKey;
use Kestello\Support\Zip\Zip;
use Kestello\Support\Zip\ZipEntry;
use Throwable;

/**
 * Whether one downloaded version may join the registry (registry-format.md §9.1, checks 2 to 4),
 * judged with Kestello's own code: PackageSignature, Manifest and PackageChecker (plugin:check).
 *
 *   $facts = PackageCheck::run($zip, 'events', 'plugin', '1.5.0', $releasedAt, $certs, $revoked, $rules);
 *
 * Returns what the ledger records, or throws Refused with a reason the publisher can act on.
 * The test install on a fresh Kestello (check 5) is a separate step.
 */
final class PackageCheck
{
    public const int MAX_ZIP_BYTES = 128 << 20;
    private const int MAX_UNPACKED = 512 << 20;
    private const array LICENSE_FILES = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING', 'COPYING.md', 'COPYING.txt'];

    /**
     * @param list<OrganisationKey> $certs the organisation's root-certified keys
     * @param \Closure(string $keyId): bool $revoked
     * @return array{key: string, name: string, summary: string, description: string, license: string, homepage: ?string, requires: array<string, mixed>, dependencies: array<string, string>, permissions: array<mixed>, warnings: list<string>}
     * @throws Refused
     */
    public static function run(string $zipPath, string $slug, string $type, string $version, int $releasedAt, array $certs, \Closure $revoked, Rules $rules): array
    {
        $size = (int) @filesize($zipPath);
        if ($size < 1 || $size > self::MAX_ZIP_BYTES) {
            throw new Refused('The zip is empty or larger than 128 MB.');
        }
        try {
            $zip = Zip::open($zipPath);
        } catch (Throwable $e) {
            throw new Refused('The download is not a readable zip: ' . $e->getMessage());
        }

        // 2. signed by a key the root certified for the organisation on the release date
        $trusted = [];
        foreach ($certs as $cert) {
            if ($cert->validAt($releasedAt) && !$revoked($cert->id)) {
                $trusted[$cert->id] = ['name' => $cert->organisation, 'public_key' => base64_encode($cert->publicKey)];
            }
        }
        $signature = PackageSignature::verify($zip, $trusted);
        if ($signature['status'] !== PackageSignature::SIGNED || $signature['key'] === null) {
            throw new Refused(match ($signature['status']) {
                PackageSignature::UNSIGNED => 'The zip is not signed. Sign it with the organisation\'s key (php bin/cms package:sign).',
                PackageSignature::TAMPERED => 'The zip\'s signature doesn\'t match its files.',
                default => "The zip is signed by key {$signature['key']}, which is not a current key of the organisation.",
            });
        }

        // 3. the manifest, where the installer looks for it: at the root or in one folder
        $packageType = PackageType::from($type);
        $names = array_values(array_filter(array_map(static fn(ZipEntry $e): string => $e->name, $zip->entries()), static fn(string $n): bool => !str_ends_with($n, '/')));
        $prefix = self::prefix($names, $packageType);
        $work = sys_get_temp_dir() . '/kestello-intake-' . bin2hex(random_bytes(6));
        try {
            try {
                $zip->extractTo($work, self::MAX_UNPACKED, 200, static fn(ZipEntry $e): bool => $e->name !== PackageSignature::FILE && !$e->isSymlink);
            } catch (Throwable $e) {
                throw new Refused('The zip could not be unpacked: ' . $e->getMessage());
            }
            $dir = rtrim($work . '/' . $prefix, '/');
            try {
                $data = json_decode((string) file_get_contents($dir . '/' . $packageType->manifestFile()), true, 32, JSON_THROW_ON_ERROR);
                $manifest = Manifest::fromArray(is_array($data) ? $data : [], $packageType, $packageType->manifestFile());
            } catch (ManifestException | \JsonException $e) {
                throw new Refused("{$packageType->manifestFile()}: " . $e->getMessage());
            }
            if ($manifest->slug !== $slug || $manifest->version !== $version) {
                throw new Refused("{$packageType->manifestFile()} says {$manifest->slug} {$manifest->version}; the release is {$slug} {$version}.");
            }

            // the license (§1.5): declared, accepted, and its text shipped
            $license = $manifest->raw['license'] ?? null;
            if (!is_string($license) || !$rules->license($license)) {
                throw new Refused('The license "' . (is_string($license) ? $license : '') . '" is not the GPL or a GPL-compatible license. Any code distributed for Kestello must be.');
            }
            $licenseFile = array_filter(self::LICENSE_FILES, static fn(string $f): bool => is_file("{$dir}/{$f}"));
            if ($licenseFile === []) {
                throw new Refused('The zip has no license text (LICENSE, LICENSE.md or COPYING).');
            }

            $summary = trim($manifest->description);
            if ($summary === '' || mb_strlen($summary) > 160 || preg_match('/[\x00-\x1f\x7f]/', $summary) === 1) {
                throw new Refused("{$packageType->manifestFile()}: description is the summary shown in the registry: one line, 1 to 160 characters.");
            }
            if (mb_strlen($manifest->name) > 80) {
                throw new Refused("{$packageType->manifestFile()}: name is at most 80 characters.");
            }

            // 4. plugin:check
            $warnings = [];
            foreach ((new PackageChecker())->check($dir, $packageType) as $finding) {
                $line = "{$finding['file']}" . ($finding['line'] > 0 ? ":{$finding['line']}" : '') . ": {$finding['message']}";
                if ($finding['level'] === 'error') {
                    throw new Refused("plugin:check: {$line}");
                }
                $warnings[] = $line;
            }

            $homepage = is_array($manifest->raw['author'] ?? null) && is_string($manifest->raw['author']['url'] ?? null) && str_starts_with($manifest->raw['author']['url'], 'https://') ? $manifest->raw['author']['url'] : null;

            return [
                'key' => $signature['key'],
                'name' => $manifest->name,
                'summary' => $summary,
                'description' => self::readme($dir),
                'license' => $license,
                'homepage' => $homepage,
                'requires' => array_filter(['core' => $manifest->requiresCore, 'php' => $manifest->requiresPhp, 'extensions' => $manifest->extensions ?: null], static fn(mixed $v): bool => $v !== null),
                'dependencies' => $manifest->dependencies,
                'permissions' => $manifest->permissions,
                'warnings' => $warnings,
            ];
        } finally {
            self::remove($work);
        }
    }

    /**
     * Where the manifest is: at the zip's root, or inside its one top folder (as PackageInstaller
     * looks). To move into Kestello as a public helper, so both use one copy.
     *
     * @param list<string> $names
     * @throws Refused
     */
    private static function prefix(array $names, PackageType $type): string
    {
        if (in_array($type->manifestFile(), $names, true)) {
            return '';
        }
        $tops = array_unique(array_map(static fn(string $n): string => explode('/', $n, 2)[0], array_filter($names, static fn(string $n): bool => $n !== PackageSignature::FILE)));
        if (count($tops) === 1 && in_array(reset($tops) . '/' . $type->manifestFile(), $names, true)) {
            return reset($tops) . '/';
        }

        throw new Refused("There is no {$type->manifestFile()} in the zip, at its root or in its one folder.");
    }

    /** README.md, as the package's description: at most 20,000 characters, cut at a paragraph. */
    private static function readme(string $dir): string
    {
        $text = is_file("{$dir}/README.md") ? (string) file_get_contents("{$dir}/README.md", false, null, 0, 200_000) : '';
        if (!mb_check_encoding($text, 'UTF-8')) {
            return '';
        }
        $text = str_replace("\r\n", "\n", preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', '', $text) ?? '');
        if (mb_strlen($text) <= 20_000) {
            return $text;
        }
        $cut = mb_substr($text, 0, 19_990);
        $paragraph = mb_strrpos($cut, "\n\n");

        return rtrim($paragraph !== false && $paragraph > 10_000 ? mb_substr($cut, 0, $paragraph) : $cut) . "\n\n…";
    }

    private static function remove(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() && !$f->isLink() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($dir);
    }
}
