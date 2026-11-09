<?php

declare(strict_types=1);

namespace Kestello\Registry;

use Kestello\Cms\Package\Registry\Fields;
use Kestello\Cms\Package\Registry\RegistryKeys;
use Kestello\Cms\Package\Update\ReleaseFeed;
use Kestello\Framework\Http\Client\HttpClient;
use Kestello\Framework\Support\Semver;
use Throwable;

/**
 * Finds new versions on each package's GitHub releases and accepts or refuses them
 * (registry-format.md §9.1 and §9.2), with the same release rules as Kestello's own GitHub
 * updates (ReleaseFeed): a release tagged v<version> carrying <slug>-<version>.zip and its
 * .sha256.
 *
 * For each new version: the checksum file, the zip, its hash, then PackageCheck. An accepted zip
 * is copied to <dl>/<slug>/<version>/<sha256>.zip, to be uploaded before the ledger change is
 * merged; a refused one is recorded so it isn't tried again until its zip changes. A version
 * already accepted whose zip has since changed is reported, and the accepted copy stays.
 *
 * Accepted versions that need a person: an organisation's first, and any that declares new
 * permissions.
 */
final class Intake
{
    private const string API = 'https://api.github.com';
    private const int MAX_NOTES = 20_000;

    /** @var array<string, bool> organisations with an accepted version, this run included */
    private array $published = [];

    public function __construct(
        private readonly string $root,
        private readonly Inputs $in,
        private readonly Rules $rules,
        private readonly HttpClient $http,
        private readonly string $dl,
        private readonly int $now,
        private readonly ?string $githubToken = null,
    ) {}

    /**
     * @return array{
     *   accepted: list<array{slug: string, version: string, review: list<string>}>,
     *   refused: list<array{slug: string, version: string, reason: string}>,
     *   changed: list<array{slug: string, version: string, reason: string}>,
     *   errors: list<string>
     * }
     */
    public function run(?string $only = null): array
    {
        $report = ['accepted' => [], 'refused' => [], 'changed' => [], 'errors' => []];
        if ($this->in->problems !== []) {
            $report['errors'][] = 'The inputs have problems; run check first.';

            return $report;
        }
        foreach ($this->in->ledger as $slug => $versions) {
            if ($versions !== []) {
                $this->published[(string) $this->in->packages[$slug]['organisation']] = true;
            }
        }
        $revoked = $this->revoked();

        foreach ($this->in->packages as $slug => $package) {
            if ($only !== null && $slug !== $only) {
                continue;
            }
            $repo = (string) $package['source']['github'];
            try {
                $releases = array_reverse($this->releases($repo, $slug));     // oldest first
            } catch (Throwable $e) {
                $report['errors'][] = "{$slug}: {$e->getMessage()}";
                continue;
            }

            $ledger = Ledger::load($this->root, $slug);
            $accepted = array_column($ledger['versions'], 'sha256', 'version');
            $changed = false;
            foreach ($releases as $release) {
                $version = $release['version'];
                try {
                    $sha = $this->checksum($release['sha256']);
                } catch (Throwable $e) {
                    $report['errors'][] = "{$slug} {$version}: {$e->getMessage()}";
                    continue;
                }
                if (isset($accepted[$version])) {
                    if ($sha !== $accepted[$version]) {
                        $report['changed'][] = ['slug' => $slug, 'version' => $version, 'reason' => "The release now offers a zip with SHA-256 {$sha}; the registry keeps the one it accepted ({$accepted[$version]}). A version means one zip: publish a new version instead."];
                    }
                    continue;
                }
                if (($ledger['refused'][$version]['sha256'] ?? false) === $sha) {
                    continue;     // refused before, and the zip hasn't changed
                }

                try {
                    $entry = $this->accept($slug, $package, $release, $sha, $revoked, $ledger['versions']);
                } catch (Refused $e) {
                    $ledger['refused'][$version] = ['sha256' => $sha, 'reason' => $e->getMessage(), 'at' => Builder::time($this->now)];
                    $report['refused'][] = ['slug' => $slug, 'version' => $version, 'reason' => $e->getMessage()];
                    $changed = true;
                    continue;
                } catch (Throwable $e) {
                    $report['errors'][] = "{$slug} {$version}: {$e->getMessage()}";
                    continue;
                }
                $review = $entry['review'];
                unset($entry['review']);
                $ledger['versions'][] = $entry;
                unset($ledger['refused'][$version]);
                $accepted[$version] = $sha;
                $this->published[(string) $package['organisation']] = true;
                $report['accepted'][] = ['slug' => $slug, 'version' => $version, 'review' => $review];
                $changed = true;
            }
            if ($changed) {
                Ledger::save($this->root, $slug, $ledger);
            }
        }

        return $report;
    }

    /**
     * @param array<string, mixed> $package
     * @param array{version: string, notes: string, published_at: string, zip: string} $release
     * @param \Closure(string): bool $revoked
     * @param list<array<string, mixed>> $earlier accepted versions of this package
     * @return array<string, mixed> the ledger entry, with "review"
     * @throws Refused
     */
    private function accept(string $slug, array $package, array $release, string $sha, \Closure $revoked, array $earlier): array
    {
        $version = $release['version'];
        $released = Fields::time($release['published_at']) ?? $this->now;
        $tmp = tempnam(sys_get_temp_dir(), 'kestello-intake-') ?: throw new \RuntimeException('No temporary file.');
        try {
            $sink = fopen($tmp, 'wb') ?: throw new \RuntimeException("Can't write {$tmp}.");
            try {
                $response = $this->http->get($release['zip'], ['timeout' => 300, 'max_redirects' => 5, 'sink' => $sink, 'headers' => ['User-Agent' => 'kestello-registry']]);
            } finally {
                fclose($sink);
            }
            if ($response->status !== 200) {
                throw new \RuntimeException("GitHub answered HTTP {$response->status} for the zip.");
            }
            if (filesize($tmp) > PackageCheck::MAX_ZIP_BYTES) {
                throw new Refused('The zip is larger than 128 MB.');
            }
            if (!hash_equals($sha, (string) hash_file('sha256', $tmp))) {
                throw new Refused('The zip doesn\'t match its .sha256 file.');
            }

            $org = (string) $package['organisation'];
            $facts = PackageCheck::run($tmp, $slug, (string) $package['type'], $version, $released, $this->in->organisations[$org]['certs'], $revoked, $this->rules);

            $review = [];
            if (!isset($this->published[$org])) {
                $review[] = "The first version from the organisation {$org}: a person reviews it.";
            }
            $previous = self::previous($earlier, $version);
            $new = array_diff(self::flatten($facts['permissions']), self::flatten($previous['permissions'] ?? []));
            if ($new !== []) {
                $review[] = 'Declares permissions ' . ($previous === null ? '' : 'it did not before ') . 'that a person checks: ' . implode('; ', $new) . '.';
            }

            $target = "{$this->dl}/{$slug}/{$version}/{$sha}.zip";
            if (!is_dir(dirname($target)) && !mkdir(dirname($target), 0o755, true) && !is_dir(dirname($target))) {
                throw new \RuntimeException("Can't create " . dirname($target) . '.');
            }
            copy($tmp, $target);

            $notes = $release['notes'];
            if (mb_strlen($notes) > self::MAX_NOTES) {
                $notes = mb_substr($notes, 0, self::MAX_NOTES - 2) . "\n…";
            }

            return array_filter([
                'version' => $version,
                'released_at' => Builder::time($released),
                'sha256' => $sha,
                'size' => (int) filesize($tmp),
                'key' => $facts['key'],
                'name' => $facts['name'],
                'summary' => $facts['summary'],
                'description' => $facts['description'],
                'license' => $facts['license'],
                'homepage' => $facts['homepage'],
                'requires' => $facts['requires'],
                'dependencies' => (object) $facts['dependencies'],
                'permissions' => (object) $facts['permissions'],
                'notes' => $notes,
                'accepted_at' => Builder::time($this->now),
                'checks' => [
                    'sha256' => 'matches the release',
                    'signature' => "key {$facts['key']}, certified for {$org}",
                    'manifest' => 'valid',
                    'license' => $facts['license'],
                    'plugin_check' => $facts['warnings'] === [] ? 'passed' : ['passed with warnings' => $facts['warnings']],
                    'install' => 'not run yet',
                ],
            ], static fn(mixed $v): bool => $v !== null) + ['review' => $review];
        } finally {
            @unlink($tmp);
        }
    }

    /** @return list<array{version: string, notes: string, published_at: string, prerelease: bool, zip: string, sha256: string, page: string, name: string}> */
    private function releases(string $repo, string $slug): array
    {
        $headers = ['Accept' => 'application/vnd.github+json', 'X-GitHub-Api-Version' => '2022-11-28', 'User-Agent' => 'kestello-registry'];
        $options = ['query' => ['per_page' => 30], 'timeout' => 30, 'max_redirects' => 2, 'headers' => $headers];
        if ($this->githubToken !== null && $this->githubToken !== '') {
            $options['bearer'] = $this->githubToken;
        }
        $response = $this->http->get(self::API . "/repos/{$repo}/releases", $options);
        if ($response->status === 403 || $response->status === 429) {
            throw new \RuntimeException('GitHub is limiting requests for now; the next run tries again.');
        }
        if ($response->status !== 200) {
            throw new \RuntimeException("GitHub answered HTTP {$response->status} for the releases of {$repo}.");
        }

        return ReleaseFeed::parse(json_decode($response->body, true), $repo, $slug);
    }

    private function checksum(string $url): string
    {
        $response = $this->http->get($url, ['timeout' => 30, 'max_redirects' => 5, 'max_bytes' => 1024, 'headers' => ['User-Agent' => 'kestello-registry']]);
        $sha = $response->status === 200 ? ReleaseFeed::checksum($response->body) : null;

        return $sha ?? throw new \RuntimeException("The .sha256 file can't be read (HTTP {$response->status}).");
    }

    /** @return \Closure(string): bool */
    private function revoked(): \Closure
    {
        if ($this->in->keysJson === null) {
            return static fn(string $id): bool => false;
        }
        $keys = RegistryKeys::verify($this->in->keysJson, $this->in->roots, $this->now);

        return static fn(string $id): bool => $keys->revoked($id) !== null;
    }

    /**
     * The newest accepted version below $version, whose permissions a new one is compared with.
     *
     * @param list<array<string, mixed>> $earlier
     * @return array<string, mixed>|null
     */
    private static function previous(array $earlier, string $version): ?array
    {
        $best = null;
        foreach ($earlier as $v) {
            if (Semver::compare((string) $v['version'], $version) < 0
                && ($best === null || Semver::compare((string) $v['version'], (string) $best['version']) > 0)) {
                $best = $v;
            }
        }

        return $best;
    }

    /**
     * Permissions as "path: value" lines, so two versions can be compared line by line.
     *
     * @return list<string>
     */
    private static function flatten(mixed $value, string $path = ''): array
    {
        if (is_object($value)) {
            $value = (array) $value;
        }
        if (!is_array($value)) {
            return [$path . ': ' . json_encode($value, JSON_UNESCAPED_SLASHES)];
        }
        $out = [];
        foreach ($value as $k => $v) {
            $out = [...$out, ...self::flatten($v, is_int($k) ? $path : ($path === '' ? (string) $k : "{$path}.{$k}"))];
        }

        return $out;
    }
}
