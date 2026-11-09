<?php

declare(strict_types=1);

namespace Kestello\Registry\Tests;

use Kestello\Cms\Package\PackageSignature;
use Kestello\Cms\Package\Registry\Envelope;
use Kestello\Framework\Http\Client\FakeTransport;
use Kestello\Framework\Http\Client\HttpClient;
use Kestello\Framework\Testing\TestCase;
use Kestello\Registry\Builder;
use Kestello\Registry\Inputs;
use Kestello\Registry\Intake;
use Kestello\Registry\Json;
use Kestello\Registry\Ledger;
use Kestello\Registry\Rules;
use Kestello\Registry\Verify;
use Kestello\Support\Zip\Zip;

/**
 * New versions from GitHub releases: real signed zips, served by a fake GitHub, accepted or
 * refused with Kestello's own checks, and then built into a registry Kestello reads.
 */
final class IntakeTest extends TestCase
{
    private const string API = 'https://api.github.com/repos/acme/events/releases';
    private const string DOWNLOADS = 'https://github.com/acme/events/releases/download';

    private string $dir;
    /** @var array{id: string, public_key: string, secret_key: string} */
    private array $root;
    /** @var array{id: string, public_key: string, secret_key: string} */
    private array $index;
    /** @var array{id: string, public_key: string, secret_key: string} */
    private array $acme;
    private int $now;
    /** @var list<array<string, mixed>> */
    private array $releases = [];
    private FakeTransport $github;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/kestello-intake-test-' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/rules', 0o755, true);
        foreach (['reserved.txt', 'licenses.txt', 'categories.json'] as $file) {
            copy(dirname(__DIR__) . "/rules/{$file}", "{$this->dir}/rules/{$file}");
        }
        $this->root = PackageSignature::generateKeys();
        $this->index = PackageSignature::generateKeys();
        $this->acme = PackageSignature::generateKeys();
        $this->now = (int) strtotime('2027-01-15T12:00:00Z');

        $this->put('keys/roots.json', [['name' => 'Test root', 'public_key' => $this->root['public_key']]]);
        $this->put('keys/keys.json', Envelope::seal(Json::encode([
            'kind' => 'keys', 'format' => 1, 'serial' => 1, 'issued_at' => self::at('-10 days'), 'expires_at' => self::at('+300 days'),
            'index_keys' => [['key' => $this->index['id'], 'public_key' => $this->index['public_key'], 'valid_from' => self::at('-30 days'), 'valid_until' => self::at('+330 days')]],
            'revoked' => [],
        ]), [$this->root['secret_key']], Envelope::KEY));
        $this->put('organisations/acme.json', ['name' => 'Acme', 'keys' => [Envelope::seal(Json::encode([
            'kind' => 'organisation', 'organisation' => 'acme', 'key' => $this->acme['id'], 'public_key' => $this->acme['public_key'],
            'valid_from' => self::at('-60 days'), 'valid_until' => self::at('+700 days'),
        ]), [$this->root['secret_key']], Envelope::KEY)]]);
        $this->put('packages/events.json', ['type' => 'plugin', 'organisation' => 'acme', 'source' => ['github' => 'acme/events'], 'categories' => ['content']]);

        $this->github = new FakeTransport();
        $this->github->on('GET ' . self::API, fn() => ['json' => $this->releases]);
    }

    protected function tearDown(): void
    {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($this->dir);
    }

    // ---- fixture helpers -------------------------------------------------------------------

    private static function at(string $when): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', (int) strtotime($when, (int) strtotime('2027-01-15T12:00:00Z')));
    }

    private function put(string $path, mixed $data): void
    {
        $file = "{$this->dir}/{$path}";
        if (!is_dir(dirname($file))) {
            mkdir(dirname($file), 0o755, true);
        }
        file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    /**
     * A plugin zip as a publisher builds it: everything in one "events/" folder, then signed.
     *
     * @param array<string, mixed> $manifest overrides
     * @param array<string, string|null> $files extra files, or null to leave one out
     */
    private function zip(string $version, array $manifest = [], array $files = [], ?string $signer = 'acme'): string
    {
        $path = "{$this->dir}/zips/events-{$version}-" . bin2hex(random_bytes(3)) . '.zip';
        if (!is_dir(dirname($path))) {
            mkdir(dirname($path), 0o755, true);
        }
        $contents = $files + [
            'plugin.json' => (string) json_encode($manifest + [
                'slug' => 'events', 'name' => 'Events', 'version' => $version, 'description' => 'Event listings with dates and places.',
                'license' => 'GPL-2.0-or-later', 'requires' => ['core' => '^0.1', 'php' => '>=8.4'],
                'author' => ['name' => 'Acme', 'url' => 'https://acme.example'],
                'permissions' => ['network' => ['api.acme.example']],
            ]),
            'LICENSE' => "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n",
            'README.md' => "# Events\n\nEvent listings for Kestello.\n",
            'src/Calendar.php' => "<?php\n\nnamespace Acme\\Events;\n\nfinal class Calendar\n{\n    public function days(): int\n    {\n        return 7;\n    }\n}\n",
        ];
        $w = Zip::create($path);
        foreach ($contents as $name => $body) {
            if ($body !== null) {
                $w->addString("events/{$name}", $body);
            }
        }
        $w->close();
        if ($signer !== null) {
            PackageSignature::sign($path, $signer === 'acme' ? $this->acme['secret_key'] : $signer);
        }

        return (string) file_get_contents($path);
    }

    /** Publish $zip as release v$version, with its .sha256 (or another checksum). */
    private function release(string $version, string $zip, string $published = '-1 day', ?string $sha = null): void
    {
        $tag = "v{$version}";
        $name = "events-{$version}.zip";
        $this->github->on('GET ' . self::DOWNLOADS . "/{$tag}/{$name}", static fn() => ['body' => $zip]);
        $this->github->on('GET ' . self::DOWNLOADS . "/{$tag}/{$name}.sha256", static fn() => ['body' => ($sha ?? hash('sha256', $zip)) . "  {$name}\n"]);
        $this->releases = array_values(array_filter($this->releases, static fn(array $r): bool => $r['tag_name'] !== $tag));
        $this->releases[] = [
            'draft' => false, 'prerelease' => false, 'tag_name' => $tag, 'name' => "Events {$version}", 'body' => "Notes for {$version}",
            'published_at' => self::at($published), 'html_url' => "https://github.com/acme/events/releases/tag/{$tag}",
            'assets' => [
                ['name' => $name, 'browser_download_url' => self::DOWNLOADS . "/{$tag}/{$name}"],
                ['name' => "{$name}.sha256", 'browser_download_url' => self::DOWNLOADS . "/{$tag}/{$name}.sha256"],
            ],
        ];
    }

    /** @return array<string, mixed> */
    private function intake(): array
    {
        $rules = Rules::load($this->dir);
        $http = new HttpClient($this->github, static fn(string $host): array => ['140.82.112.3']);

        return (new Intake($this->dir, Inputs::load($this->dir, $rules), $rules, $http, "{$this->dir}/dl", $this->now))->run();
    }

    private function refusedFor(string $version, string $expected): void
    {
        $report = $this->intake();
        $this->assertSame([], $report['accepted']);
        $this->assertSame($version, $report['refused'][0]['version'] ?? null, json_encode($report));
        $this->assertStringContainsString($expected, $report['refused'][0]['reason']);
        $this->assertSame($report['refused'][0]['reason'], Ledger::load($this->dir, 'events')['refused'][$version]['reason'] ?? null, 'recorded');
    }

    // ---- accepting -----------------------------------------------------------------------

    public function testAGoodVersionIsAcceptedRecordedCopiedAndBuilt(): void
    {
        $zip = $this->zip('1.5.0');
        $this->release('1.5.0', $zip);
        $report = $this->intake();

        $this->assertSame([], $report['errors']);
        $this->assertSame([], $report['refused']);
        $this->assertSame('1.5.0', $report['accepted'][0]['version']);
        $this->assertSame(['The first version from the organisation acme: a person reviews it.', 'Declares permissions that a person checks: network: "api.acme.example".'], $report['accepted'][0]['review']);

        $sha = hash('sha256', $zip);
        $this->assertSame($zip, file_get_contents("{$this->dir}/dl/events/1.5.0/{$sha}.zip"));
        $entry = Ledger::load($this->dir, 'events')['versions'][0];
        $this->assertSame([$sha, strlen($zip), $this->acme['id'], 'Event listings with dates and places.', 'GPL-2.0-or-later', 'https://acme.example'], [$entry['sha256'], $entry['size'], $entry['key'], $entry['summary'], $entry['license'], $entry['homepage']]);
        $this->assertSame("# Events\n\nEvent listings for Kestello.\n", $entry['description']);
        $this->assertSame(self::at('-1 day'), $entry['released_at']);

        // the ledger builds into a registry that Kestello's reader accepts
        $in = Inputs::load($this->dir, Rules::load($this->dir));
        $this->assertSame([], $in->problems);
        $files = Builder::build($in, $this->now, $this->index['secret_key']);
        $this->assertSame([], Verify::build($files, $in, [$this->root['id'] => (string) base64_decode($this->root['public_key'], true)], $this->now));
    }

    public function testRunningAgainChangesNothing(): void
    {
        $this->release('1.5.0', $this->zip('1.5.0'));
        $this->intake();
        $ledger = file_get_contents("{$this->dir}/ledger/events.json");
        $this->assertSame(['accepted' => [], 'refused' => [], 'changed' => [], 'errors' => []], $this->intake());
        $this->assertSame($ledger, file_get_contents("{$this->dir}/ledger/events.json"));
    }

    public function testOnlyTheOrganisationsFirstVersionAndNewPermissionsNeedAPerson(): void
    {
        $this->release('1.5.0', $this->zip('1.5.0'));
        $this->intake();
        $this->release('1.5.1', $this->zip('1.5.1'));
        $this->release('1.6.0', $this->zip('1.6.0', ['permissions' => ['network' => ['api.acme.example', 'tracker.example']]]));
        $accepted = $this->intake()['accepted'];
        $this->assertSame(['1.5.1', '1.6.0'], array_column($accepted, 'version'), 'oldest first');
        $this->assertSame([], $accepted[0]['review']);
        $this->assertSame(['Declares permissions it did not before that a person checks: network: "tracker.example".'], $accepted[1]['review']);
    }

    public function testAnAcceptedZipNeverChanges(): void
    {
        $zip = $this->zip('1.5.0');
        $this->release('1.5.0', $zip);
        $this->intake();
        $this->release('1.5.0', $this->zip('1.5.0', ['description' => 'Something else entirely.']));
        $report = $this->intake();
        $this->assertSame('1.5.0', $report['changed'][0]['version'] ?? null);
        $this->assertStringContainsString('A version means one zip', $report['changed'][0]['reason']);
        $this->assertSame(hash('sha256', $zip), Ledger::load($this->dir, 'events')['versions'][0]['sha256']);
    }

    // ---- refusing ------------------------------------------------------------------------

    public function testAnUnsignedZipIsRefusedOnceAndTriedAgainWhenItChanges(): void
    {
        $this->release('1.5.0', $this->zip('1.5.0', signer: null));
        $this->refusedFor('1.5.0', 'The zip is not signed');
        $this->assertSame(['accepted' => [], 'refused' => [], 'changed' => [], 'errors' => []], $this->intake(), 'not tried again');

        $this->release('1.5.0', $this->zip('1.5.0'));
        $report = $this->intake();
        $this->assertSame('1.5.0', $report['accepted'][0]['version'] ?? null, 'a new zip is tried');
        $this->assertSame([], Ledger::load($this->dir, 'events')['refused']);
    }

    public function testAKeyNotCertifiedForTheOrganisationOrNotOnTheReleaseDateIsRefused(): void
    {
        $this->release('1.5.0', $this->zip('1.5.0', signer: PackageSignature::generateKeys()['secret_key']));
        $this->refusedFor('1.5.0', 'which is not a current key of the organisation');

        $this->release('1.4.0', $this->zip('1.4.0'), '-90 days');          // before the certificate starts
        $this->refusedFor('1.4.0', 'which is not a current key of the organisation');
    }

    public function testTheZipMustMatchItsChecksumAndItsRelease(): void
    {
        $this->release('1.5.0', $this->zip('1.5.0'), sha: str_repeat('a', 64));
        $this->refusedFor('1.5.0', "doesn't match its .sha256 file");

        $this->release('1.6.0', $this->zip('1.5.9'));
        $this->refusedFor('1.6.0', 'plugin.json says events 1.5.9; the release is events 1.6.0');
    }

    public function testTheLicenseMustBeTheGplOrCompatibleAndShipped(): void
    {
        $this->release('1.5.0', $this->zip('1.5.0', ['license' => 'LicenseRef-Proprietary']));
        $this->refusedFor('1.5.0', 'is not the GPL or a GPL-compatible license');

        $this->release('1.6.0', $this->zip('1.6.0', [], ['LICENSE' => null]));
        $this->refusedFor('1.6.0', 'no license text');
    }

    public function testPluginCheckErrorsRefuseAVersion(): void
    {
        $this->release('1.5.0', $this->zip('1.5.0', [], ['src/Run.php' => "<?php\neval(\$_GET['x']);\n"]));
        $this->refusedFor('1.5.0', 'plugin:check: src/Run.php:2: eval() executes arbitrary code');
    }

    public function testTheSummaryIsTheManifestsOneLineDescription(): void
    {
        $this->release('1.5.0', $this->zip('1.5.0', ['description' => str_repeat('Long ', 40)]));
        $this->refusedFor('1.5.0', 'description is the summary shown in the registry');
    }

    public function testGitHubTroubleIsAnErrorNotARefusal(): void
    {
        $this->github->on('GET ' . self::API, static fn() => ['status' => 403, 'json' => ['message' => 'rate limited']]);
        $report = $this->intake();
        $this->assertSame(['events: GitHub is limiting requests for now; the next run tries again.'], $report['errors']);
        $this->assertFalse(is_file("{$this->dir}/ledger/events.json"));
    }
}
