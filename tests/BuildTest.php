<?php

declare(strict_types=1);

namespace Kestello\Registry\Tests;

use Kestello\Cms\Package\PackageSignature;
use Kestello\Cms\Package\Registry\Envelope;
use Kestello\Cms\Package\Registry\PackageFile;
use Kestello\Cms\Package\Registry\RegistryIndex;
use Kestello\Cms\Package\Registry\RegistryKeys;
use Kestello\Framework\Testing\TestCase;
use Kestello\Registry\Builder;
use Kestello\Registry\Cli;
use Kestello\Registry\Inputs;
use Kestello\Registry\Json;
use Kestello\Registry\LicenseExpression;
use Kestello\Registry\Output;
use Kestello\Registry\Rules;
use Kestello\Registry\Verify;

/**
 * The builder end to end: a throwaway repository with generated keys goes through Inputs, Builder
 * and Verify, and comes out as files Kestello's own reader accepts.
 */
final class BuildTest extends TestCase
{
    private string $dir;
    /** @var array{id: string, public_key: string, secret_key: string} */
    private array $root;
    /** @var array{id: string, public_key: string, secret_key: string} */
    private array $index;
    /** @var array{id: string, public_key: string, secret_key: string} */
    private array $acme;
    private int $now;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/kestello-registry-' . bin2hex(random_bytes(6));
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
            'kind' => 'keys', 'format' => 1, 'serial' => 1,
            'issued_at' => self::at('-10 days'), 'expires_at' => self::at('+300 days'),
            'index_keys' => [['key' => $this->index['id'], 'public_key' => $this->index['public_key'], 'valid_from' => self::at('-30 days'), 'valid_until' => self::at('+330 days')]],
            'revoked' => [],
        ]), [$this->root['secret_key']], Envelope::KEY));
        $this->put('organisations/acme.json', ['name' => 'Acme', 'homepage' => 'https://acme.example', 'verified' => ['domain' => 'acme.example', 'at' => self::at('-90 days')], 'prefix' => 'acme-', 'keys' => [$this->cert('acme')]]);
        $this->put('packages/events.json', ['type' => 'plugin', 'organisation' => 'acme', 'source' => ['github' => 'acme/events'], 'categories' => ['content']]);
        $this->put('ledger/events.json', ['format' => 1, 'versions' => [$this->version('1.4.0', '-40 days'), $this->version('1.5.0', '-10 days'), $this->version('1.6.0-rc.1', '-2 days')]]);
        $this->put('advisories/KSA-2027-0001.json', ['id' => 'KSA-2027-0001', 'type' => 'plugin', 'package' => 'events', 'affected' => '<1.5.0', 'fixed' => '1.5.0', 'severity' => 'high', 'title' => 'Stored XSS in event titles', 'url' => 'https://kestello.com/security/KSA-2027-0001', 'published_at' => self::at('-9 days')]);
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

    /** @return array<mixed> */
    private function get(string $path): array
    {
        return Json::read("{$this->dir}/{$path}");
    }

    /** @param array<string, mixed> $over */
    private function cert(string $org, array $over = [], ?string $signer = null, ?array $key = null): array
    {
        $key ??= $this->acme;

        return Envelope::seal(Json::encode($over + [
            'kind' => 'organisation', 'organisation' => $org, 'key' => $key['id'], 'public_key' => $key['public_key'],
            'valid_from' => self::at('-60 days'), 'valid_until' => self::at('+700 days'),
        ]), [$signer ?? $this->root['secret_key']], Envelope::KEY);
    }

    /** @param array<string, mixed> $over */
    private function version(string $version, string $released, array $over = []): array
    {
        return $over + [
            'version' => $version, 'released_at' => self::at($released),
            'sha256' => hash('sha256', $version), 'size' => 4000, 'key' => $this->acme['id'],
            'name' => 'Events', 'summary' => "Event listings ({$version}).", 'description' => "# Events\n\nListings.",
            'license' => 'GPL-2.0-or-later', 'requires' => ['core' => '^0.1', 'php' => '>=8.4'],
            'dependencies' => [], 'permissions' => ['network' => ['api.acme.example']], 'notes' => "Notes for {$version}",
            'accepted_at' => self::at($released), 'checks' => ['plugin:check' => 'passed'],
        ];
    }

    private function inputs(): Inputs
    {
        return Inputs::load($this->dir, Rules::load($this->dir));
    }

    /** @return array<string, string> */
    private function roots(): array
    {
        return [$this->root['id'] => (string) base64_decode($this->root['public_key'], true)];
    }

    /** @return array<string, string> */
    private function build(?Inputs $in = null): array
    {
        $in ??= $this->inputs();
        $this->assertSame([], $in->problems);
        $files = Builder::build($in, $this->now, $this->index['secret_key']);
        $this->assertSame([], Verify::build($files, $in, $this->roots(), $this->now));

        return $files;
    }

    private function hasProblem(string $expected, Inputs $in): void
    {
        foreach ($in->problems as $problem) {
            if (str_contains($problem, $expected)) {
                $this->assertTrue(true);

                return;
            }
        }
        $this->fail("Expected a problem containing \"{$expected}\"; got: " . json_encode($in->problems));
    }

    // ---- building ----------------------------------------------------------------------

    public function testABuildIsReadByKestellosOwnReader(): void
    {
        $files = $this->build();
        $index = RegistryIndex::verify($files['index.json'], RegistryKeys::verify($files['keys.json'], $this->roots(), $this->now), $this->roots(), $this->now);
        $this->assertSame($this->now, $index->serial);
        $this->assertSame('1.5.0', $index->packages['events']['stable']);
        $this->assertSame('1.6.0-rc.1', $index->packages['events']['prerelease']);
        $this->assertSame('Event listings (1.5.0).', $index->packages['events']['summary'], 'described by the newest stable version');

        $package = PackageFile::parse($files[$index->packages['events']['file']->path], $index->packages['events']);
        $this->assertSame(['1.6.0-rc.1', '1.5.0', '1.4.0'], array_column($package['versions'], 'version'));
        $this->assertSame('dl/events/1.5.0/' . hash('sha256', '1.5.0') . '.zip', $package['versions'][1]['download']);
        $this->assertSame('https://github.com/acme/events', $package['source']);
        $this->assertSame(['index.json', 'keys.json'], array_slice(array_reverse(array_keys($files)), 0, 2), 'the index is written last');
    }

    public function testTheSameInputsGiveTheSameBytes(): void
    {
        $a = Builder::build($this->inputs(), $this->now, $this->index['secret_key']);
        $b = Builder::build($this->inputs(), $this->now, $this->index['secret_key']);
        $this->assertSame($a, $b);
    }

    public function testAWithdrawnVersionStaysListedButIsNeverLatest(): void
    {
        $this->put('packages/events.json', ['withdrawn' => ['1.5.0' => ['at' => self::at('-1 day'), 'reason' => 'Breaks forms']]] + $this->get('packages/events.json'));
        $files = $this->build();
        $index = RegistryIndex::verify($files['index.json'], RegistryKeys::verify($files['keys.json'], $this->roots(), $this->now), $this->roots(), $this->now);
        $this->assertSame('1.4.0', $index->packages['events']['stable']);
        $versions = PackageFile::parse($files[$index->packages['events']['file']->path], $index->packages['events'])['versions'];
        $this->assertSame('Breaks forms', $versions[1]['withdrawn']['reason'] ?? null);
    }

    public function testAPaidPackageHasAStoreLinkAndNoRegistryCopy(): void
    {
        $this->put('packages/events.json', ['commerce' => ['model' => 'yearly-per-site', 'price' => 'From 49 EUR a year', 'store_url' => 'https://acme.example/buy', 'license' => 'seller']] + $this->get('packages/events.json'));
        $files = $this->build();
        $index = RegistryIndex::verify($files['index.json'], RegistryKeys::verify($files['keys.json'], $this->roots(), $this->now), $this->roots(), $this->now);
        $this->assertTrue($index->packages['events']['paid']);
        $package = PackageFile::parse($files[$index->packages['events']['file']->path], $index->packages['events']);
        $this->assertSame([null, null, null], array_column($package['versions'], 'download'));
    }

    public function testAPackageWithNothingAcceptedIsNotListed(): void
    {
        unlink("{$this->dir}/ledger/events.json");
        $in = $this->inputs();
        $files = Builder::build($in, $this->now, $this->index['secret_key']);
        $index = RegistryIndex::verify($files['index.json'], RegistryKeys::verify($files['keys.json'], $this->roots(), $this->now), $this->roots(), $this->now);
        $this->assertSame([], $index->packages);
        $this->assertSame(['acme'], array_keys($index->organisations));
    }

    public function testOutputWritesEveryFile(): void
    {
        $files = $this->build();
        Output::write("{$this->dir}/build/v1", $files);
        foreach ($files as $path => $bytes) {
            $this->assertSame($bytes, file_get_contents("{$this->dir}/build/v1/{$path}"), $path);
        }
        $this->assertSame([], glob("{$this->dir}/build/v1/*.tmp") ?: []);
    }

    public function testCheckNeedsNoSecrets(): void
    {
        ob_start();
        $status = Cli::run($this->dir, ['check', '--now=' . self::at('now')]);
        $output = (string) ob_get_clean();
        $this->assertSame(0, $status, $output);
        $this->assertStringContainsString('OK: 1 packages, 1 organisations, 1 advisories.', $output);
    }

    public function testAnEmptyRepositoryChecksCleanly(): void
    {
        foreach (['organisations/acme.json', 'packages/events.json', 'ledger/events.json', 'advisories/KSA-2027-0001.json', 'keys/keys.json', 'keys/roots.json'] as $f) {
            unlink("{$this->dir}/{$f}");
        }
        ob_start();
        $status = Cli::run($this->dir, ['check']);
        $output = (string) ob_get_clean();
        $this->assertSame(0, $status, $output);
    }

    // ---- what a check refuses ----------------------------------------------------------------

    public function testReservedNamesAreForTheProjectOnly(): void
    {
        $this->put('packages/kestello-seo.json', ['organisation' => 'acme'] + $this->get('packages/events.json'));
        $this->put('packages/forms.json', ['organisation' => 'acme'] + $this->get('packages/events.json'));
        $in = $this->inputs();
        $this->hasProblem('packages/kestello-seo.json: "kestello-seo" is reserved', $in);
        $this->hasProblem('packages/forms.json: "forms" is reserved', $in);

        $this->put('organisations/kestellohq.json', ['name' => 'Kestello', 'keys' => []]);
        $this->put('packages/kestello-seo.json', ['organisation' => 'kestellohq'] + $this->get('packages/events.json'));
        unlink("{$this->dir}/packages/forms.json");
        $this->assertSame([], $this->inputs()->problems);
    }

    public function testOnlyTheGplOrACompatibleLicenseIsAccepted(): void
    {
        $ledger = $this->get('ledger/events.json');
        $ledger['versions'][0]['license'] = 'LicenseRef-Proprietary';
        $this->put('ledger/events.json', $ledger);
        $this->hasProblem('version 1.4.0 has the license "LicenseRef-Proprietary", which is not the GPL or a GPL-compatible license', $this->inputs());
    }

    public function testLicenseExpressions(): void
    {
        $allowed = Rules::load(dirname(__DIR__))->licenses;
        foreach (['MIT', 'GPL-2.0-or-later', 'Apache-2.0', 'WTFPL', 'MIT OR LicenseRef-Commercial', '(Apache-2.0 OR MIT) AND ISC', 'LicenseRef-X OR (MIT AND BSD-3-Clause)'] as $ok) {
            $this->assertTrue(LicenseExpression::accepts($ok, $allowed), $ok);
        }
        foreach (['', 'Proprietary', 'MIT AND LicenseRef-Other', 'GPL-2.0+', 'GPL-2.0-or-later WITH Classpath-exception-2.0', 'MIT OR', '(MIT', 'MIT)', 'mit', 'MIT MIT'] as $no) {
            $this->assertFalse(LicenseExpression::accepts($no, $allowed), $no);
        }
    }

    public function testAVersionMustBeSignedByAKeyCertifiedOnItsReleaseDate(): void
    {
        $ledger = $this->get('ledger/events.json');
        $ledger['versions'][0]['released_at'] = self::at('-90 days');     // before the certificate starts
        $ledger['versions'][1]['key'] = 'ffffffffffffffff';
        $this->put('ledger/events.json', $ledger);
        $in = $this->inputs();
        $this->hasProblem('version 1.4.0 is signed by key ' . $this->acme['id'] . ', which the root had not certified for acme on its release date', $in);
        $this->hasProblem('version 1.5.0 is signed by key ffffffffffffffff', $in);
    }

    public function testOrganisationKeysMustBeCertifiedByTheRootForThatOrganisation(): void
    {
        $this->put('organisations/acme.json', ['keys' => [$this->cert('acme', signer: $this->acme['secret_key']), $this->cert('northwind')]] + $this->get('organisations/acme.json'));
        $in = $this->inputs();
        $this->hasProblem('organisations/acme.json: key certificate 0: The registry\'s organisation key is not signed by a key Kestello trusts', $in);
        $this->hasProblem('organisations/acme.json: key certificate 1 is for the organisation northwind', $in);
    }

    public function testAPrefixBelongsToItsOrganisation(): void
    {
        $other = PackageSignature::generateKeys();
        $this->put('organisations/northwind.json', ['name' => 'Northwind', 'keys' => [$this->cert('northwind', key: $other)]]);
        $this->put('packages/acme-forms.json', ['organisation' => 'northwind'] + $this->get('packages/events.json'));
        $this->hasProblem('packages/acme-forms.json: names starting with "acme-" belong to the organisation acme', $this->inputs());

        $this->put('organisations/northwind.json', ['name' => 'Northwind', 'prefix' => 'northwind-', 'keys' => []]);
        $this->hasProblem('organisations/northwind.json: prefix must be "northwind-", and needs a verified domain', $this->inputs());
    }

    public function testInputsNameTheirProblems(): void
    {
        $this->put('packages/gallery.json', ['type' => 'widget', 'organisation' => 'nobody', 'source' => ['github' => 'x'], 'categories' => ['nope']]);
        $this->hasProblem('packages/gallery.json: organisation must name a file in organisations/', $this->inputs());
        $this->put('packages/gallery.json', ['type' => 'widget', 'organisation' => 'acme', 'source' => ['github' => 'x'], 'categories' => ['nope']]);
        $in = $this->inputs();
        $this->hasProblem('packages/gallery.json: type is plugin or theme', $in);
        $this->hasProblem('packages/gallery.json: source is {"github": "owner/repository"}', $in);
        $this->hasProblem('packages/gallery.json: "nope" is not in rules/categories.json', $in);

        $this->put('ledger/orphan.json', ['format' => 1, 'versions' => []]);
        $this->hasProblem('ledger/orphan.json: there is no packages/orphan.json', $this->inputs());
    }

    public function testNamesOneLetterApartNeedAPerson(): void
    {
        $this->put('packages/evnets.json', $this->get('packages/events.json'));
        $in = $this->inputs();
        $this->assertSame([], $in->problems);
        $this->assertCount(1, $in->notices);
        $this->assertStringContainsString('packages/events.json and packages/evnets.json', $in->notices[0]);

        $this->put('packages/evnets.json', ['similar_ok' => ['events']] + $this->get('packages/events.json'));
        $this->assertSame([], $this->inputs()->notices);

        $this->assertTrue(Rules::similar('event', 'events'));
        $this->assertTrue(Rules::similar('forms', 'forums'));
        $this->assertFalse(Rules::similar('seo-pro', 'seo-plus'));
        $this->assertFalse(Rules::similar('events', 'events'));
    }

    public function testAnAdvisorySitesCantReadStopsTheBuild(): void
    {
        $this->put('advisories/KSA-2027-0001.json', ['severity' => 'urgent'] + $this->get('advisories/KSA-2027-0001.json'));
        $in = $this->inputs();
        $files = Builder::build($in, $this->now, $this->index['secret_key']);
        $problems = Verify::build($files, $in, $this->roots(), $this->now);
        $this->assertSame(['advisories/KSA-2027-0001.json: sites would leave it out as unreadable. Check each field against registry-format.md §8.'], $problems);
    }

    public function testAnIndexKeyTheKeyListDoesntNameIsCaught(): void
    {
        $in = $this->inputs();
        $files = Builder::build($in, $this->now, PackageSignature::generateKeys()['secret_key']);
        $this->assertSame(["The registry's list is not signed by a key Kestello trusts for it."], Verify::build($files, $in, $this->roots(), $this->now));
    }
}
