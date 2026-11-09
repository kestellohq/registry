<?php

declare(strict_types=1);

namespace Kestello\Registry\Tests;

use Kestello\Cms\Package\Registry\OrganisationKey;
use Kestello\Cms\Package\Registry\RegistryKeys;
use Kestello\Framework\Testing\TestCase;
use Kestello\Registry\Ceremony;
use Kestello\Registry\Json;

/** The root key's jobs: new keys, keys.json and organisation certificates. */
final class CeremonyTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/kestello-ceremony-' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/secrets', 0o700, true);
    }

    protected function tearDown(): void
    {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($this->dir);
    }

    /** @return array<string, string> */
    private function roots(string ...$files): array
    {
        $out = [];
        foreach ($files as $f) {
            $k = Json::read($f);
            $out[$k['id']] = (string) base64_decode($k['public_key'], true);
        }

        return $out;
    }

    public function testKeygenWritesAPrivateFileAndNeverOverwrites(): void
    {
        $file = "{$this->dir}/secrets/root.json";
        $id = Ceremony::keygen($file);
        $this->assertSame(0o600, fileperms($file) & 0o777);
        $this->assertSame($id, Json::read($file)['id']);
        $this->assertThrows(\RuntimeException::class, static fn() => Ceremony::keygen($file));
    }

    public function testKeysJsonIsSignedByTheRootAndItsSerialOnlyGoesUp(): void
    {
        $now = (int) strtotime('2027-01-15T12:00:00Z');
        Ceremony::keygen($root = "{$this->dir}/secrets/root.json");
        Ceremony::keygen($index = "{$this->dir}/secrets/index.json");
        $k = Json::read($root);
        mkdir("{$this->dir}/keys");
        file_put_contents("{$this->dir}/keys/roots.json", Json::encode([['name' => 'Root', 'public_key' => $k['public_key']]]));

        Ceremony::signKeys($this->dir, $root, [$index], [], null, $now);
        $keys = RegistryKeys::verify((string) file_get_contents("{$this->dir}/keys/keys.json"), $this->roots($root), $now);
        $this->assertSame(1, $keys->serial);
        $this->assertSame([Json::read($index)['id']], array_keys($keys->indexKeysAt($now)));

        Ceremony::keygen($next = "{$this->dir}/secrets/index-2.json");
        Ceremony::signKeys($this->dir, $root, [$next], [Json::read($index)['id'] => 'Replaced'], null, $now + 60);
        $keys = RegistryKeys::verify((string) file_get_contents("{$this->dir}/keys/keys.json"), $this->roots($root), $now + 60, 1);
        $this->assertSame(2, $keys->serial);
        $this->assertSame('Replaced', $keys->revoked(Json::read($index)['id'])['reason'] ?? null);

        Ceremony::signKeys($this->dir, $root, [$next], [], null, $now + 120);
        $keys = RegistryKeys::verify((string) file_get_contents("{$this->dir}/keys/keys.json"), $this->roots($root), $now + 120);
        $this->assertSame('Replaced', $keys->revoked(Json::read($index)['id'])['reason'] ?? null, 'revocations are kept');
        $this->assertThrows(\RuntimeException::class, fn() => Ceremony::signKeys($this->dir, $root, [$next], [], 2, $now + 180));
    }

    public function testCertifyAddsARootSignedCertificate(): void
    {
        $now = (int) strtotime('2027-01-15T12:00:00Z');
        Ceremony::keygen($root = "{$this->dir}/secrets/root.json");
        Ceremony::keygen($acme = "{$this->dir}/secrets/acme.json");
        mkdir("{$this->dir}/organisations");
        file_put_contents("{$this->dir}/organisations/acme.json", Json::encode(['name' => 'Acme']));

        Ceremony::certify($this->dir, $root, 'acme', $acme, 3, $now);
        $data = Json::read("{$this->dir}/organisations/acme.json");
        $this->assertSame('Acme', $data['name']);
        $cert = OrganisationKey::verify($data['keys'][0], $this->roots($root));
        $this->assertSame([Json::read($acme)['id'], 'acme'], [$cert->id, $cert->organisation]);
        $this->assertTrue($cert->validAt($now + 2 * 365 * 86_400));
        $this->assertStringNotContainsString(Json::read($acme)['secret_key'], (string) file_get_contents("{$this->dir}/organisations/acme.json"));
    }
}
