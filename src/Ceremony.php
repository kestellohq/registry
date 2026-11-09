<?php

declare(strict_types=1);

namespace Kestello\Registry;

use Kestello\Cms\Package\PackageSignature;
use Kestello\Cms\Package\Registry\Envelope;
use Kestello\Cms\Package\Registry\Fields;
use Kestello\Cms\Package\Registry\RegistryKeys;
use RuntimeException;

/**
 * The root key's jobs (registry-format.md §3), run on the machine that holds the root key, never
 * in CI:
 *
 *   keygen   --out=<file>                                  a new key pair; the secret never printed
 *   sign-keys --root=<secret file> --index=<file>[,<file>] [--revoke=<id>:<reason>,…] [--serial=N]
 *            writes keys/keys.json
 *   certify  --root=<secret file> --organisation=<id> --key=<file> [--years=3]
 *            adds a certificate to organisations/<id>.json
 *
 * A key file is {"id", "public_key", "secret_key"} (mode 0600). The commands read a file's
 * public_key when they need the public half, so a public-only copy ({"id", "public_key"}) works.
 */
final class Ceremony
{
    public static function keygen(string $out): string
    {
        if (file_exists($out)) {
            throw new RuntimeException("{$out} exists. A key file is never overwritten.");
        }
        if (!is_dir(dirname($out)) && !mkdir(dirname($out), 0o700, true) && !is_dir(dirname($out))) {
            throw new RuntimeException("Can't create " . dirname($out) . '.');
        }
        $keys = PackageSignature::generateKeys();
        $old = umask(0o077);
        try {
            if (file_put_contents($out, Json::encode($keys) . "\n", LOCK_EX) === false) {
                throw new RuntimeException("Can't write {$out}.");
            }
        } finally {
            umask($old);
        }
        chmod($out, 0o600);

        return $keys['id'];
    }

    /**
     * @param list<string> $indexFiles
     * @param array<string, string> $revoke key id => reason
     */
    public static function signKeys(string $root, string $rootFile, array $indexFiles, array $revoke, ?int $serial, int $now): string
    {
        $index = [];
        foreach ($indexFiles as $file) {
            $key = self::key($file);
            $index[] = ['key' => $key['id'], 'public_key' => $key['public_key'], 'valid_from' => Builder::time($now), 'valid_until' => Builder::time($now + 395 * 86_400)];
        }
        $previous = is_file("{$root}/keys/keys.json") ? self::previous($root, $now) : null;
        $serial ??= ($previous['serial'] ?? 0) + 1;
        if ($previous !== null && $serial <= $previous['serial']) {
            throw new RuntimeException("The serial must go up: the current keys.json is number {$previous['serial']}.");
        }
        $revoked = $previous['revoked'] ?? [];
        foreach ($revoke as $id => $reason) {
            $revoked[] = ['key' => $id, 'at' => Builder::time($now), 'reason' => $reason];
        }
        $payload = Json::encode([
            'kind' => 'keys', 'format' => 1, 'serial' => $serial,
            'issued_at' => Builder::time($now), 'expires_at' => Builder::time($now + 395 * 86_400),
            'index_keys' => $index, 'revoked' => $revoked,
        ]);
        $envelope = Envelope::seal($payload, [self::secret($rootFile)], Envelope::KEY);
        self::write("{$root}/keys/keys.json", json_encode($envelope, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

        return "keys/keys.json: number {$serial}, " . count($index) . ' index key(s), ' . count($revoked) . ' revoked.';
    }

    public static function certify(string $root, string $rootFile, string $organisation, string $keyFile, int $years, int $now): string
    {
        if (Fields::organisationId($organisation) === null || $years < 1 || $years > 3) {
            throw new RuntimeException('certify needs an organisation id and --years from 1 to 3.');
        }
        $file = "{$root}/organisations/{$organisation}.json";
        $data = is_file($file) ? Json::read($file) : ['name' => $organisation];
        $key = self::key($keyFile);
        $cert = Envelope::seal(Json::encode([
            'kind' => 'organisation', 'organisation' => $organisation, 'key' => $key['id'], 'public_key' => $key['public_key'],
            'valid_from' => Builder::time($now), 'valid_until' => Builder::time($now + $years * 365 * 86_400),
        ]), [self::secret($rootFile)], Envelope::KEY);
        $data['keys'] = [...(array) ($data['keys'] ?? []), $cert];
        self::write($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

        return "organisations/{$organisation}.json: certified key {$key['id']} for {$years} year(s).";
    }

    /** @return array{id: string, public_key: string} */
    private static function key(string $file): array
    {
        $d = Json::read($file);
        $public = Fields::publicKey($d['public_key'] ?? null);
        if ($public === null) {
            throw new RuntimeException("{$file} has no public_key.");
        }

        return ['id' => PackageSignature::keyId($public), 'public_key' => (string) $d['public_key']];
    }

    private static function secret(string $file): string
    {
        $secret = Json::read($file)['secret_key'] ?? null;
        if (!is_string($secret) || strlen((string) base64_decode($secret, true)) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new RuntimeException("{$file} has no secret_key.");
        }

        return $secret;
    }

    /** @return array{serial: int, revoked: list<array<string, mixed>>} */
    private static function previous(string $root, int $now): array
    {
        $roots = [];
        foreach (Json::read("{$root}/keys/roots.json") as $k) {
            $public = Fields::publicKey($k['public_key'] ?? null);
            if ($public !== null) {
                $roots[PackageSignature::keyId($public)] = $public;
            }
        }
        $body = (string) file_get_contents("{$root}/keys/keys.json");
        $keys = RegistryKeys::verify($body, $roots, $now);
        $payload = Json::decode((string) base64_decode((string) (Json::decode($body, 'keys/keys.json')['payload'] ?? ''), true), 'keys/keys.json');

        return ['serial' => $keys->serial, 'revoked' => array_values((array) ($payload['revoked'] ?? []))];
    }

    private static function write(string $file, string $contents): void
    {
        if (!is_dir(dirname($file))) {
            mkdir(dirname($file), 0o755, true);
        }
        file_put_contents($file, $contents);
    }
}
