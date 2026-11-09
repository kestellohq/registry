<?php

declare(strict_types=1);

namespace Kestello\Registry;

use Kestello\Cms\Package\PackageSignature;
use Kestello\Cms\Package\Registry\Envelope;
use Kestello\Framework\Http\Client\HttpClient;
use Kestello\Framework\Testing\TestRunner;
use RuntimeException;
use Throwable;

/** The commands of bin/registry. */
final class Cli
{
    /** @param list<string> $args */
    public static function run(string $root, array $args): int
    {
        $command = $args[0] ?? 'help';
        $options = [];
        foreach (array_slice($args, 1) as $arg) {
            if (preg_match('/^--([a-z-]+)=(.*)$/', $arg, $m) === 1) {
                $options[$m[1]] = $m[2];
            }
        }
        try {
            return match ($command) {
                'check' => self::check($root, $options),
                'build' => self::build($root, $options),
                'accept' => self::accept($root, $options),
                'test' => (new TestRunner())->run($root . '/tests', $options['filter'] ?? null) ? 0 : 1,
                default => self::help(),
            };
        } catch (Throwable $e) {
            fwrite(STDERR, $e->getMessage() . "\n");

            return 1;
        }
    }

    /**
     * Check the inputs, then build and read back with throwaway index keys: everything a real
     * build checks except the index signature, without any secret.
     *
     * @param array<string, string> $options
     */
    private static function check(string $root, array $options): int
    {
        $now = self::now($options);
        $in = Inputs::load($root, Rules::load($root));
        foreach ($in->notices as $notice) {
            echo "Needs a person: {$notice}\n";
        }
        if ($in->problems !== []) {
            echo 'Problems:' . "\n- " . implode("\n- ", $in->problems) . "\n";

            return 1;
        }
        [$keysJson, $roots, $indexSecret] = self::throwawayKeys($now);
        $in->keysJson = $keysJson;
        $files = Builder::build($in, $now, $indexSecret);
        $problems = Verify::build($files, $in, $roots + $in->roots, $now);
        if ($problems !== []) {
            echo 'Problems in the build:' . "\n- " . implode("\n- ", $problems) . "\n";

            return 1;
        }
        echo sprintf("OK: %d packages, %d organisations, %d advisories.\n", count(array_filter($in->ledger)), count($in->organisations), count($in->advisories));

        return 0;
    }

    /** @param array<string, string> $options */
    private static function build(string $root, array $options): int
    {
        $out = $options['out'] ?? throw new RuntimeException('Usage: build --out=<directory> [--now=<ISO time>]');
        $secret = getenv('KESTELLO_REGISTRY_INDEX_KEY');
        if (!is_string($secret) || $secret === '') {
            throw new RuntimeException('KESTELLO_REGISTRY_INDEX_KEY is not set. Only the publishing job has it.');
        }
        $now = self::now($options);
        $in = Inputs::load($root, Rules::load($root));
        $files = Builder::build($in, $now, $secret);
        $problems = Verify::build($files, $in, $in->roots, $now);
        if ($problems !== []) {
            throw new RuntimeException("The build would not read back as written; nothing was written:\n- " . implode("\n- ", $problems));
        }
        Output::write($out, $files);
        echo sprintf("Built %d files into %s (serial %d).\n", count($files), $out, $now);

        return 0;
    }

    /**
     * Look for new versions and accept or refuse them. Prints a summary, and writes the full report
     * as JSON with --report for the workflow that opens the pull request.
     *
     * @param array<string, string> $options
     */
    private static function accept(string $root, array $options): int
    {
        $dl = $options['dl'] ?? throw new RuntimeException('Usage: accept --dl=<directory for accepted zips> [--package=<name>] [--report=<file>]');
        $rules = Rules::load($root);
        $in = Inputs::load($root, $rules);
        $token = getenv('GITHUB_TOKEN');
        $intake = new Intake($root, $in, $rules, new HttpClient(), $dl, self::now($options), is_string($token) ? $token : null);
        $report = $intake->run($options['package'] ?? null);
        foreach ($report['accepted'] as $a) {
            echo "Accepted {$a['slug']} {$a['version']}" . ($a['review'] === [] ? '' : ' (needs a person: ' . implode(' ', $a['review']) . ')') . "\n";
        }
        foreach ($report['refused'] as $r) {
            echo "Refused {$r['slug']} {$r['version']}: {$r['reason']}\n";
        }
        foreach ($report['changed'] as $c) {
            echo "Changed {$c['slug']} {$c['version']}: {$c['reason']}\n";
        }
        foreach ($report['errors'] as $e) {
            fwrite(STDERR, "Error: {$e}\n");
        }
        if (isset($options['report'])) {
            file_put_contents($options['report'], Json::encode($report) . "\n");
        }

        return $report['errors'] === [] ? 0 : 1;
    }

    /**
     * A key list signed by a throwaway root, naming a throwaway index key: for checking a build
     * with no secrets.
     *
     * @return array{0: string, 1: array<string, string>, 2: string}
     */
    private static function throwawayKeys(int $now): array
    {
        $root = PackageSignature::generateKeys();
        $index = PackageSignature::generateKeys();
        $keys = Json::encode([
            'kind' => 'keys', 'format' => 1, 'serial' => 1,
            'issued_at' => Builder::time($now), 'expires_at' => Builder::time($now + 86_400),
            'index_keys' => [['key' => $index['id'], 'public_key' => $index['public_key'], 'valid_from' => Builder::time($now), 'valid_until' => Builder::time($now + 86_400)]],
            'revoked' => [],
        ]);

        return [
            Json::encode(Envelope::seal($keys, [$root['secret_key']], Envelope::KEY)),
            [$root['id'] => (string) base64_decode($root['public_key'], true)],
            $index['secret_key'],
        ];
    }

    /** @param array<string, string> $options */
    private static function now(array $options): int
    {
        if (!isset($options['now'])) {
            return time();
        }
        $t = strtotime($options['now']);

        return $t === false ? throw new RuntimeException('--now is not a date and time.') : $t;
    }

    private static function help(): int
    {
        echo "Usage: php bin/registry check | accept --dl=<directory> [--package=<name>] [--report=<file>] | build --out=<directory> [--now=<time>] | test [--filter=<name>]\n";

        return 2;
    }
}
