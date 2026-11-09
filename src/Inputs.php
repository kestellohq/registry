<?php

declare(strict_types=1);

namespace Kestello\Registry;

use Kestello\Cms\Package\PackageSignature;
use Kestello\Cms\Package\Registry\Fields;
use Kestello\Cms\Package\Registry\OrganisationKey;
use Kestello\Cms\Package\Registry\RegistryException;
use Throwable;

/**
 * Everything in the repository the builder reads, checked against the rules. Problems stop a
 * build; notices ask a person to look (a name close to another one) and don't.
 *
 *   keys/roots.json            [{"name", "public_key"}]: the root keys Kestello ships
 *   keys/keys.json             signed by a root: index keys and revocations, published as is
 *   organisations/<id>.json    {"name", "homepage"?, "verified"?: {"domain", "at"}, "prefix"?, "keys": [certificate envelopes]}
 *   packages/<slug>.json       {"type", "organisation", "source": {"github"}, "categories", "homepage"?, "support"?,
 *                               "commerce"?, "withdrawn"?: {"<version>": {"at", "reason"}}, "similar_ok"?: [names]}
 *   ledger/<slug>.json         {"format": 1, "versions": [accepted versions]}: written by the builder only
 *   advisories/<id>.json       one advisory each
 *   moves/<name>.json          a root-signed move certificate each
 */
final class Inputs
{
    /** @var list<string> */
    public array $problems = [];
    /** @var list<string> */
    public array $notices = [];
    /** @var array<string, string> key id => raw public key */
    public array $roots = [];
    public ?string $keysJson = null;
    /** @var array<string, array{name: string, homepage: ?string, verified: ?array{domain: string, at: string}, prefix: ?string, keys: list<array<mixed>>, certs: list<OrganisationKey>}> */
    public array $organisations = [];
    /** @var array<string, array<string, mixed>> */
    public array $packages = [];
    /** @var array<string, list<array<string, mixed>>> slug => versions */
    public array $ledger = [];
    /** @var array<string, array<string, mixed>> */
    public array $advisories = [];
    /** @var list<array<mixed>> */
    public array $moves = [];

    private function __construct(private readonly string $root, private readonly Rules $rules) {}

    public static function load(string $root, Rules $rules): self
    {
        $in = new self($root, $rules);
        $in->keys();
        $in->organisations();
        $in->packages();
        $in->ledger();
        $in->advisories();
        $in->moves();
        $in->names();

        return $in;
    }

    private function keys(): void
    {
        $roots = $this->root . '/keys/roots.json';
        $keys = $this->root . '/keys/keys.json';
        if (!is_file($roots)) {
            if (glob($this->root . '/organisations/*.json') !== []) {
                $this->problems[] = 'keys/roots.json: missing, and organisations need root-certified keys.';
            }

            return;
        }
        foreach ($this->json($roots) ?? [] as $i => $k) {
            $public = is_array($k) ? Fields::publicKey($k['public_key'] ?? null) : null;
            if ($public === null || Fields::line($k['name'] ?? null, 80) === null) {
                $this->problems[] = "keys/roots.json: entry {$i} needs a name and a base64 Ed25519 public_key.";
                continue;
            }
            $this->roots[PackageSignature::keyId($public)] = $public;
        }
        if (!is_file($keys)) {
            $this->problems[] = 'keys/keys.json: missing. It is signed by a root key at the key ceremony.';

            return;
        }
        $this->keysJson = (string) file_get_contents($keys);
    }

    private function organisations(): void
    {
        foreach ($this->files('organisations') as $id => $file) {
            $where = "organisations/{$id}.json";
            $d = $this->json($file);
            if ($d === null) {
                continue;
            }
            if (Fields::organisationId($id) === null) {
                $this->problems[] = "{$where}: an organisation id is 2 to 39 lowercase letters, digits and single dashes.";
                continue;
            }
            if ($this->rules->reserved($id) && $id !== Rules::PROJECT) {
                $this->problems[] = "{$where}: \"{$id}\" is reserved for the project.";
            }
            $name = Fields::line($d['name'] ?? null, 80);
            $homepage = isset($d['homepage']) ? Fields::https($d['homepage']) : null;
            $verified = $d['verified'] ?? null;
            $prefix = $d['prefix'] ?? null;
            if ($name === null) {
                $this->problems[] = "{$where}: name is required, at most 80 characters.";
            }
            if (isset($d['homepage']) && $homepage === null) {
                $this->problems[] = "{$where}: homepage must be an https address.";
            }
            if ($verified !== null && (!is_array($verified) || Fields::line($verified['domain'] ?? null, 253) === null || Fields::time($verified['at'] ?? null) === null)) {
                $this->problems[] = "{$where}: verified is {\"domain\", \"at\"}.";
                $verified = null;
            }
            if ($prefix !== null && ($prefix !== "{$id}-" || $verified === null)) {
                $this->problems[] = "{$where}: prefix must be \"{$id}-\", and needs a verified domain or company.";
                $prefix = null;
            }
            $keys = $d['keys'] ?? [];
            $certs = [];
            if (!is_array($keys) || !array_is_list($keys) || count($keys) > 20) {
                $this->problems[] = "{$where}: keys is a list of at most 20 certificates.";
                $keys = [];
            }
            foreach ($keys as $i => $envelope) {
                try {
                    $cert = OrganisationKey::verify($envelope, $this->roots);
                    if ($cert->organisation !== $id) {
                        $this->problems[] = "{$where}: key certificate {$i} is for the organisation {$cert->organisation}.";
                    }
                    $certs[] = $cert;
                } catch (RegistryException $e) {
                    $this->problems[] = "{$where}: key certificate {$i}: {$e->getMessage()}";
                }
            }
            $this->organisations[$id] = [
                'name' => $name ?? $id, 'homepage' => $homepage,
                'verified' => is_array($verified) ? ['domain' => (string) $verified['domain'], 'at' => (string) $verified['at']] : null,
                'prefix' => $prefix, 'keys' => array_values($keys), 'certs' => $certs,
            ];
        }
    }

    private function packages(): void
    {
        foreach ($this->files('packages') as $slug => $file) {
            $where = "packages/{$slug}.json";
            $d = $this->json($file);
            if ($d === null) {
                continue;
            }
            if (Fields::packageName($slug) === null) {
                $this->problems[] = "{$where}: a package name is 3 to 64 lowercase letters, digits and single dashes.";
                continue;
            }
            $org = $d['organisation'] ?? null;
            if (!is_string($org) || !isset($this->organisations[$org])) {
                $this->problems[] = "{$where}: organisation must name a file in organisations/.";
                continue;
            }
            if ($this->rules->reserved($slug) && $org !== Rules::PROJECT) {
                $this->problems[] = "{$where}: \"{$slug}\" is reserved for the project.";
            }
            foreach ($this->organisations as $other => $o) {
                if ($other !== $org && $o['prefix'] !== null && str_starts_with($slug, $o['prefix'])) {
                    $this->problems[] = "{$where}: names starting with \"{$o['prefix']}\" belong to the organisation {$other}.";
                }
            }
            if (!in_array($d['type'] ?? null, ['plugin', 'theme'], true)) {
                $this->problems[] = "{$where}: type is plugin or theme.";
            }
            $github = is_array($d['source'] ?? null) ? ($d['source']['github'] ?? null) : null;
            if (!is_string($github) || preg_match('#^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$#', $github) !== 1) {
                $this->problems[] = "{$where}: source is {\"github\": \"owner/repository\"}.";
            }
            $categories = $d['categories'] ?? null;
            if (!is_array($categories) || !array_is_list($categories) || $categories === [] || count($categories) > 10) {
                $this->problems[] = "{$where}: categories is a list of 1 to 10 categories from rules/categories.json.";
            } else {
                foreach ($categories as $c) {
                    if (!is_string($c) || !isset($this->rules->categories[$c])) {
                        $this->problems[] = "{$where}: \"" . (is_string($c) ? $c : '?') . '" is not in rules/categories.json.';
                    }
                }
            }
            foreach (['homepage', 'support'] as $k) {
                if (isset($d[$k]) && Fields::https($d[$k]) === null) {
                    $this->problems[] = "{$where}: {$k} must be an https address.";
                }
            }
            if (isset($d['commerce'])) {
                $c = $d['commerce'];
                if (!is_array($c) || ($c['model'] ?? null) !== 'yearly-per-site' || ($c['license'] ?? null) !== 'seller'
                    || Fields::line($c['price'] ?? null, 40) === null || Fields::https($c['store_url'] ?? null) === null) {
                    $this->problems[] = "{$where}: commerce is {\"model\": \"yearly-per-site\", \"price\" (at most 40 characters), \"store_url\" (https), \"license\": \"seller\"}.";
                }
            }
            foreach (is_array($d['withdrawn'] ?? null) ? $d['withdrawn'] : [] as $version => $w) {
                if (Fields::version((string) $version) === null || !is_array($w) || Fields::time($w['at'] ?? null) === null || Fields::line($w['reason'] ?? null, 200) === null) {
                    $this->problems[] = "{$where}: withdrawn is {\"<version>\": {\"at\", \"reason\"}}.";
                }
            }
            $this->packages[$slug] = $d;
        }
    }

    private function ledger(): void
    {
        foreach ($this->files('ledger') as $slug => $file) {
            $where = "ledger/{$slug}.json";
            if (!isset($this->packages[$slug])) {
                $this->problems[] = "{$where}: there is no packages/{$slug}.json. A ledger is never deleted; remove the package by withdrawing its versions.";
                continue;
            }
            $d = $this->json($file);
            if ($d === null || ($d['format'] ?? null) !== 1 || !is_array($d['versions'] ?? null) || !array_is_list($d['versions'])) {
                $this->problems[] = "{$where}: not a ledger (format 1 with a list of versions).";
                continue;
            }
            $org = (string) $this->packages[$slug]['organisation'];
            $seen = [];
            $versions = [];
            foreach ($d['versions'] as $i => $v) {
                $problem = is_array($v) ? $this->version($v, $org) : 'is not an object';
                $label = is_array($v) && is_string($v['version'] ?? null) ? $v['version'] : "#{$i}";
                if ($problem !== null) {
                    $this->problems[] = "{$where}: version {$label} {$problem}.";
                    continue;
                }
                if (isset($seen[$v['version']])) {
                    $this->problems[] = "{$where}: version {$label} is listed twice.";
                    continue;
                }
                $seen[$v['version']] = true;
                $versions[] = $v;
            }
            $this->ledger[$slug] = $versions;
        }
    }

    /**
     * What is wrong with an accepted version, or null.
     *
     * @param array<mixed> $v
     */
    private function version(array $v, string $org): ?string
    {
        $requires = is_array($v['requires'] ?? null) ? $v['requires'] : [];
        $released = Fields::time($v['released_at'] ?? null);
        $checks = [
            'has no valid version' => Fields::version($v['version'] ?? null) === null,
            'has no valid released_at' => $released === null,
            'has no valid sha256' => Fields::sha256($v['sha256'] ?? null) === null,
            'has no valid size' => !is_int($v['size'] ?? null) || $v['size'] < 1,
            'has no valid signing key' => Fields::keyId($v['key'] ?? null) === null,
            'has no name (at most 80 characters)' => Fields::line($v['name'] ?? null, 80) === null,
            'has no summary (at most 160 characters)' => Fields::line($v['summary'] ?? null, 160) === null,
            'has a description over 20,000 characters' => Fields::text($v['description'] ?? null, 20_000) === null,
            'has notes over 20,000 characters' => Fields::text($v['notes'] ?? null, 20_000) === null,
            'needs requires.core' => Fields::constraint($requires['core'] ?? null) === null,
            'has an invalid requires.php' => isset($requires['php']) && Fields::constraint($requires['php']) === null,
        ];
        foreach ($checks as $problem => $failed) {
            if ($failed) {
                return $problem;
            }
        }
        $license = $v['license'] ?? null;
        if (!is_string($license) || !$this->rules->license($license)) {
            return 'has the license "' . (is_string($license) ? $license : '?') . '", which is not the GPL or a GPL-compatible license from rules/licenses.txt';
        }
        foreach ($this->organisations[$org]['certs'] as $cert) {
            if ($cert->id === $v['key'] && $cert->validAt((int) $released)) {
                return null;
            }
        }

        return "is signed by key {$v['key']}, which the root had not certified for {$org} on its release date";
    }

    private function advisories(): void
    {
        foreach ($this->files('advisories') as $id => $file) {
            $d = $this->json($file);
            if ($d === null) {
                continue;
            }
            if (($d['id'] ?? null) !== $id) {
                $this->problems[] = "advisories/{$id}.json: its id must be the file's name.";
                continue;
            }
            $this->advisories[$id] = $d;
        }
        ksort($this->advisories, SORT_STRING);
    }

    private function moves(): void
    {
        foreach ($this->files('moves') as $file) {
            $d = $this->json($file);
            if ($d !== null) {
                $this->moves[] = $d;
            }
        }
    }

    /** Names a person should compare (registry-format.md §1.1). */
    private function names(): void
    {
        $slugs = array_keys($this->packages);
        foreach ($slugs as $a) {
            foreach ($slugs as $b) {
                $ok = array_merge((array) ($this->packages[$a]['similar_ok'] ?? []), (array) ($this->packages[$b]['similar_ok'] ?? []));
                if ($a < $b && Rules::similar($a, $b) && !in_array($a, $ok, true) && !in_array($b, $ok, true)) {
                    $this->notices[] = "packages/{$a}.json and packages/{$b}.json: the names are one letter apart. A person checks this isn't impersonation, then adds the other name to \"similar_ok\".";
                }
            }
        }
    }

    /** @return array<string, string> name => file, sorted */
    private function files(string $dir): array
    {
        $out = [];
        foreach (glob($this->root . "/{$dir}/*.json") ?: [] as $file) {
            $out[basename($file, '.json')] = $file;
        }
        ksort($out, SORT_STRING);

        return $out;
    }

    /** @return array<mixed>|null */
    private function json(string $file): ?array
    {
        try {
            return Json::read($file);
        } catch (Throwable $e) {
            $this->problems[] = substr($file, strlen($this->root) + 1) . ': ' . $e->getMessage();

            return null;
        }
    }
}
