<?php

declare(strict_types=1);

namespace Kestello\Registry;

/**
 * The rules in rules/: reserved names, accepted licenses and categories.
 */
final readonly class Rules
{
    /** The project's own organisation: the only one that may use reserved names. */
    public const string PROJECT = 'kestellohq';

    /**
     * @param list<string> $reserved exact names, or prefixes ending in "-*"
     * @param list<string> $licenses SPDX ids
     * @param array<string, string> $categories id => label
     */
    public function __construct(
        public array $reserved,
        public array $licenses,
        public array $categories,
    ) {}

    public static function load(string $root): self
    {
        $categories = Json::read($root . '/rules/categories.json');

        return new self(
            self::lines($root . '/rules/reserved.txt'),
            self::lines($root . '/rules/licenses.txt'),
            array_map('strval', $categories),
        );
    }

    /** Whether $name is reserved for the project (packages and organisations alike). */
    public function reserved(string $name): bool
    {
        foreach ($this->reserved as $rule) {
            if (str_ends_with($rule, '*') ? str_starts_with($name, substr($rule, 0, -1)) : $name === $rule) {
                return true;
            }
        }

        return false;
    }

    public function license(string $expression): bool
    {
        return LicenseExpression::accepts($expression, $this->licenses);
    }

    /**
     * Two names a person should compare before both are listed: one edit apart, counting a swap
     * of two neighbouring letters as one edit (event, evnets, events).
     */
    public static function similar(string $a, string $b): bool
    {
        if ($a === $b) {
            return false;
        }
        $la = strlen($a);
        $lb = strlen($b);
        if (abs($la - $lb) > 1) {
            return false;
        }
        // optimal string alignment distance, stopped at 1
        $d = [];
        for ($i = 0; $i <= $la; $i++) {
            $d[$i][0] = $i;
        }
        for ($j = 0; $j <= $lb; $j++) {
            $d[0][$j] = $j;
        }
        for ($i = 1; $i <= $la; $i++) {
            for ($j = 1; $j <= $lb; $j++) {
                $cost = $a[$i - 1] === $b[$j - 1] ? 0 : 1;
                $d[$i][$j] = min($d[$i - 1][$j] + 1, $d[$i][$j - 1] + 1, $d[$i - 1][$j - 1] + $cost);
                if ($i > 1 && $j > 1 && $a[$i - 1] === $b[$j - 2] && $a[$i - 2] === $b[$j - 1]) {
                    $d[$i][$j] = min($d[$i][$j], $d[$i - 2][$j - 2] + 1);
                }
            }
        }

        return $d[$la][$lb] <= 1;
    }

    /** @return list<string> */
    private static function lines(string $file): array
    {
        $text = @file_get_contents($file);
        if ($text === false) {
            throw new \RuntimeException("Missing {$file}.");
        }
        $lines = array_map('trim', explode("\n", $text));

        return array_values(array_filter($lines, static fn(string $l): bool => $l !== '' && !str_starts_with($l, '#')));
    }
}
