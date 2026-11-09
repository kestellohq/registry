<?php

declare(strict_types=1);

namespace Kestello\Registry;

/**
 * Whether an SPDX license expression lets the code be used under the GPL (registry-format.md §1.5).
 *
 *   MIT                          on the list
 *   MIT OR LicenseRef-Commercial  yes: you may choose MIT
 *   MIT AND LicenseRef-Other      no: both apply, and one isn't on the list
 *   (Apache-2.0 OR MIT) AND ISC   yes
 *
 * OR needs one acceptable side, AND needs both. WITH (a license exception) and the old "+"
 * suffix are not accepted: a person decides those. Anything that doesn't parse is not accepted.
 */
final class LicenseExpression
{
    /** @var list<string> */
    private array $tokens = [];
    private int $at = 0;

    /** @param list<string> $allowed SPDX ids */
    private function __construct(private readonly array $allowed) {}

    /** @param list<string> $allowed */
    public static function accepts(string $expression, array $allowed): bool
    {
        if (strlen($expression) > 200 || preg_match_all('/\(|\)|[A-Za-z0-9.+:-]+|\S/', $expression, $m) === false) {
            return false;
        }
        $parser = new self($allowed);
        $parser->tokens = $m[0];
        if ($parser->tokens === []) {
            return false;
        }
        $ok = $parser->expression();

        return $ok === true && $parser->at === count($parser->tokens);
    }

    /** null when the expression doesn't parse */
    private function expression(): ?bool
    {
        $result = $this->term();
        while ($result !== null && $this->peek() === 'OR') {
            $this->at++;
            $right = $this->term();
            $result = $right === null ? null : ($result || $right);
        }

        return $result;
    }

    private function term(): ?bool
    {
        $result = $this->factor();
        while ($result !== null && $this->peek() === 'AND') {
            $this->at++;
            $right = $this->factor();
            $result = $right === null ? null : ($result && $right);
        }

        return $result;
    }

    private function factor(): ?bool
    {
        $token = $this->peek();
        if ($token === '(') {
            $this->at++;
            $inner = $this->expression();
            if ($inner === null || $this->peek() !== ')') {
                return null;
            }
            $this->at++;

            return $inner;
        }
        if ($token === null || in_array($token, [')', 'AND', 'OR', 'WITH'], true) || preg_match('/^[A-Za-z0-9.:-]+\+?$/', $token) !== 1) {
            return null;
        }
        $this->at++;
        if ($this->peek() === 'WITH') {
            return null;
        }

        return in_array($token, $this->allowed, true);
    }

    private function peek(): ?string
    {
        return $this->tokens[$this->at] ?? null;
    }
}
