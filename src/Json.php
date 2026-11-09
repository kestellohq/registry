<?php

declare(strict_types=1);

namespace Kestello\Registry;

use RuntimeException;

/**
 * JSON in and out. Output is compact, with keys in the order the builder writes them, so the same
 * inputs always give the same bytes (and the same hash-named files).
 */
final class Json
{
    public static function encode(mixed $value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /** @return array<mixed> */
    public static function read(string $file): array
    {
        $text = @file_get_contents($file);
        if ($text === false) {
            throw new RuntimeException("Missing {$file}.");
        }

        return self::decode($text, $file);
    }

    /** @return array<mixed> */
    public static function decode(string $text, string $what): array
    {
        try {
            $data = json_decode($text, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new RuntimeException("{$what} is not valid JSON: {$e->getMessage()}.");
        }
        if (!is_array($data)) {
            throw new RuntimeException("{$what} must hold a JSON object or list.");
        }

        return $data;
    }
}
