<?php

declare(strict_types=1);

namespace Kestello\Registry;

use RuntimeException;

/**
 * Writes a build to a directory in the order uploads must follow (registry-format.md §9.3): the
 * hash-named files first, then keys.json, then index.json. Each file is written to a temporary
 * name and renamed, so a reader never sees half a file.
 */
final class Output
{
    /** @param array<string, string> $files path => bytes, as Builder::build() orders them */
    public static function write(string $dir, array $files): void
    {
        $last = ['keys.json', 'index.json'];
        $order = array_merge(array_diff(array_keys($files), $last), array_intersect($last, array_keys($files)));
        foreach ($order as $path) {
            $target = rtrim($dir, '/') . '/' . $path;
            if (!is_dir(dirname($target)) && !mkdir(dirname($target), 0o755, true) && !is_dir(dirname($target))) {
                throw new RuntimeException("Can't create " . dirname($target) . '.');
            }
            if (file_put_contents($target . '.tmp', $files[$path]) === false || !rename($target . '.tmp', $target)) {
                throw new RuntimeException("Can't write {$target}.");
            }
        }
    }
}
