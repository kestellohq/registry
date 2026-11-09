<?php

declare(strict_types=1);

namespace Kestello\Registry;

use RuntimeException;

/** A version that may not join the registry. The message is for the publisher. */
final class Refused extends RuntimeException {}
