<?php

namespace Donr\Error;

use Exception;

class Decrypt extends Exception
{
    public function __construct(
        $message
    ) {
        parent::__construct($message, null, null);
    }
}
