<?php

namespace Donr\Error;

use Exception;

class AuthenticationVerification extends Exception
{
    public function __construct(
        $message
    ) {
        parent::__construct($message, null, null);
    }
}
