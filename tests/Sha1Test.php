<?php

namespace PHPSha1\Tests;

use PHPSha1\Sha1;
use PHPUnit_Framework_TestCase;

class Sha1Test extends PHPUnit_Framework_TestCase
{
    public function test_that_it_produces_correct_hash()
    {
        $native = sha1('string to hash');
        $purephp = Sha1::hash('string to hash');

        $this->assertEquals($native, $purephp);
    }

}
