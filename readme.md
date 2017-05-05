# PHPSha1

## This is an implementation of `SHA1` encryption written purely in `PHP`

### Example
```php
<?php

require 'vendor/autoload.php';

use PHPSha1\Sha1;

Sha1::hash('string to hash');
// e40871214d28a178b352c9392597f855d7dd6091

sha1('string to hash');
// e40871214d28a178b352c9392597f855d7dd6091

```
