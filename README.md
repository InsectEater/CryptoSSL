# CryptoSSL

Introduction
------------

CryptoSSL is a simple class for assymetric encrypting and decrypting, using PHP
OpenSSL library. Its goal is to be used easy with minimum coding, but yet retain
the basic funcionality of crypting and decrypting with public and private keys.

Current capabilities of CryptoSSL
---------------------------------

* Load public and private keys in .pem format;
* Using public and private keys to encrypt and decrypt short size data;
* Using public and private keys to encrypt and decrypt big size data, using 
intermediary randomly genereated secret key.

Installation
------------

It is simple - just include the class file.

Usage
-----

### Direct encrypting with public and private keys on small size data
```PHP
<?php
$c = new \InsectEater\CryptoSSL('public.pem', 'private.pem');
$Data = 'My secret key. The kitten is eating.';

echo $c->publicEncrypt($Data);
echo $c->privateDecrypt($c->Encrypted);
```

### Encrypting big data
```PHP
<?php
$c = new \InsectEater\CryptoSSL();
$c->setPublicKey('public.pem');
$Data = 'My secret key. The kitten is eating.';

$Data = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.';

$c->seal($Data);
echo $c->Encrypted;
echo $c->SealingKey;
```

### Encrypting using different encoding and cypher
```PHP
<?php
$c = new \InsectEater\CryptoSSL('public.pem', 'private.pem');
$Data = 'My secret key. The kitten is eating.';

$c->seal($Data, $c::HEX, 'AES-256-ECB');
echo $c->Encrypted;
echo $c->SealingKey;

$c->open($c->Encrypted, $c->SealingKey, $c::HEX, 'AES-256-ECB');
echo $c->Decrypted;
```