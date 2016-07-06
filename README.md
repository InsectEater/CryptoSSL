# CryptoSSL

Introduction
------------

CryptoSSL is a simple class for asymmetric encrypting and decrypting, using PHP
OpenSSL library. Its goal is to be used easy with minimum coding, but yet retain
the basic functionality of encrypting and decrypting with public and private keys.

Current capabilities of CryptoSSL
---------------------------------

* Load public and private keys in .pem format;
* Use public and private keys to directly encrypt and decrypt short size data;
* Use public and private keys to encrypt and decrypt big size data, by 
randomly generated secret key for the internal symmetric encryption.
- By using openssl_seal() / openssl_open functions (less secure)
- By using mcrypt_crypt / mcrypt_decrypt functions (more secure)
* Get encrypted data in three posibble encodings
- RAW - encrypted data is not changed
- BASE64 - (default)
- HEX - hex representation of encrypted data bytes

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
For more, check example.php file.