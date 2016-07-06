<?php

include_once 'CryptoSSL.class.php';

$c = new \InsectEater\CryptoSSL('public.pem', 'private.pem');
/*
$Data = 'My secret key. The kitten is eating.';

echo '<h1>Direct encrypting with public and private keys on small size data</h1>';

echo '<b>Encrypted:</b> '.$c->publicEncrypt($Data)."<br />\r\n";
echo '<b>Decrypted:</b> '.$c->privateDecrypt($c->Encrypted)."<br />\r\n<br />\r\n";

$Data = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.';

echo '<h1>Encrypting big data</h1>';
$c->clear(true);
$c->setPublicKey('public.pem');
$c->seal($Data);
echo '<b>Sealed:</b> '.$c->Encrypted."<br />\r\n";
echo '<b>Sealing key:</b> '.$c->SealingKey."<br />\r\n";

$c->setPrivateKey('private.pem');
$c->open($c->Encrypted, $c->SealingKey);
echo '<b>Opened:</b> '.$c->Decrypted."<br />\r\n<br />\r\n";

echo '<h1>Encrypting using different encoding and cypher</h1>';
$c->seal($Data, $c::HEX, 'AES-256-ECB');
echo '<b>Sealed:</b> '.$c->Encrypted."<br />\r\n";
echo '<b>Sealing key:</b> '.$c->SealingKey."<br />\r\n";
$c->open($c->Encrypted, $c->SealingKey, $c::HEX, 'AES-256-ECB');
echo '<b>Opened:</b> '.$c->Decrypted;
*/

echo $c->mcrypt_seal('Hello there');

/*
$Mc =mcrypt_module_open (MCRYPT_BLOWFISH, null, 'cfb', null);
$IvSize = mcrypt_enc_get_iv_size($Mc);
$KeySize = mcrypt_enc_get_key_size($Mc);
var_dump($KeySize);

$Key = openssl_random_pseudo_bytes($KeySize);
$Iv = openssl_random_pseudo_bytes($IvSize);
$Data = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna';
$Crypted = $Iv.mcrypt_encrypt (MCRYPT_BLOWFISH, $Key , $Data , 'cfb', $Iv);
unset($Iv);

$Iv = substr($Crypted, 0, 8);
$Crypted = substr($Crypted, 8);
var_dump(mcrypt_decrypt(MCRYPT_BLOWFISH, $Key , $Crypted, 'cfb', $Iv) );
*/

/*

    MCRYPT_3DES
    MCRYPT_ARCFOUR_IV (libmcrypt > 2.4.x only)
    MCRYPT_ARCFOUR (libmcrypt > 2.4.x only)
    MCRYPT_BLOWFISH
    MCRYPT_CAST_128
    MCRYPT_CAST_256
    MCRYPT_CRYPT
    MCRYPT_DES
    MCRYPT_DES_COMPAT (libmcrypt 2.2.x only)
    MCRYPT_ENIGMA (libmcrypt > 2.4.x only, alias for MCRYPT_CRYPT)
    MCRYPT_GOST
    MCRYPT_IDEA (non-free)
    MCRYPT_LOKI97 (libmcrypt > 2.4.x only)
    MCRYPT_MARS (libmcrypt > 2.4.x only, non-free)
    MCRYPT_PANAMA (libmcrypt > 2.4.x only)
    MCRYPT_RIJNDAEL_128 (libmcrypt > 2.4.x only)
    MCRYPT_RIJNDAEL_192 (libmcrypt > 2.4.x only)
    MCRYPT_RIJNDAEL_256 (libmcrypt > 2.4.x only)
    MCRYPT_RC2
    MCRYPT_RC4 (libmcrypt 2.2.x only)
    MCRYPT_RC6 (libmcrypt > 2.4.x only)
    MCRYPT_RC6_128 (libmcrypt 2.2.x only)
    MCRYPT_RC6_192 (libmcrypt 2.2.x only)
    MCRYPT_RC6_256 (libmcrypt 2.2.x only)
    MCRYPT_SAFER64
    MCRYPT_SAFER128
    MCRYPT_SAFERPLUS (libmcrypt > 2.4.x only)
    MCRYPT_SERPENT(libmcrypt > 2.4.x only)
    MCRYPT_SERPENT_128 (libmcrypt 2.2.x only)
    MCRYPT_SERPENT_192 (libmcrypt 2.2.x only)
    MCRYPT_SERPENT_256 (libmcrypt 2.2.x only)
    MCRYPT_SKIPJACK (libmcrypt > 2.4.x only)
    MCRYPT_TEAN (libmcrypt 2.2.x only)
    MCRYPT_THREEWAY
    MCRYPT_TRIPLEDES (libmcrypt > 2.4.x only)
    MCRYPT_TWOFISH (for older mcrypt 2.x versions, or mcrypt > 2.4.x )
    MCRYPT_TWOFISH128 (TWOFISHxxx are available in newer 2.x versions, but not in the 2.4.x versions)
    MCRYPT_TWOFISH192
    MCRYPT_TWOFISH256
    MCRYPT_WAKE (libmcrypt > 2.4.x only)
    MCRYPT_XTEA (libmcrypt > 2.4.x only)

*/