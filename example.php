<?php

include_once 'CryptoSSL.class.php';

$c = new \InsectEater\CryptoSSL('public.pem', 'private.pem');

$Data = 'Encrypting small size data.';

echo '<b>Encrypted:</b> '.$c->publicEncrypt($Data)."<br />\r\n";
echo '<b>Decrypted:</b> '.$c->privateDecrypt($c->Encrypted)."<br />\r\n<br />\r\n";

// -----------------------

$Data = 'Encrypting big size data like this: Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ';

$c->clear(true);
$c->setPublicKey('public.pem');
$c->seal($Data);
echo '<b>Sealed:</b> '.$c->Encrypted."<br />\r\n";
echo '<b>Sealing key:</b> '.$c->SealingKey."<br />\r\n";

$c->setPrivateKey('private.pem');
$c->open($c->Encrypted, $c->SealingKey);
echo '<b>Opened:</b> '.$c->Decrypted."<br />\r\n<br />\r\n";

// -----------------------

$Data = 'Encrypting big size data but using different encoding scheme - HEX instead of BASE64 and cypher - MCRYPT_BLOWFISH instead of the default MCRYPT_RIJNDAEL_256';

$c->setEncoding('HEX');
$c->mcryptSeal($Data, MCRYPT_BLOWFISH);
echo '<b>Sealed:</b> '.$c->Encrypted."<br />\r\n";
echo '<b>Sealing key:</b> '.$c->SealingKey."<br />\r\n";
$c->mcryptOpen($c->Encrypted, $c->SealingKey, MCRYPT_BLOWFISH);
echo '<b>Opened:</b> '.$c->Decrypted;