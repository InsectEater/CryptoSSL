<?php

include_once 'CryptoSSL.class.php';

$c = new \InsectEater\CryptoSSL('public.pem', 'private.pem');
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

