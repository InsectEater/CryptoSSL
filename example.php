<?php

include_once 'CryptoSSL.class.php';

$Data = 'Some public encrypted, private decrypted small chunk of data.';
$sender = new \InsectEater\CryptoSSL('public.pem');
echo '<b>Encrypted:</b> '.$sender->publicEncrypt($Data)."<br />\r\n";

$reciever = new \InsectEater\CryptoSSL(null, 'private.pem');
echo '<b>Decrypted:</b> '.$reciever->privateDecrypt($sender->Encrypted)."<br />\r\n<br />\r\n";

// -----------------------

$Data = 'Encrypting big size data like this: Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ';

$sender = new \InsectEater\CryptoSSL('public.pem');
$sender->seal($Data);
echo '<b>Sealed:</b> '.$sender->Encrypted."<br />\r\n";
echo '<b>Sealing key:</b> '.$sender->SealingKey."<br />\r\n";

//We transfer the (already public encrypted) sealing key and the encrypted data to the other party
$reciever = new \InsectEater\CryptoSSL();
$reciever->setPrivateKey('private.pem');
$reciever->open($sender->Encrypted, $sender->SealingKey);
echo '<b>Opened:</b> '.$reciever->Decrypted."<br />\r\n<br />\r\n";

// -----------------------

$Data = 'Encrypting big size data but using different encoding scheme - HEX instead of BASE64 and cypher - MCRYPT_BLOWFISH instead of the default MCRYPT_RIJNDAEL_256. We must set HEX encoding scheme and MCRYPT_BLOWFISH for BOTHS sides';
$sender = new \InsectEater\CryptoSSL('public.pem', 'private.pem');
$sender->setEncoding('HEX');
$sender->mcryptSeal($Data, MCRYPT_BLOWFISH);
echo '<b>Sealed:</b> '.$sender->Encrypted."<br />\r\n";
echo '<b>Sealing key:</b> '.$sender->SealingKey."<br />\r\n";

//We transfer the (already public encrypted) sealing key and the encrypted data to the other party
$reciever = new \InsectEater\CryptoSSL(null, 'private.pem');
$reciever->setEncoding('HEX');
$reciever->mcryptOpen($sender->Encrypted, $sender->SealingKey, MCRYPT_BLOWFISH);
echo '<b>Opened:</b> '.$reciever->Decrypted."<br />\r\n<br />\r\n";

// -----------------------

$Data = 'Some private encrypted, public decrypted small chunk of data (usually used for signing)';
$sender = new \InsectEater\CryptoSSL(null, 'private.pem');
$sender->privateEncrypt($Data);
echo '<b>Encrypted:</b> '.$sender->Encrypted."<br />\r\n";

$reciever = new \InsectEater\CryptoSSL('public.pem');
$reciever->publicDecrypt($sender->Encrypted);
echo '<b>Decrypted:</b> '.$reciever->Decrypted."<br />\r\n";

