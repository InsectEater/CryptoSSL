<?php
include_once 'CryptoSSL.class.php';

$c = new \InsectEater\CryptoSSL('public.pem', 'private.pem');
$Data = 'My secret key';

echo $c->publicEncrypt($Data);."<br />\r\n";
echo $c->privateDecrypt($c->Encrypted);