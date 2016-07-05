<?php
include_once 'CryptoSSL.class.php';

$c = new \InsectEater\CryptoSSL('public.pem', 'private.pem');
$Data = 'My secret key';

//echo $c->publicEncrypt($Data)."<br />\r\n";
//echo $c->privateDecrypt($c->Encrypted);


$c->seal('00000000000000000000000000000000000000000000000');
var_dump($c->Encrypted);
var_dump($c->SealingKey);