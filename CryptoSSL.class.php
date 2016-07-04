<?php

/**
 * Encrypt and decrypt using global and private keys uisng PHP OpenSSL library.
 *
 * You can also encrypt/decrypt long texts using private and public keys. In this
 * scenario symmetric encyption with random generated key is used, and then ythe key itself
 * is SSL encrypted and included in the crypted message.
 */

 class CryptoSSL
{               
    const RAW   = 5;
    const BASE64= 6;
    const HEX   = 7;
    
    private $PublicKey;
    private $PrivateKey;
    
    //Holds the result from last encryption operation
    public $Encrypted;
    
    //Holds the result from the last decryption operation
    public $Decrypted;
    
    public function __construct($PublicKey = null, $PrivateKey = null)
    {
        if (isset($PublicKey)) $this->setPublicKey($PublicKey);
        if (isset($PrivateKey)) $this->setPrivateKey($PrivateKey);
    }
    
    public function setPublicKey($PublicKey)
    {
        if (is_file($PublicKey)) $PublicKey = file_get_contents($PublicKey);
        $this->PublicKey = openssl_pkey_get_public($PublicKey);
        if ($this->PrivateKey === false)
            throw new exception('Can not load the public key.');
    }
    
    public function setPrivateKey($PrivateKey)
    {
        if (is_file($PrivateKey)) $PrivateKey = file_get_contents($PrivateKey);
        $this->PrivateKey = openssl_pkey_get_private($PrivateKey);
        if ($this->PrivateKey === false)
            throw new exception('Can not load the private key.');
    }
    
    public function publicEncrypt($Data, $EncodeType=self::BASE64)
    {
        openssl_public_encrypt ($Data , $this->Encrypted ,$this->PublicKey);
        $this->postEncode($this->Encrypted , $EncodeType);
        return $this->Encrypted;
    }
    
    public function privateEncrypt($Data, $EncodeType=self::BASE64)
    {
        openssl_private_encrypt ($Data , $this->Encrypted ,$this->PrivateKey);
        $this->postEncode($this->Encrypted , $EncodeType);
        return $this->Encrypted;
    }

    public function publicDecrypt($Data, $EncodeType=self::BASE64)
    {
        $this->preDecode($Data , $EncodeType);
        openssl_private_decrypt ($Data, $this->Decrypted ,$this->PrivateKey);
        return $this->Decrypted;
    }
    
    public function privateDecrypt($Data, $EncodeType=self::BASE64)
    {
        $this->preDecode($Data , $EncodeType);
        openssl_private_decrypt ($Data, $this->Decrypted ,$this->PrivateKey);
        return $this->Decrypted;
    }
    
    private function postEncode(&$Data, $EncodeType)
    {
        if ($EncodeType === self::BASE64)
            $Data = base64_encode($this->Encrypted);
        else if ($EncodeType === self::HEX)
            $Data = bin2hex($this->Encrypted);
    }
    
    private function preDecode(&$Data, $EncodeType)
    {
        if ($EncodeType === self::BASE64)
            $Data = base64_decode($this->Encrypted);
        else if ($EncodeType === self::HEX)
            $Data = hex2bin($this->Encrypted);
    }
    
    
}

$c = new CryptoSSL('public.pem', 'private.pem');
$What = 'My secret key';
$c->publicEncrypt($What);
echo $c->privateDecrypt($c->Encrypted);

