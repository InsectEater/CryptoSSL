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
    const RAW   = 1;
    const BASE64= 2;
    const HEX   = 3;
    
    private $PublicKey;
    private $PrivateKey;
    
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
        $this->PrivateKey = openssl_pkey_get_public($PrivateKey);
        if ($this->PrivateKey === false)
            throw new exception('Can not load the private key.');
    }
    
    public function encryptPublic($Data)
    {
        
    }
}

$c = new CryptoSSL(null, 'key.pem');