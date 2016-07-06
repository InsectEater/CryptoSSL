<?php
namespace InsectEater;
/**
 * Encrypt and decrypt data using global and private keys via PHP OpenSSL library.
 *
 * You can also encrypt or decrypt (seal or open) long texts using private and public keys. In this
 * scenario symmetric encyption with random generated key is used, and then the key itself
 * is SSL encrypted..
 */

 class CryptoSSL
{
    const RAW   = 5;
    const BASE64= 6;
    const HEX   = 7;

/**
 * var String Holds the result from last encryption operation.
 */
    public $Encrypted;
    
/**
 * var String Holds the result from last decryption operation.
 */
    public $Decrypted;

/**
 * var Resource Holds the loaded public key, used for crypting operations by the class.
 */
    private $PublicKey;
/**
 * var Resource Holds the loaded private key, used for crypting operations by the class.
 */
    private $PrivateKey;
    
/**
 * Class constructor
 *
 * @param string $PublicKey Public key to be used. Can be a path to the file containing it,
 * or the key itself (pem format encoded).
 * @param string $PrivateKey Private key to be used. Can be a path to the file containing it,
 * or the key itself (pem format encoded).
 *
 * return void
*/    
    
    public function __construct($PublicKey = null, $PrivateKey = null)
    {
        if (isset($PublicKey)) $this->setPublicKey($PublicKey);
        if (isset($PrivateKey)) $this->setPrivateKey($PrivateKey);
    }
/**
 * Set the public key to be used for further crypting operations. Can be a path
 * to a file containing it, or the key itself (pem format encoded).
 * 
 * @throws Exception If the file can not be found, or the key can not be loaded.
 *
 * @param String $PublicKey The Public key to be loaded (or path to the file, containing it).
 */
    public function setPublicKey($PublicKey)
    {
        if (is_readable($PublicKey)) $PublicKey = file_get_contents($PublicKey);
        $this->PublicKey = openssl_pkey_get_public($PublicKey);
        if ($this->PrivateKey === false)
            throw new exception('Can not load the public key.');
    }
/**
 * Set the private key to be used for further crypting operations. Can be a path
 * to a file containing it, or the key itself (pem format encoded).
 * 
 * @throws Exception If the file can not be found, or the key can not be loaded.
 *
 * @param String $PrivateKey The Private key to be loaded (or path to the file, containing it).
 */
    public function setPrivateKey($PrivateKey)
    {
        if (is_readable($PrivateKey)) $PrivateKey = file_get_contents($PrivateKey);
        $this->PrivateKey = openssl_pkey_get_private($PrivateKey);
        if ($this->PrivateKey === false)
            throw new exception('Can not load the private key.');
    }

    /**
 * Encrypts $Data with public key and encodes the result according to $EncodeType.
 * The result is saved in class $Encrypted property and returned.
 *
 * @param String $Data Data to be encrypted.
 * @param Constant $EncodeType What encoding to be applied on the encrypted data
 * can be: self::RAW - no change on the result;
 *         self::BASE64 (default) - Result will be base64 encoded;
 *         self::HEX - Result is converted to hexadeciaml representation of each byte.
 * @return String The result of the encryption.
 */
    public function publicEncrypt($Data, $EncodeType=self::BASE64)
    {
        openssl_public_encrypt ($Data , $this->Encrypted ,$this->PublicKey);
        $this->postEncode($this->Encrypted , $EncodeType);
        return $this->Encrypted;
    }

/**
 * Encrypts $Data with private key and encodes the result according to $EncodeType.
 * The result is saved in class $Encrypted property and returned.
 *
 * @param String $Data Data to be encrypted.
 * @param Constant $EncodeType What encoding to apply on the encrypted data
 * can be: self::RAW - no change on the result;
 *         self::BASE64 (default) - Result will be base64 encoded;
 *         self::HEX - Result is converted to hexadeciaml representation of each byte.
 * @return String The result of the encryption.
 */
    public function privateEncrypt($Data, $EncodeType=self::BASE64)
    {
        openssl_private_encrypt ($Data , $this->Encrypted ,$this->PrivateKey);
        $this->postEncode($this->Encrypted , $EncodeType);
        return $this->Encrypted;
    }
/**
 * Decrypts $Data with public key, which was previously encoded using $EncodeType.
 * The result is saved in class $Decrypted property and returned.
 *
 * @param String $Data Data to be decrypted.
 * @param Constant $EncodeType What encoding was applied on the encrypted data.
 * can be: self::RAW - the data will be not changed before decryption;
 *         self::BASE64 (default) - The data will be base64 decoded before decryption;
 *         self::HEX - The data is considered hex encoded and will be converted
 * to binary, before decryption.
 * @return String The result of the decryption.
 */
    public function publicDecrypt($Data, $EncodeType=self::BASE64)
    {
        $this->preDecode($Data , $EncodeType);
        openssl_private_decrypt ($Data, $this->Decrypted ,$this->PrivateKey);
        return $this->Decrypted;
    }

/**
 * Decrypts $Data with private key, which was previously encoded using $EncodeType.
 * The result is saved in class $Decrypted property and returned.
 *
 * @param String $Data Data to be decrypted.
 * @param Constant $EncodeType What encoding was applied on the encrypted data.
 * can be: self::RAW - the data will be not changed before decryption;
 *         self::BASE64 (default) - The data will be base64 decoded before decryption;
 *         self::HEX - The data is considered hex encoded and will be converted
 * to binary, before decryption.
 * @return String The result of the decryption.
 */
    public function privateDecrypt($Data, $EncodeType=self::BASE64)
    {
        $this->preDecode($Data , $EncodeType);
        openssl_private_decrypt ($Data, $this->Decrypted ,$this->PrivateKey);
        return $this->Decrypted;
    }

/*
 * Encrypts $Data with randomly generated secret key. Then encrypts the key with the
 * public key. The encrypted secret key is storedin the $SealingKey class property.
 * The result of the $Data encryption is stored in the $Encrypted class property.
 *
 * @param String $Data Data to be encrypted.
 * @param Constant $EncodeType What encoding to apply on the encrypted data.
 * can be: self::RAW - no change on the result;
 *         self::BASE64 (default) - Result will be base64 encoded;
 *         self::HEX - Result is converted to hexadeciaml representation of each byte.
 * @param String $Method What cypher method to use to encode the Data. Only modes which do not
 * require initialization vectors are supported (openssl_seal function limitation).
 * Default is to RC4, but you can use for example AES-256-ECB.
 */
    public function seal($Data, $EncodeType = null, $Method = 'RC4')
    {
        if (empty($EncodeType)) $EncodeType = self::BASE64;
        $AvailableMethods = openssl_get_cipher_methods(true);
        if (!in_array($Method, $AvailableMethods)) $Method = 'RC4';
        openssl_seal($Data, $this->Encrypted, $Key, array($this->PublicKey), $Method);
        $this->SealingKey = $Key[0];
        $this->postEncode($this->SealingKey , $EncodeType);
        $this->postEncode($this->Encrypted , $EncodeType);
    }
/*
 * Decrypts $Data supplied secret key and private key. The result from decryption is 
 * stored in $this->Decrypted property and returned.
 * 
 * @param String $Data Data to be decrypted.
 * @param String SealingKe The key to be used on the encrypted $Data.
 * @param Constant $EncodeType What encoding was applied on the encrypted data.
 * can be: self::RAW - the data will be not changed before decryption;
 *         self::BASE64 (default) - The data will be base64 decoded before decryption;
 *         self::HEX - The data is considered hex encoded and will be converted;
 * @param String $Method What cypher method to use to encode the Data. Only modes which do not
 * require initialization vectors are supported (openssl_seal function limitation).
 * Default is to RC4, but you can use for example AES-256-ECB.
 */
    public function open($Data, $SealingKey, $EncodeType = null, $Method = 'RC4') {
        if (empty($EncodeType)) $EncodeType = self::BASE64;
        $this->preDecode($SealingKey, $EncodeType);
        $this->preDecode($Data, $EncodeType);
        openssl_open($Data, $this->Decrypted, $SealingKey, $this->PrivateKey, $Method);
        return $this->Decrypted;
    }

/**
 * Internal function to encode Data which was previosly decrypted.
 *
 * return void
 */
    private function postEncode(&$Data, $EncodeType)
    {
        if ($EncodeType === self::BASE64)
            $Data = base64_encode($Data);
        else if ($EncodeType === self::HEX)
            $Data = bin2hex($Data);
    }
/**
 * Internal function to decode Data before decrypt it
 *
 * return void
 */
    private function preDecode(&$Data, $EncodeType)
    {
        if ($EncodeType === self::BASE64)
            $Data = base64_decode($Data);
        else if ($EncodeType === self::HEX)
            $Data = hex2bin($Data);
    }

}