<?php
namespace InsectEater;
/**
 * Encrypt and decrypt data using global and private keys via PHP OpenSSL library.
 *
 * You can also encrypt or decrypt (seal or open) long texts using private and public keys. In this
 * scenario symmetric encyption with random generated key is used, and then the key itself
 * is SSL encrypted.
 * @version 1.0
 */

class CryptoSSL
{
/**
 * var String Holds the result from last encryption operation.
 */
    public $Encrypted;
    
/**
 * var String Holds the result from last decryption operation.
 */
    public $Decrypted;

/**
 * var String Holds the key generated when encrypting big size data.
 */
    public $SealingKey;

/**
 * var Resource Holds the loaded public key, used for crypting operations by the class.
 */
    private $PublicKey;
/**
 * var Resource Holds the loaded private key, used for crypting operations by the class.
 */
    private $PrivateKey;
/**
 * var String What encoding type to use for raw encrypted data.
 */
    private $EncodeType = 'BASE64';

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
            throw new \exception('Can not load the public key.');
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
            throw new \exception('Can not load the private key.');
    }

    /**
 * Encrypts $Data with public key and returns the (encoded) result.
 * The result is saved in class $Encrypted property and returned.
 *
 * @param String $Data Data to be encrypted.
 *
 * @return String The result of the encryption.
 */
    public function publicEncrypt($Data)
    {
        if (empty($this->PublicKey))
            throw new \exception('Missing public key.');
        openssl_public_encrypt ($Data , $this->Encrypted ,$this->PublicKey);
        $this->postEncode($this->Encrypted);
        return $this->Encrypted;
    }

/**
 * Encrypts $Data with private key and returns the (encoded) result.
 * The result is saved in class $Encrypted property and returned.
 *
 * @param String $Data Data to be encrypted.
 *
 * @return String The result of the encryption.
 */
    public function privateEncrypt($Data)
    {
        if (empty($this->PrivateKey))
            throw new \exception('Missing private key.');
        openssl_private_encrypt ($Data , $this->Encrypted ,$this->PrivateKey);
        $this->postEncode($this->Encrypted);
        return $this->Encrypted;
    }
/**
 * Decrypts $Data with public key. The result is saved in class $Decrypted property
 * and returned.
 *
 * @param String $Data Data to be decrypted.
 *
 * @return String The result of the decryption.
 */
    public function publicDecrypt($Data)
    {
        if (empty($this->PublicKey))
            throw new \exception('Missing public key.');
        $this->preDecode($Data);
        openssl_private_decrypt ($Data, $this->Decrypted ,$this->PublicKey);
        return $this->Decrypted;
    }

/**
 * Decrypts $Data with private key. The result is saved in class $Decrypted
 * property and returned.
 *
 * @param String $Data Data to be decrypted.
 *
 * @return String The result of the decryption.
 */
    public function privateDecrypt($Data)
    {
        if (empty($this->PrivateKey))
            throw new \exception('Missing private key.');
        $this->preDecode($Data);
        openssl_private_decrypt ($Data, $this->Decrypted ,$this->PrivateKey);
        return $this->Decrypted;
    }

/**
 * Encrypts $PlainData with randomly generated sealing key.
 * The sealing key is crypted with public key and stored in  the $SealingKey
 * class property. The result of the $Data encryption is stored in the
 * $Encrypted class property. This is wrapper of openssl_seal function;
 *
 * @param String $PlainData Data to be encrypted.
 * @param String $Method What cypher method to use to crypt the$PlainData. Only modes
 * which do not require initialization vectors are supported (openssl_seal 
 * function limitation).
 * Default is to RC4, but you can use for example AES-256-ECB (both are unsecure.
 *
 * @return $String Encrypted data.
 */
    public function seal($PlainData, $Method = 'RC4')
    {
        if (empty($this->PublicKey))
            throw new \exception('Missing public key.');
        $AvailableMethods = openssl_get_cipher_methods(true);
        if (!in_array($Method, $AvailableMethods)) $Method = 'RC4';
        openssl_seal($PlainData, $this->Encrypted, $Key, array($this->PublicKey), $Method);
        $this->SealingKey = $Key[0];
        $this->postEncode($this->SealingKey);
        $this->postEncode($this->Encrypted);
        return $this->Encrypted;
    }
/**
 * Decrypts $CryptedData with private key.
 * The result from decryption is stored in $this->Decrypted property and returned.
 * 
 * @param String $CryptedData Data to be decrypted.
 * @param String $SealingKey The key to be used on the encrypted $Data.
 * @param String $Method What cypher method to use to encode the Data. Only modes which do not
 * require initialization vectors are supported (openssl_seal function limitation).
 * Default is to RC4, but you can use for example AES-256-ECB (both are unsecure).
 *
 * return String Decrypted data.
 */
    public function open($CryptedData, $SealingKey, $Method = 'RC4') {
        if (empty($this->PrivateKey))
            throw new \exception('Missing private key.');
        $this->preDecode($SealingKey);
        $this->preDecode($CryptedData);
        openssl_open($CryptedData, $this->Decrypted, $SealingKey, $this->PrivateKey, $Method);
        return $this->Decrypted;
    }

/**
 * Encrypts $PlainData with randomly generated sealing key.
 * The sealing key is crypted with public key and stored in  the $SealingKey
 * class property. The result of the $Data encryption is stored in the
 * $Encrypted class property. Here is used more secure mcrypt_encrypt function
 * with ciphers put in cfb mode. The initialization vector is applied
 * at the beginig of the encrypted data.
 *
 * @param String $PlainData Data to be encrypted.
 * @param String $Method What cypher method to use to encode the $PlainData. Must be
 * some of the MCRYPT_ciphername, supported by mcrypt, which can be put in cfb mode.
 * Default is to MCRYPT_RIJNDAEL_256 (Other name of AES-256).
 *
 * @return $String Encrypted data.
 */
    public function mcryptSeal($PlainData, $Method = MCRYPT_RIJNDAEL_256)
    {
        if (empty($this->PublicKey))
            throw new \exception('Missing public key.');
        $Mc =mcrypt_module_open ($Method, null, 'cfb', null);
        $IvSize = mcrypt_enc_get_iv_size($Mc);
        $Iv = openssl_random_pseudo_bytes($IvSize);
        $KeySize = mcrypt_enc_get_key_size($Mc);
        mcrypt_module_close($Mc);
        $this->SealingKey = openssl_random_pseudo_bytes($KeySize);
        $this->Encrypted = $Iv.mcrypt_encrypt ($Method, $this->SealingKey , $PlainData , 'cfb', $Iv);
        $this->postEncode($this->SealingKey);
        $this->postEncode($this->Encrypted);
        return $this->Encrypted;
    }
/**
 * Decrypts $CryptedData with private key.
 * The result from decryption is stored in $this->Decrypted property and returned.
 * 
 * @param String $CryptedData Data to be decrypted.
 * @param String $SealingKey The key to be used on the encrypted $Data.
 * @param String $Method What cypher method to use to decode the $EncryptedData. Must be
 * some of the MCRYPT_ciphername, supported by mcrypt, which can be put in cfb mode.
 * Default is to MCRYPT_RIJNDAEL_256 (Other name of AES-256).
 *
 * return String Decrypted data.
 */
    public function mcryptOpen($EncryptedData, $Key, $Method = MCRYPT_RIJNDAEL_256)
    {
        if (empty($this->PrivateKey))
            throw new \exception('Missing private key.');
        $Mc =mcrypt_module_open ($Method, null, 'cfb', null);
        $IvSize = mcrypt_enc_get_iv_size($Mc);
        mcrypt_module_close($Mc);
        $this->preDecode($EncryptedData);
        $this->preDecode($Key);
        $Iv = substr($EncryptedData, 0, $IvSize);
        $EncryptedData = substr($EncryptedData, $IvSize);
        $this->Decrypted = mcrypt_decrypt ($Method, $Key , $EncryptedData , 'cfb', $Iv);
        return $this->Decrypted;
    }

/**
 * Set the encoding type to be used when working with raw encrytped data when  return it
 * or before use it for decryption (this is valid for symmetric keys and data).
 * 
 * @param String $EncodeType Can be one of the following:
 *         self::RAW - the data is not changed;
 *         self::BASE64 (default);
 *         self::HEX - Hex representation of data bytes;
 *
 * @return void
 */

public function setEncoding($EncodeType)
    {   
        $EncodeType = strtoupper($EncodeType);
        if ( !in_array($EncodeType , array('BASE64', 'RAW', 'HEX')) )
            $EncodeType = 'BASE64';
        $this->EncodeType = $EncodeType;
    }

/**
 * Clear sensitive data from class variables.
 * 
 * @param boolean $ClearKeys If true, will clear the data for public and private keys.
 * default is to false;
 * @return void
 */
    public function clear($ClearKeys = false)
    {
        $this->Encrypted = null;
        $this->Decrypted = null;
        $this->SealingKey = null;
        if ($ClearKeys) {
            openssl_free_key($this->PublicKey);
            openssl_free_key($this->PrivateKey);
            $this->PublicKey = null;
            $this->PrivateKey = null;
        }
    }


    
/**
 * Encode Data after encryption
 *
 * return void
 */
    private function postEncode(&$Data)
    {
        switch ($this->EncodeType) {
            case 'BASE64': $Data = base64_encode($Data); break;
            case 'HEX': $Data = bin2hex($Data); break;
        }
    }
/**
 * Decode Data before encryption
 *
 * return void
 */
    private function preDecode(&$Data)
    {
        switch ($this->EncodeType) {
            case 'BASE64': $Data = base64_decode($Data); break;
            case 'HEX': $Data = hex2bin($Data); break;
        }
    }
}