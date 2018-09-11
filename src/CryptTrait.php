<?php
/**
 * Public/private key encryption.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use Defuse\Crypto\Crypto;

trait CryptTrait
{
    /**
     * @var string
     */
    protected $encryptionKey;

    /**
     * Encrypt data with a private key.
     *
     * @param string $unencryptedData
     *
     * @throws \LogicException
     *
     * @return string
     */
    protected function encrypt($unencryptedData)
    {
        try {
            if (extension_loaded('sodium')) {
                $nonce = \random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
                return \sodium_bin2hex(\sodium_crypto_secretbox($unencryptedData, $nonce, $this->encryptionKey)).'.'.\sodium_bin2hex($nonce);
            }
            return Crypto::encryptWithPassword($unencryptedData, $this->encryptionKey);
        } catch (\Exception $e) {
            throw new \LogicException($e->getMessage());
        }
    }

    /**
     * Decrypt data with a public key.
     *
     * @param string $encryptedData
     *
     * @throws \LogicException
     *
     * @return string
     */
    protected function decrypt($encryptedData)
    {
        try {
            if (extension_loaded('sodium')) {
                $encDataWithNonce = explode('.', $encryptedData);
                $encryptedData = \sodium_hex2bin($encDataWithNonce[0]);
                $nonce = \sodium_hex2bin($encDataWithNonce[1]);
                return \sodium_crypto_secretbox_open($encryptedData, $nonce, $this->encryptionKey);
            }
            return Crypto::decryptWithPassword($encryptedData, $this->encryptionKey);
        } catch (\Exception $e) {
            throw new \LogicException($e->getMessage());
        }
    }

    /**
     * Set the encryption key
     *
     * @param string $key
     */
    public function setEncryptionKey($key = null)
    {
        $this->encryptionKey = $key;
    }
}
