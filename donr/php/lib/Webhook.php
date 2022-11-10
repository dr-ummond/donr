<?php

namespace Donr;

class Webhook
{
    /**
     * @var string
     */
    private static $secret;

    /**
     * @param $payload
     * @param $header
     * @param $secret
     * @return mixed
     * @throws AuthenticationVerification
     * @throws Decrypt
     */
    public static function constructEvent($payload, $header, $secret)
    {
        $bearer = self::getBearer($header);

        self::$secret = $secret;

        $token = self::getToken($bearer);
        $timestamp = self::getTimestamp($bearer);

        if (!password_verify($secret, $token)) {
            throw new Error\AuthenticationVerification(
                "Token and Secret do not match"
            );
        }

        $key = $token . ':' . $timestamp;

        $payload = self::getPayload(json_decode($payload), $key);

        return json_decode($payload, true);
    }

    /**
     * @param $header
     * @return mixed|null
     */
    private static function getBearer($header)
    {
        if (!empty($header)) {
            if (preg_match('/Bearer\s(\S+)/', $header, $matches)) {
                return $matches[1];
            }
        }
        return null;
    }

    /**
     * @param $bearer
     * @return false|string
     */
    private static function getTimestamp($bearer)
    {
        $decryptedBearer = self::decrypter($bearer, self::$secret);

        return substr($decryptedBearer, strpos($decryptedBearer, ":") + 1);
    }

    /**
     * @param $bearer
     * @return false|string
     */
    private static function getToken($bearer)
    {
        $decryptedBearer = self::decrypter($bearer, self::$secret);

        return strtok($decryptedBearer, ':');
    }

    /**
     * @param $payload
     * @param $key
     * @return false|string
     * @throws Decrypt
     */
    private static function getPayload($payload, $key)
    {
        return self::decrypter($payload, $key);
    }

    /**
     * @param $encodeString
     * @param $key
     * @return false|string
     * @throws Decrypt
     */
    private static function decrypter($encodeString, $key)
    {
        $encodeString = preg_replace('/-/i', '+', $encodeString);
        $encodeString = preg_replace('/_/i', '/', $encodeString);

        $decryptedString = openssl_decrypt( $encodeString , 'des-ede3', $key, 0, '');

        if ($decryptedString === false) {
            throw new Error\Decrypt(
                "Unable to decrypt data"
            );
        }

        return openssl_decrypt( $encodeString , 'des-ede3', $key, 0, '');
    }
}
