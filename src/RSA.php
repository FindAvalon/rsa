<?php

namespace Longway\RSA;

use Closure;
use ErrorException;

class RSA
{
    public function buildKey(string $dir, int $bits = 1024)
    {
        $res = openssl_pkey_new(array('private_key_bits' => $bits));
        openssl_pkey_export($res, $private_key);
        $public_key=openssl_pkey_get_details($res);
        if ( !is_dir($dir) ) throw new ErrorException('dir not found');
        file_put_contents($dir.'/public.key', $public_key['key']);
        file_put_contents($dir.'/private.key', $private_key);
    }

    public function encrypt($key, string $data, $delimiter = "\n")
    {
        if ( $res = openssl_get_privatekey($key)  ) {
            return $this->privateEncrypt($res, $data, $delimiter);
        } elseif ( $res = openssl_get_publickey($key) ) {
            return $this->publicEncrypt($res, $data, $delimiter);
        }
        throw new ErrorException('无效的key');
    }

    public function decrypt($key, string $data, $delimiter = "\n")
    {
        if ( $res = openssl_get_privatekey($key)  ) {
            return $this->privateDecrypt($res, $data, $delimiter);
        } elseif ( $res = openssl_get_publickey($key) ) {
            return $this->publicDecrypt($res, $data, $delimiter);
        }
        throw new ErrorException('无效的key');
    }

    protected function publicDecrypt($res, string $data, $delimiter = "\n")
    {
        return $this->composeData($res, $data, $delimiter, function ($data, $res) {
            openssl_public_decrypt($data, $decrypted, $res);
            return $decrypted;
        });
    }

    protected function privateDecrypt($res, string $data, $delimiter = "\n")
    {
        return $this->composeData($res, $data, $delimiter, function ($data, $res) {
            openssl_private_decrypt($data, $decrypted, $res);
            return $decrypted;
        });
    }

    protected function composeData($res, $data, $delimiter, Closure $operator)
    {
        $dataArr = explode($delimiter, $data);
        if ( count($dataArr) == 0 ) return null;

        $data = '';
        foreach ( $dataArr as $cell ) {
            $temp = base64_decode($cell);
            $decrypted = call_user_func_array($operator, [
                $temp,
                $res
            ]);
            $data .= $decrypted;
        }
        return $data;
    }

    protected function privateEncrypt($res, $data, $delimiter)
    {
        return $this->splitData($res, $data, $delimiter, function ($data, $res) {
            openssl_private_encrypt($data, $encrypted, $res);
            return $encrypted;
        });
    }

    protected function publicEncrypt($res, $data, $delimiter)
    {
        return $this->splitData($res, $data, $delimiter, function ($data, $res) {
            openssl_public_encrypt($data, $encrypted, $res);
            return $encrypted;
        });
    }

    protected function splitData($res, $data, $delimiter, Closure $operator)
    {
        $bits = openssl_pkey_get_details($res)['bits'] ?? 0;
        $cellLength = $bits ? $bits / 8 - 11 : 0;

        if ( !$cellLength ) return null;

        $dataArr = [];

        while ( $data ) {
            $dataLength = strlen($data);
            if ( $dataLength > $cellLength ) {
                $targetData = substr($data, 0, $cellLength);
                $data = substr($data, $cellLength - 1, $dataLength - $cellLength);
            } else {
                $targetData = $data;
                $data = null;
            }
            $encrypted = call_user_func_array($operator, [
                $targetData,
                $res
            ]);
            $dataArr[] = base64_encode($encrypted);
        }
        return join($delimiter, $dataArr);
    }

}