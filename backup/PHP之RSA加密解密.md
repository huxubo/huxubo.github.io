RSA算法属于非对称加密算法,非对称加密算法需要两个秘钥:公开密钥(publickey)和私有秘钥(privatekey).公开密钥和私有秘钥是一对,如果公开密钥对数据进行加密,只有用对应的私有秘钥才能解密;如果私有秘钥对数据进行加密那么只有用对应的公开密钥才能解密.因为加密解密使用的是两个不同的秘钥,所以这种算法叫做非对称加密算法.简单的说就是公钥加密私钥解密,私钥加密公钥解密**
```php
<?php

namespace util;


/**
 * rsa加密类
 * Class Rsa
 */
class RsaUtil
{

    const CHAR_SET = "UTF-8";
    const BASE_64_FORMAT = "UrlSafeNoPadding";
    const RSA_ALGORITHM_KEY_TYPE = OPENSSL_KEYTYPE_RSA;
    const RSA_ALGORITHM_SIGN = OPENSSL_ALGO_SHA256;

    protected $public_key;
    protected $private_key;
    protected $key_len;

    public function __construct($pub_key = '', $pri_key = null)
    {
        if ($pub_key) {
            $this->public_key = $pub_key;
            $pub_id = openssl_pkey_get_public($this->public_key);
            $this->key_len = openssl_pkey_get_details($pub_id)['bits'];
        }
        if ($pri_key) {
            $this->private_key = $pri_key;
            $pri_id = openssl_pkey_get_private($this->private_key);
            $this->key_len = openssl_pkey_get_details($pri_id)['bits'];
        }
    }

    /*
     * 创建密钥对
     */
    public static function createKeys($key_size = 1024)
    {
        $config = array(
            "private_key_bits" => $key_size,
            "private_key_type" => self::RSA_ALGORITHM_KEY_TYPE,
        );
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $private_key);
        $public_key_detail = openssl_pkey_get_details($res);
        $public_key = $public_key_detail["key"];

        return array(
            "public_key" => $public_key,
            "private_key" => $private_key,
        );
    }

    /*
     * 公钥加密
     */
    public function publicEncrypt($data)
    {
        $encrypted = '';
        $part_len = $this->key_len / 8 - 11;
        $parts = str_split($data, $part_len);

        foreach ($parts as $part) {
            $encrypted_temp = '';
            openssl_public_encrypt($part, $encrypted_temp, $this->public_key);
            $encrypted .= $encrypted_temp;
        }

        return base64_encode($encrypted);
    }

    /*
     * 私钥解密
     */
    public function privateDecrypt($encrypted)
    {
        $decrypted = "";
        $part_len = $this->key_len / 8; 
        //url  中的get传值默认会吧+号过滤成' '，替换回来就好了
        str_replace('% ', '+', $encrypted); 
        echo $encrypted;
        $base64_decoded = base64_decode($encrypted);
        $parts = str_split($base64_decoded, $part_len);
        foreach ($parts as $part) {
            $decrypted_temp = '';
            openssl_private_decrypt($part, $decrypted_temp, $this->private_key);
            $decrypted .= $decrypted_temp;
        }
        return $decrypted;
    }

    /*
     * 私钥加密
     */
    public function privateEncrypt($data)
    {
        $encrypted = '';
        $part_len = $this->key_len / 8 - 11;
        $parts = str_split($data, $part_len);

        foreach ($parts as $part) {
            $encrypted_temp = '';
            openssl_private_encrypt($part, $encrypted_temp, $this->private_key);
            $encrypted .= $encrypted_temp;
        }
        return base64_encode($encrypted);
    }

    /*
     * 公钥解密
     */
    public function publicDecrypt($encrypted)
    {
        $decrypted = "";
        $part_len = $this->key_len / 8;
        $base64_decoded = base64_decode($encrypted);
        $parts = str_split($base64_decoded, $part_len);

        foreach ($parts as $part) {
            $decrypted_temp = '';
            openssl_public_decrypt($part, $decrypted_temp, $this->public_key);
            $decrypted .= $decrypted_temp;
        }
        return $decrypted;
    }

    /*
     * 数据加签
     */
    public function sign($data)
    {
        openssl_sign($data, $sign, $this->private_key, self::RSA_ALGORITHM_SIGN);
        return base64_encode($sign);
    }

    /*
     * 数据签名验证
     */
    public function verify($data, $sign)
    {
        $pub_id = openssl_get_publickey($this->public_key);
        $res = openssl_verify($data, base64_decode($sign), $pub_id, self::RSA_ALGORITHM_SIGN);
        return $res;
    }

}
