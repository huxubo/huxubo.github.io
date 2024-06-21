RC4：Rivest Cipher 4 的缩写，是一种流加密算法，密钥长度可变，它加解密使用相同的密钥。

由 Ron Rivest 在 1987 年设计。它以其简单性和高效性而闻名，并被广泛用于加密通信和数据保护领域。 RC4 算法使用一个变长的密钥（通常为 8 至 256 字节）来生成一个伪随机的密钥流，然后将该密钥流与原始数据进行异或运算以实现加密。解密时，再次将密钥流与密文进行异或运算即可恢复原始数据。

RC4 算法的核心是生成密钥流的过程，该过程基于密钥和伪随机数生成器。它使用了状态向量、置换操作和密钥编排等步骤来生成密钥流。这使得 RC4 算法具有快速、高效的特点。 然而，尽管 RC4 在设计初期被广泛应用，但随着时间的推移，研究人员发现了一些安全漏洞和弱点。例如，RC4 存在针对密钥的偏差攻击和密钥重用等问题。因此，在现代加密应用中，RC4 已经不再被推荐使用。 相比之下，更强大和安全的加密算法，如 AES（Advanced Encryption Standard），已经取代了 RC4 在许多领域的应用。
```php
<?php
/**
 * RC4加密解密算法
 * @param string $data 要加密或解密的数据，十六进制表示
 * @param string $pwd  加密使用的密钥
 * @param bool $decrypt true表示解密，false表示加密
 * @return string 加密或解密后的数据，十六进制表示
 */
function rc4($data, $pwd, $decrypt = false)
{
    $key = [];
    $box = [];
    $pwd_length = strlen($pwd);
    $data_length = strlen($data);
    $cipher = '';

    for ($i = 0; $i < 256; $i++) {
        $key[$i] = ord($pwd[$i % $pwd_length]);
        $box[$i] = $i;
    }

    for ($j = $i = 0; $i < 256; $i++) {
        $j = ($j + $box[$i] + $key[$i]) % 256;
        $tmp = $box[$i];
        $box[$i] = $box[$j];
        $box[$j] = $tmp;
    }

    for ($a = $j = $i = 0; $i < $data_length; $i++) {
        $a = ($a + 1) % 256;
        $j = ($j + $box[$a]) % 256;
        $tmp = $box[$a];
        $box[$a] = $box[$j];
        $box[$j] = $tmp;
        $k = $box[(($box[$a] + $box[$j]) % 256)];
        $result = ord($data[$i]) ^ $k;
        if ($decrypt) {
            $cipher .= chr($result);
        } else {
            $cipher .= sprintf("%02x", $result);
        }
    }

    return $cipher;
}

// 测试加密和解密
$data = "HelloWorld"; // 要加密的数据
$key = "my_secret_key"; // 加密使用的密钥

// 加密
$encrypted_data = rc4($data, $key);
echo "加密后的数据：$encrypted_data\n";

// 解密
$decrypted_data = rc4(hex2bin($encrypted_data), $key, true);
echo "解密后的数据：$decrypted_data\n";