<?php
/**
 * Created by AbdelkaderBah.
 * Date: 5/27/20
 * Time: 02:28
 */


use phpseclib\Crypt\AES;

class AesEncryption
{
    /**
     * @link http://php.net/manual/en/function.openssl-get-cipher-methods.php Available methods.
     * @var string Cipher method. Recommended AES-128-CBC, AES-192-CBC, AES-256-CBC
     */
    protected $encryptMethod = 'AES-256-CBC';


    /**
     * Decrypt string.
     *
     * @link https://stackoverflow.com/questions/12730761/how-to-aes-cbc-encrypt-using-pidcrypt-then-decrypt-with-phpseclib/13873724#13873724 Reference.
     * @param string $encryptedString The encrypted string that is base64 encode.
     * @param string $key The key.
     * @return mixed Return original string value. Return null for failure get salt, iv.
     */
    public function decrypt($encryptedString, $key)
    {
        $data = base64_decode($encryptedString);
        $salt = substr($data, 8, 8);
        $ct = substr($data, 16);
        $rounds = 3;
        $data00 = $key . $salt;
        $md5_hash = array();
        $md5_hash[0] = md5($data00, true);
        $result = $md5_hash[0];
        for ($i = 1; $i < $rounds; $i++) {
            $md5_hash[$i] = md5($md5_hash[$i - 1] . $data00, true);
            $result .= $md5_hash[$i];
        }
        $key = substr($result, 0, 32);
        $iv = substr($result, 32, 16);

        //phpseclib specifics
        $aes = new AES(AES::MODE_CBC);
        $aes->setKey($key);
        $aes->setIV($iv);

        return $aes->decrypt($ct);
    }// decrypt


    /**
     * Encrypt string.
     *
     * @link https://stackoverflow.com/questions/41222162/encrypt-in-php-openssl-and-decrypt-in-javascript-cryptojs Reference.
     * @param string $string The original string to be encrypt.
     * @param string $key The key.
     * @return string Return encrypted string.
     */
    public function encrypt($data, $key)
    {
        //my randomly generated 8 byte salt
        $salt = substr(time(), -8);

        $salted = '';
        $dx = '';
        while (strlen($salted) < 48) {
            $dx = md5($dx . $key . $salt, true);
            $salted .= $dx;
        }
        $key = substr($salted, 0, 32);
        $iv = substr($salted, 32, 16);

        //phpseclib specifics
        $aes = new AES(AES::MODE_CBC);
        $aes->setKey($key);
        $aes->setIV($iv);
        $encrypted_data = $aes->encrypt($data . "\n");

        //alternatively with openssl you would do the following
        //$encrypted_data = openssl_encrypt($data . "\n", 'aes-256-cbc', $key, true, $iv);

        return (base64_encode('Salted__' . $salt . $encrypted_data));
    }// encrypt

}
