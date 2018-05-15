<?php

require_once __DIR__.'/../src/RSA.php';

$rsa = new \Longway\RSA\RSA();

$privateKey = file_get_contents(__DIR__.'/private.key');
$publicKey = file_get_contents(__DIR__.'/public.key');

$str = '';
for ( $i = 0; $i < 1235; $i++ ) {
    $str .= 'a';
}

$encrypted = $rsa->encrypt($publicKey, $str);

var_dump($str == $rsa->decrypt($privateKey, $encrypted));


$encrypted = $rsa->encrypt($privateKey, $str);

var_dump($str == $rsa->decrypt($publicKey, $encrypted));
