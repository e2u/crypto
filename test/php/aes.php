<?php

//var_dump(openssl_get_cipher_methods());
function dump_cihpers(){
  foreach(openssl_get_cipher_methods() as $m){
    echo $m."\n";
  }
}
  


// dump_cihpers();
//

/*
aes-256-cbc
aes-256-cfb
aes-256-cfb1
aes-256-cfb8
aes-256-ecb
aes-256-ofb
*/

$key = "12345678901234567890123456789012";
$iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
$plain = "BEGIN---1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ---END";

foreach(array("aes-256-cbc","aes-256-cfb","aes-256-cfb1","aes-256-cfb8","aes-256-ecb","aes-256-ofb") as $m){
  $enc = bin2hex(base64_decode(openssl_encrypt($plain,$m,$key,0,$iv)));
  printf("%s : %s\n",$m,$enc);
}


