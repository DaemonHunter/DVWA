<?php

// Hardened version of the ECB attack demonstration.
// Original used AES-128-ECB (vulnerable to block rearrangement).
// Now uses AES-256-GCM; the auth tag prevents any ciphertext manipulation.

require_once ("token_library_low.php");

$key = KEY_LOW;

// Generate tokens using authenticated encryption — block swapping is not possible.
$sooty_plaintext = '{"user":"sooty","ex":' . (time() + 3600) . ',"level":"admin","bio":"Izzy wizzy let\'s get busy"}';
$sweep_plaintext = '{"user":"sweep","ex":' . (time() - 3600) . ',"level":"user","bio":"Squeeeeek"}';
$soo_plaintext   = '{"user":"soo","ex":'   . (time() + 7200) . ',"level":"user","bio":"I won The Weakest Link"}';

$sooty_iv = random_bytes(12);
$sweep_iv = random_bytes(12);
$soo_iv   = random_bytes(12);

$sooty_ciphered = encrypt_low($sooty_plaintext, $sooty_iv);
$sweep_ciphered = encrypt_low($sweep_plaintext, $sweep_iv);
$soo_ciphered   = encrypt_low($soo_plaintext,   $soo_iv);

print "Sooty token (admin, GCM):\n";
var_dump (base64_encode ($sooty_iv . $sooty_ciphered));

print "\nSweep token (user, GCM):\n";
var_dump (base64_encode ($sweep_iv . $sweep_ciphered));

print "\nSoo token (user, GCM):\n";
var_dump (base64_encode ($soo_iv . $soo_ciphered));

print "\nNote: AES-256-GCM authenticated encryption is in use.\n";
print "Block rearrangement is not possible — any ciphertext modification\n";
print "causes the GCM authentication tag verification to fail.\n";
