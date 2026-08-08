<?php

// Mirrors token_library_impossible.php — uses AES-256-GCM with a per-invocation random IV.
// The low level previously used XOR/ECB; this hardens it to authenticated encryption.

define ("KEY_LOW", "rainbowclimbinghigh");
define ("ALGO_LOW", "aes-256-gcm");

function encrypt_low ($plaintext, $iv) {
	if (strlen ($iv) != 12) {
		throw new Exception ("IV must be 12 bytes, " . strlen ($iv) . " passed");
	}
	$e = openssl_encrypt($plaintext, ALGO_LOW, KEY_LOW, OPENSSL_RAW_DATA, $iv, $tag);
	if ($e === false) {
		throw new Exception ("Encryption failed");
	}
	return $e . $tag;
}

function decrypt_low ($ciphertext, $iv) {
	if (strlen ($iv) != 12) {
		throw new Exception ("IV must be 12 bytes, " . strlen ($iv) . " passed");
	}
	$tag  = substr($ciphertext, -16);
	$text = substr($ciphertext, 0, -16);
	$e = openssl_decrypt($text, ALGO_LOW, KEY_LOW, OPENSSL_RAW_DATA, $iv, $tag);
	if ($e === false) {
		throw new Exception ("Decryption failed");
	}
	return $e;
}

function create_token_low () {
	$token = "userid:2";
	$iv    = random_bytes(12);
	$e     = encrypt_low ($token, $iv);
	$data  = array (
		"token" => base64_encode ($e),
		"iv"    => base64_encode ($iv),
	);
	return json_encode($data);
}

function check_token_low ($data) {
	$users    = array ();
	$users[1] = array ("name" => "Geoffery", "level" => "admin");
	$users[2] = array ("name" => "Bungle",   "level" => "user");
	$users[3] = array ("name" => "Zippy",    "level" => "user");
	$users[4] = array ("name" => "George",   "level" => "user");

	$data_array = false;
	try {
		$data_array = json_decode ($data, true);
	} catch (TypeError $exp) {
		return json_encode (array (
			"status"  => 521,
			"message" => "Data not in JSON format",
			"extra"   => $exp->getMessage()
		));
	}

	if (is_null ($data_array)) {
		return json_encode (array (
			"status"  => 522,
			"message" => "Data in wrong format"
		));
	}

	if (!array_key_exists ("token", $data_array)) {
		return json_encode (array (
			"status"  => 523,
			"message" => "Missing token"
		));
	}
	if (!array_key_exists ("iv", $data_array)) {
		return json_encode (array (
			"status"  => 524,
			"message" => "Missing IV"
		));
	}

	$ciphertext = base64_decode ($data_array['token']);
	$iv         = base64_decode ($data_array['iv']);

	$ret = array ("status" => 500, "message" => "Unknown error");
	try {
		$d = decrypt_low ($ciphertext, $iv);
		if (preg_match ("/^userid:(\d+)$/", $d, $matches)) {
			$id = $matches[1];
			if (array_key_exists ($id, $users)) {
				$user = $users[$id];
				$ret  = array (
					"status" => 200,
					"user"   => $user["name"],
					"level"  => $user['level']
				);
			} else {
				$ret = array ("status" => 525, "message" => "User not found");
			}
		} else {
			$ret = array ("status" => 527, "message" => "No user specified");
		}
	} catch (Exception $exp) {
		$ret = array (
			"status"  => 526,
			"message" => "Unable to decrypt token",
			"extra"   => $exp->getMessage()
		);
	}
	return json_encode ($ret);
}
