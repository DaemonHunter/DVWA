<?php

// Hardened: replaced XOR cipher with AES-256-GCM authenticated encryption.
// Per-invocation random IV prevents ciphertext analysis and block manipulation.

function aes_gcm_encrypt ($plaintext, $key) {
	$iv = random_bytes(12);
	$e  = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
	if ($e === false) {
		throw new Exception ("Encryption failed");
	}
	return base64_encode ($iv . $e . $tag);
}

function aes_gcm_decrypt ($encoded, $key) {
	$raw        = base64_decode ($encoded);
	$iv         = substr ($raw, 0, 12);
	$tag        = substr ($raw, -16);
	$ciphertext = substr ($raw, 12, -16);
	$d = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
	if ($d === false) {
		throw new Exception ("Decryption failed (authentication error)");
	}
	return $d;
}

$key = hash ('sha256', "wachtwoord", true); // 32-byte key for AES-256

$errors   = "";
$success  = "";
$messages = "";
$encoded  = null;
$encode_radio_selected = " checked='checked' ";
$decode_radio_selected = " ";
$message  = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	try {
		if (array_key_exists ('message', $_POST)) {
			$message = $_POST['message'];
			if (array_key_exists ('direction', $_POST) && $_POST['direction'] == "decode") {
				$encoded = aes_gcm_decrypt ($message, $key);
				$encode_radio_selected = " ";
				$decode_radio_selected = " checked='checked' ";
			} else {
				$encoded = aes_gcm_encrypt ($message, $key);
			}
		}
		if (array_key_exists ('password', $_POST)) {
			$password = $_POST['password'];
			// Constant-time comparison to prevent timing attacks
			if (hash_equals (hash ('sha256', "Olifant"), hash ('sha256', $password))) {
				$success = "Welcome back user";
			} else {
				$errors = "Login Failed";
			}
		}
	} catch(Exception $e) {
		$errors = $e->getMessage();
	}
}

$html = "
		<p>
		This super secure system will allow you to exchange messages with your friends without anyone else being able to read them. Use the box below to encode and decode messages.
		</p>
		<form name=\"aes\" method='post' action=\"" . $_SERVER['PHP_SELF'] . "\">
			<p>
				<label for='message'>Message:</label><br />
				<textarea style='width: 600px; height: 56px' id='message' name='message'>" . htmlentities ($message) . "</textarea>
			</p>
			<p>
				<input type='radio' value='encode' name='direction' id='direction_encode' " . $encode_radio_selected . "><label for='direction_encode'>Encode</label> or
				<input type='radio' value='decode' name='direction' id='direction_decode' " . $decode_radio_selected . "><label for='direction_decode'>Decode</label>
			</p>
			<p>
				<input type=\"submit\" value=\"Submit\">
			</p>
		</form>
";

if (!is_null ($encoded)) {
	$html .= "
			<p>
				<label for='encoded'>Message:</label><br />
				<textarea readonly='readonly' style='width: 600px; height: 56px' id='encoded' name='encoded'>" . htmlentities ($encoded) . "</textarea>
			</p>";
}

$html .= "
		<hr>
		<p>
		You have intercepted the following message. It is protected with authenticated encryption — decoding requires the correct key and IV.
		</p>
";

if ($errors != "") {
	$html .= '<div class="warning">' . htmlentities ($errors) . '</div>';
}

if ($messages != "") {
	$html .= '<div class="nearly">' . htmlentities ($messages) . '</div>';
}

if ($success != "") {
	$html .= '<div class="success">' . htmlentities ($success) . '</div>';
}

$html .= "
		<form name=\"auth\" method='post' action=\"" . $_SERVER['PHP_SELF'] . "\">
			<p>
				<label for='password'>Password:</label><br />
				<input type='password' id='password' name='password'>
			</p>
			<p>
				<input type=\"submit\" value=\"Login\">
			</p>
		</form>
";
?>
