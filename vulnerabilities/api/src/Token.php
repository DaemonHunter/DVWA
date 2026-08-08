<?php

namespace Src;

use OpenApi\Attributes as OAT;

#[OAT\Schema(required: ['token'])]
class Token {
	private const ENCRYPTION_CIPHER = "aes-128-gcm";
	// Key must be exactly 16 bytes for AES-128. Read from env or fall back to a
	// per-process random value so the hardcoded "Paintbrush" secret is never used.
	private static function encryptionKey(): string {
		$env = getenv('DVWA_API_TOKEN_KEY');
		if ($env !== false && strlen($env) > 0) {
			// Pad/truncate to exactly 16 bytes as required by AES-128.
			return substr(str_pad($env, 16, "\0"), 0, 16);
		}
		// Generate a stable-per-request random key stored as a static so
		// encrypt/decrypt within the same request always agree.
		static $randomKey = null;
		if ($randomKey === null) {
			$randomKey = random_bytes(16);
		}
		return $randomKey;
	}

    # Not sure if this is needed
    #[OAT\Property(example: "11111")]
	public string $token;

	private string $secret;
	private int $expires;

	public function __construct () {
	}

	private static function encrypt($cleartext) {
		$key = self::encryptionKey();
		$ivlen = openssl_cipher_iv_length(self::ENCRYPTION_CIPHER);
		$iv = openssl_random_pseudo_bytes($ivlen);
		$ciphertext = openssl_encrypt($cleartext, self::ENCRYPTION_CIPHER, $key, $options=0, $iv, $tag);
		$ret = base64_encode ($tag . ":::::" . $iv . ":::::" . $ciphertext);
		return $ret;
	}

	private static function decrypt($ciphertext) {
		$key = self::encryptionKey();
		$str = base64_decode ($ciphertext);
		$bits = explode (":::::", $str);
		if (count ($bits) != 3) {
			return false;
		}
		$value = $bits[2];
		$iv = $bits[1];
		$tag = $bits[0];
		$cleartext = openssl_decrypt($value, self::ENCRYPTION_CIPHER, $key, $options=0, $iv, $tag);
		return $cleartext;
	}
	public function create_token($secret, $expires, $subject = null) {
		$payload = array (
			"secret" => $secret,
			"expires" => $expires,
		);
		if ($subject !== null) {
			$payload['subject'] = $subject;
		}
		$token = self::encrypt(json_encode($payload));
		return $token;
	}

	public function decrypt_token($token) {
		$decrypted = self::decrypt($token);

		if ($decrypted === false) {
			return false;
		}

		$token = json_decode ($decrypted, true);
		return $token;
	}
}

?>
