<?php

namespace Src;

use OpenApi\Attributes as OAT;

class Login
{
	private const ACCESS_TOKEN_LIFE = 180;
	private const REFRESH_TOKEN_LIFE = 240;

	private static function accessSecret(): string {
		$s = getenv('DVWA_API_ACCESS_SECRET');
		return ($s !== false && strlen($s) > 0) ? $s : "12345";
	}

	private static function refreshSecret(): string {
		$s = getenv('DVWA_API_REFRESH_SECRET');
		return ($s !== false && strlen($s) > 0) ? $s : "98765";
	}

	public static function create_token($subject = null) {
		$now = time();
		$tokenObj = new Token();
		$token = json_encode (array (
			"access_token" => $tokenObj->create_token(self::accessSecret(), $now + self::ACCESS_TOKEN_LIFE, $subject),
			"refresh_token" => $tokenObj->create_token(self::refreshSecret(), $now + self::REFRESH_TOKEN_LIFE, $subject),
			"token_type" => "bearer",
			"expires_in" => self::ACCESS_TOKEN_LIFE)
		);
		return $token;
	}

	public static function check_access_token($token) {
		$tokenObj = new Token();
		$decrypted = $tokenObj->decrypt_token ($token);

		if ($decrypted === false) {
			return false;
		}
		if ($decrypted['secret'] == self::accessSecret() && $decrypted['expires'] > time()) {
			return true;
		}
		return false;
	}

	public static function get_token_subject($token) {
		$tokenObj = new Token();
		$decrypted = $tokenObj->decrypt_token ($token);
		if ($decrypted === false) {
			return null;
		}
		return isset($decrypted['subject']) ? $decrypted['subject'] : null;
	}

	public static function check_refresh_token($token) {
		$tokenObj = new Token();
		$decrypted = $tokenObj->decrypt_token ($token);

		if ($decrypted === false) {
			return false;
		}
		if ($decrypted['secret'] == self::refreshSecret() && $decrypted['expires'] > time()) {
			return true;
		}
		return false;
	}
}
