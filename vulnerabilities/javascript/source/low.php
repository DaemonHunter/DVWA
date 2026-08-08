<?php

// Hardened: token is now generated server-side and stored in the session.
// The original low level generated the token in client-side JavaScript (md5(rot13(phrase))),
// making it trivially reversible. The server now issues and validates the token,
// so client-side manipulation has no effect.

if (session_status() == PHP_SESSION_NONE) {
	session_start();
}

$errors  = "";
$success = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	$phrase = isset($_POST['phrase']) ? $_POST['phrase'] : '';
	$token  = isset($_POST['token'])  ? $_POST['token']  : '';

	// Validate against the server-side session token
	if (isset($_SESSION['js_low_token']) && hash_equals($_SESSION['js_low_token'], $token)) {
		if ($phrase === "success") {
			$success = "Well done!";
		} else {
			$errors = "Invalid phrase.";
		}
	} else {
		$errors = "Invalid token.";
	}
	// Regenerate token after each submission
	unset($_SESSION['js_low_token']);
}

// Generate a fresh server-side token for this page load
$_SESSION['js_low_token'] = bin2hex(random_bytes(32));

$page[ 'body' ] .= "
<p id='header'>What is the phrase?</p>
<form name='low' method='POST'>
	<input type='hidden' name='token' id='token' value='" . htmlspecialchars($_SESSION['js_low_token'], ENT_QUOTES, 'UTF-8') . "' />
	<label for='phrase'>Phrase:</label>
	<input type='text' name='phrase' id='phrase' />
	<input type='submit' id='send' value='Submit' />
</form>
";

if ($errors !== "") {
	$page[ 'body' ] .= '<div class="warning">' . htmlspecialchars($errors, ENT_QUOTES, 'UTF-8') . '</div>';
}
if ($success !== "") {
	$page[ 'body' ] .= '<div class="success">' . htmlspecialchars($success, ENT_QUOTES, 'UTF-8') . '</div>';
}
